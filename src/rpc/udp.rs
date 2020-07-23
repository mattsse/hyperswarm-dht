use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_std::{
    net::UdpSocket,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    stream::Stream,
};
use bytes::{BufMut, BytesMut};
use futures::{pin_mut, ready, Future, Sink};
use futures_codec::{Decoder, Encoder};

/// A unified `Stream` and `Sink` interface to an underlying `UdpSocket`, using
/// the `Encoder` and `Decoder` traits to encode and decode frames.
///
/// Raw UDP sockets work with datagrams, but higher-level code usually wants to
/// batch these into meaningful chunks, called "frames". This method layers
/// framing on top of this socket by using the `Encoder` and `Decoder` traits to
/// handle encoding and decoding of messages frames. Note that the incoming and
/// outgoing frame types may be distinct.
///
/// This function returns a *single* object that is both `Stream` and `Sink`;
/// grouping this into a single object is often useful for layering things which
/// require both read and write access to the underlying object.
///
/// If you want to work more directly with the streams and sink, consider
/// calling `split` on the `UdpFramed` returned by this method, which will break
/// them into separate objects, allowing them to interact more easily.
#[must_use = "sinks do nothing unless polled"]
// #[cfg_attr(docsrs, doc(all(feature = "codec", feature = "udp")))]
#[derive(Debug)]
pub struct UdpFramed<C> {
    socket: UdpSocket,
    codec: C,
    rd: BytesMut,
    wr: BytesMut,
    out_addr: SocketAddr,
    flushed: bool,
}

impl<C: Decoder + Unpin> Stream for UdpFramed<C> {
    type Item = Result<(C::Item, SocketAddr), C::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();

        pin.rd.reserve(INITIAL_RD_CAPACITY);

        let (_n, addr) = unsafe {
            // Read into the buffer without having to initialize the memory.
            //
            // safety: we know async_std::net::UdpSocket never reads from the memory
            // during a recv
            let res = {
                let bytes = &mut *(pin.rd.bytes_mut() as *mut _ as *mut [u8]);

                let fut = pin.socket.recv_from(bytes);
                pin_mut!(fut);
                ready!(fut.poll(cx))
            };

            let (n, addr) = res?;
            pin.rd.advance_mut(n);
            (n, addr)
        };

        let frame_res = pin.codec.decode(&mut pin.rd);
        pin.rd.clear();
        let frame = frame_res?;
        let result = frame.map(|frame| Ok((frame, addr))); // frame -> (frame, addr)

        Poll::Ready(result)
    }
}

impl<C: Encoder + Unpin> Sink<(C::Item, SocketAddr)> for UdpFramed<C> {
    type Error = C::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: (C::Item, SocketAddr)) -> Result<(), Self::Error> {
        let (frame, out_addr) = item;

        let pin = self.get_mut();

        pin.codec.encode(frame, &mut pin.wr)?;
        pin.out_addr = out_addr;
        pin.flushed = false;

        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            ref mut socket,
            ref mut out_addr,
            ref mut wr,
            ..
        } = *self;

        let n = {
            let fut = socket.send_to(&wr, *out_addr);
            pin_mut!(fut);
            ready!(fut.poll(cx))?
        };

        let wrote_all = n == self.wr.len();
        self.wr.clear();
        self.flushed = true;

        let res = if wrote_all {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to write entire datagram to socket",
            )
            .into())
        };

        Poll::Ready(res)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}

const INITIAL_RD_CAPACITY: usize = 64 * 1024;
const INITIAL_WR_CAPACITY: usize = 8 * 1024;

impl<C> UdpFramed<C> {
    /// Create a new `UdpFramed` backed by the given socket and codec.
    ///
    /// See struct level documentation for more details.
    pub fn new(socket: UdpSocket, codec: C) -> UdpFramed<C> {
        UdpFramed {
            socket,
            codec,
            out_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
            rd: BytesMut::with_capacity(INITIAL_RD_CAPACITY),
            wr: BytesMut::with_capacity(INITIAL_WR_CAPACITY),
            flushed: true,
        }
    }

    /// Returns a reference to the underlying I/O stream wrapped by `Framed`.
    ///
    /// # Note
    ///
    /// Care should be taken to not tamper with the underlying stream of data
    /// coming in as it may corrupt the stream of frames otherwise being worked
    /// with.
    pub fn get_ref(&self) -> &UdpSocket {
        &self.socket
    }

    /// Returns a mutable reference to the underlying I/O stream wrapped by
    /// `Framed`.
    ///
    /// # Note
    ///
    /// Care should be taken to not tamper with the underlying stream of data
    /// coming in as it may corrupt the stream of frames otherwise being worked
    /// with.
    pub fn get_mut(&mut self) -> &mut UdpSocket {
        &mut self.socket
    }

    /// Consumes the `Framed`, returning its underlying I/O stream.
    pub fn into_inner(self) -> UdpSocket {
        self.socket
    }
}

#[cfg(test)]
mod tests {
    use bytes::Buf;
    use futures::{SinkExt, StreamExt};
    use futures_codec::BytesCodec;

    use super::*;

    const QUICK_BROWN_FOX: &str = "The quick brown fox jumps over the lazy dog";

    #[async_std::test]
    async fn udp_framed() -> Result<(), Box<dyn std::error::Error>> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;
        let mut framed = UdpFramed::new(socket, BytesCodec);

        let handle = async_std::task::spawn(async move {
            let (msg, addr) = framed.next().await.unwrap()?;
            assert_eq!(msg.bytes(), QUICK_BROWN_FOX.as_bytes());
            framed.send((msg, addr)).await?;
            Ok::<_, io::Error>(())
        });

        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        socket.send_to(QUICK_BROWN_FOX.as_bytes(), addr).await?;
        let mut buf = vec![0; QUICK_BROWN_FOX.len()];

        let (len, peer) = socket.recv_from(&mut buf).await?;
        assert_eq!(peer, addr);
        assert_eq!(len, QUICK_BROWN_FOX.len());
        assert_eq!(QUICK_BROWN_FOX.as_bytes(), &buf[..len]);

        handle.await?;
        Ok(())
    }
}
