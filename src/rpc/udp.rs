use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_std::{
    net::UdpSocket,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    stream::Stream,
};
use bytes::BytesMut;
use futures::{pin_mut, ready, Future, Sink};
use futures_codec::{Decoder, Encoder};

pub type RecvFuture =
    Pin<Box<dyn Future<Output = io::Result<(Vec<u8>, usize, SocketAddr)>> + Send + Sync>>;

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
pub struct UdpFramed<C> {
    socket: Arc<UdpSocket>,
    codec: C,
    rd: Option<Vec<u8>>,
    wr: BytesMut,
    out_addr: SocketAddr,
    flushed: bool,
    recv_fut: Option<RecvFuture>,
}

impl<C: Decoder + Unpin> fmt::Debug for UdpFramed<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpFramed")
            .field("socket", &self.socket)
            .field("out_addr", &self.out_addr)
            .field("flushed", &self.flushed)
            .finish()
    }
}

impl<C: Decoder + Unpin> Stream for UdpFramed<C> {
    type Item = Result<(C::Item, SocketAddr), C::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if self.recv_fut.is_none() {
                let buf = self.rd.take().unwrap();
                let recv_fut = recv_next(self.socket.clone(), buf);
                self.recv_fut = Some(Box::pin(recv_fut));
            }

            if let Some(f) = &mut self.recv_fut {
                let res = ready!(f.as_mut().poll(cx));
                self.recv_fut = None;
                let res = match res {
                    Err(e) => Poll::Ready(Some(Err(e.into()))),
                    Ok((buf, 0, _addr)) => {
                        self.rd = Some(buf);
                        continue;
                    }
                    Ok((buf, n, addr)) => {
                        let frame_res = self.codec.decode(&mut buf[..n].into());
                        let frame = frame_res?;
                        let result = frame.map(|frame| Ok((frame, addr)));
                        self.rd = Some(buf);

                        Poll::Ready(result)
                    }
                };
                return res;
            }
        }
    }
}

async fn recv_next(
    socket: Arc<UdpSocket>,
    mut buf: Vec<u8>,
) -> io::Result<(Vec<u8>, usize, SocketAddr)> {
    match socket.recv_from(&mut buf).await {
        Err(e) => Err(e),
        Ok((n, addr)) => Ok((buf, n, addr)),
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
            socket: Arc::new(socket),
            codec,
            out_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
            rd: Some(vec![0u8; INITIAL_RD_CAPACITY]),
            wr: BytesMut::with_capacity(INITIAL_WR_CAPACITY),
            flushed: true,
            recv_fut: None,
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
        &*self.socket
    }

    /// Consumes the `Framed`, returning its underlying I/O stream.
    pub fn into_inner(mut self) -> UdpSocket {
        self.recv_fut = None;
        Arc::try_unwrap(self.socket).unwrap()
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
