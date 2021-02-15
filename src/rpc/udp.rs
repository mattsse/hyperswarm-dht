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
use futures::{ready, Future, Sink};
use futures_codec::{Decoder, Encoder};

pub type RecvFuture =
    Pin<Box<dyn Future<Output = (Vec<u8>, io::Result<(usize, SocketAddr)>)> + Send + Sync>>;

// pub type SendFuture = Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + Sync>>;
pub type SendFuture = Pin<Box<dyn Future<Output = (BytesMut, io::Result<usize>)> + Send + Sync>>;

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
    recv_buf: Option<Vec<u8>>,
    send_buf: Option<BytesMut>,
    out_addr: SocketAddr,
    flushed: bool,
    recv_fut: Option<RecvFuture>,
    send_fut: Option<SendFuture>,
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

pub fn io_error(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, message)
}

impl<C: Decoder + Unpin> Stream for UdpFramed<C> {
    type Item = Result<(C::Item, SocketAddr), C::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.recv_fut.is_none() {
            let buf = self.recv_buf.take().unwrap();
            let recv_fut = recv_next(self.socket.clone(), buf);
            self.recv_fut = Some(Box::pin(recv_fut));
        }

        let fut = self.recv_fut.as_mut().unwrap();

        let (buf, recv_res) = ready!(fut.as_mut().poll(cx));

        let res = match recv_res {
            Err(e) => Some(Err(e.into())),
            Ok((n, addr)) => {
                let frame = self.codec.decode(&mut buf[..n].into());
                match frame {
                    Err(e) => Some(Err(e)),
                    Ok(Some(frame)) => Some(Ok((frame, addr))),
                    Ok(None) => Some(Err(io_error("received empty package").into())),
                }
            }
        };
        self.recv_buf = Some(buf);
        self.recv_fut = None;
        Poll::Ready(res)
    }
}

async fn recv_next(
    socket: Arc<UdpSocket>,
    mut buf: Vec<u8>,
) -> (Vec<u8>, io::Result<(usize, SocketAddr)>) {
    let res = socket.recv_from(&mut buf).await;
    (buf, res)
}

async fn send_next(
    socket: Arc<UdpSocket>,
    addr: SocketAddr,
    buf: BytesMut,
) -> (BytesMut, io::Result<usize>) {
    let res = socket.send_to(&buf, addr).await;
    (buf, res)
}

impl<C: Encoder + Unpin> Sink<(C::Item, SocketAddr)> for UdpFramed<C> {
    type Error = C::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => Poll::Ready(Ok(())),
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(self: Pin<&mut Self>, item: (C::Item, SocketAddr)) -> Result<(), Self::Error> {
        let (frame, out_addr) = item;
        let pin = self.get_mut();
        if let Some(buf) = pin.send_buf.as_mut() {
            pin.codec.encode(frame, buf)?;
            pin.out_addr = out_addr;
            pin.flushed = false;
            Ok(())
        } else {
            Err(io_error("start_send called while send in process").into())
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        if self.send_fut.is_none() {
            let socket = self.socket.clone();
            let buf = self.send_buf.take().unwrap();
            let fut = send_next(socket, self.out_addr, buf);
            self.send_fut = Some(Box::pin(fut));
        };

        let fut = self.send_fut.as_mut().unwrap();
        let (mut buf, send_res) = ready!(fut.as_mut().poll(cx));

        let res = match send_res {
            Err(e) => Err(e.into()),
            Ok(n) => {
                if n == buf.len() {
                    Ok(())
                } else {
                    Err(io_error("failed to write entire datagram to socket").into())
                }
            }
        };

        buf.clear();
        self.send_buf = Some(buf);
        self.send_fut = None;
        self.flushed = true;

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
            flushed: true,
            recv_buf: Some(vec![0u8; INITIAL_RD_CAPACITY]),
            recv_fut: None,
            send_buf: Some(BytesMut::with_capacity(INITIAL_WR_CAPACITY)),
            send_fut: None,
            out_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
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
