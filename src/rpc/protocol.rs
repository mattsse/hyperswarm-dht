use std::io;

use bytes::BytesMut;
use futures::io::Error;
use futures_codec::{Decoder, Encoder};
use prost::Message as ProstMessage;

use crate::rpc::message::Message;

/// Rpc codec for the framing
#[derive(Debug, Clone, Default)]
pub(crate) struct DhtRpcCodec;

impl Decoder for DhtRpcCodec {
    type Item = Message;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Note: the udpsocket reads an entire datagram message from the remote address.
        // Therefor `src` should include the entire `Message` payload
        Message::decode(src).map(Some).map_err(invalid_data)
    }
}

impl Encoder for DhtRpcCodec {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(&item);
        Ok(())
    }
}

/// Creates an `io::Error` with `io::ErrorKind::InvalidData`.
fn invalid_data<E>(e: E) -> io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::InvalidData, e)
}
