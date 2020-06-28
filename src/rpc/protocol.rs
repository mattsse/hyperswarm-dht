use std::io;

use bytes::{Bytes, BytesMut};
use prost::Message as ProstMessage;
use tokio_util::codec::{Decoder, Encoder};
use unsigned_varint::codec::UviBytes;

use crate::rpc::message::Message;

/// Gossip codec for the framing
pub(crate) struct DhtRpcCodec;

impl Decoder for DhtRpcCodec {
    type Item = Message;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Note the udpsocket reads an entire datagram message from the remote address. Therefor `src` should include the entire `Message` payload
        Message::decode(src).map(Some).map_err(invalid_data)
    }
}

impl Encoder<Vec<u8>> for DhtRpcCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Vec<u8>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.copy_from_slice(&item);
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
