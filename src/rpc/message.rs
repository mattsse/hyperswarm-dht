use crate::kbucket::KeyBytes;
use crate::rpc::RequestId;
use futures_codec::{Decoder, Encoder};
use std::fmt;
use std::fmt::Formatter;
use std::io;
use std::net::SocketAddr;
use wasm_timer::Instant;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Holepunch {
    #[prost(bytes, optional, tag = "2")]
    pub from: ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(bytes, optional, tag = "3")]
    pub to: ::std::option::Option<std::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Message {
    #[prost(uint64, optional, tag = "11")]
    pub version: ::std::option::Option<u64>,
    /// request/response type + id
    #[prost(enumeration = "Type", required, tag = "1")]
    pub r#type: i32,
    #[prost(uint64, required, tag = "2")]
    pub rid: u64,
    #[prost(bytes, optional, tag = "10")]
    pub to: ::std::option::Option<std::vec::Vec<u8>>,
    /// kademlia stuff
    #[prost(bytes, optional, tag = "3")]
    pub id: ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(bytes, optional, tag = "4")]
    pub target: ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(bytes, optional, tag = "5")]
    pub closer_nodes: ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(bytes, optional, tag = "6")]
    pub roundtrip_token: ::std::option::Option<std::vec::Vec<u8>>,
    /// rpc stuff
    #[prost(string, optional, tag = "7")]
    pub command: ::std::option::Option<std::string::String>,
    #[prost(string, optional, tag = "8")]
    pub error: ::std::option::Option<std::string::String>,
    #[prost(bytes, optional, tag = "9")]
    pub value: ::std::option::Option<std::vec::Vec<u8>>,
}

impl Message {
    pub fn get_type(&self) -> Result<Type, i32> {
        match self.r#type {
            1 => Ok(Type::Query),
            2 => Ok(Type::Update),
            3 => Ok(Type::Response),
            i => Err(i),
        }
    }

    pub fn get_command(&self) -> Option<Command> {
        if let Some(ref s) = self.command {
            match s.as_str() {
                "_holepunch" => Some(Command::HolePunch),
                "_find_node" => Some(Command::FindNode),
                "_ping" => Some(Command::Ping),
                s => Some(Command::Unknown(s.to_string())),
            }
        } else {
            None
        }
    }

    pub(crate) fn get_request_id(&self) -> RequestId {
        RequestId(self.rid)
    }

    pub(crate) fn valid_key_bytes(&self) -> Option<KeyBytes> {
        if let Some(ref id) = self.id {
            if id.len() == 32 {
                return Some(KeyBytes::new(id.as_slice()));
            }
        }
        None
    }

    pub(crate) fn valid_id(&self) -> Option<&[u8]> {
        if let Some(ref id) = self.id {
            if id.len() == 32 {
                return Some(id.as_slice());
            }
        }
        None
    }

    /// Check that the len of the key is exact 32 bytes
    #[inline]
    pub(crate) fn has_valid_id(&self) -> bool {
        self.id
            .as_ref()
            .map(|id| id.len() == 32)
            .unwrap_or_default()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Type {
    Query = 1,
    Update = 2,
    Response = 3,
}

impl Type {
    pub fn id(&self) -> i32 {
        match self {
            Type::Query => 1,
            Type::Update => 2,
            Type::Response => 3,
        }
    }
}

pub trait CommandCodec:
    Encoder<Item = Vec<u8>, Error = io::Error> + Decoder<Item = Vec<u8>, Error = io::Error>
{
}

pub enum Command {
    Ping,
    FindNode,
    HolePunch,
    Unknown(String),
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Command::Ping => f.write_str("_ping"),
            Command::FindNode => f.write_str("_find_node"),
            Command::HolePunch => f.write_str("_holepunch"),
            Command::Unknown(s) => f.write_str(s),
        }
    }
}

pub enum MessageState {
    /// Waiting to send a message to the remote.
    OutPendingSend { msg: Message, addr: SocketAddr },
    /// Waiting to flush the substream so that the data arrives to the remote.
    OutPendingFlush { req: RequestId, timestamp: Instant },
    /// Waiting for an answer back from the remote.
    OutWaitingAnswer { req: RequestId, timestamp: Instant },
    /// Waiting for a request from the remote.
    InWaitingMessage { req: RequestId },
    /// Waiting to send an answer back to the remote.
    InPendingSend { req: RequestId, msg: Message },
    /// Waiting to flush an answer back to the remote.
    InPendingFlush { req: RequestId, timestamp: Instant },
}
