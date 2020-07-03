use std::fmt;
use std::fmt::Formatter;
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;

use futures_codec::{Decoder, Encoder};
use sha2::digest::generic_array::GenericArray;
use wasm_timer::Instant;

use crate::kbucket::KeyBytes;
use crate::peers::decode_peers;
use crate::rpc::query::Query;
use crate::rpc::RequestId;

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
    pub fn is_query(&self) -> bool {
        self.r#type == Type::Query.id()
    }

    pub fn is_response(&self) -> bool {
        self.r#type == Type::Response.id()
    }

    pub fn is_update(&self) -> bool {
        self.r#type == Type::Update.id()
    }

    fn as_valid_key_bytes(key: Option<&Vec<u8>>) -> Option<KeyBytes> {
        if let Some(id) = key {
            if id.len() == 32 {
                return Some(KeyBytes::new(id.as_slice()));
            }
        }
        None
    }

    /// The decoded address in `to`, if any
    pub fn get_to_addr(&self) -> Option<SocketAddr> {
        self.to
            .as_ref()
            .and_then(|to| decode_peers(to).into_iter().next())
    }

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
            Some(Command::from(s))
        } else {
            None
        }
    }

    fn cmd_eq(&self, name: &str) -> bool {
        if let Some(ref cmd) = self.command {
            cmd == name
        } else {
            false
        }
    }

    pub fn is_ping(&self) -> bool {
        self.cmd_eq("_ping")
    }

    pub fn is_find_node(&self) -> bool {
        self.cmd_eq("_find_node")
    }

    pub fn is_holepunch(&self) -> bool {
        self.cmd_eq("_holepunch")
    }

    pub(crate) fn get_request_id(&self) -> RequestId {
        RequestId(self.rid)
    }

    pub(crate) fn valid_id_key_bytes(&self) -> Option<KeyBytes> {
        Self::as_valid_key_bytes(self.id.as_ref())
    }

    pub(crate) fn valid_target_key_bytes(&self) -> Option<KeyBytes> {
        Self::as_valid_key_bytes(self.target.as_ref())
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

// TODO handle inputEncoding and outputEncoding differently
pub trait CommandCodec:
    Encoder<Item = Vec<u8>, Error = io::Error> + Decoder<Item = Vec<u8>, Error = io::Error>
{
    fn update(&mut self, query: &Query) -> Result<Option<Vec<u8>>, String>;

    fn query(&self, query: &Query) -> Result<Option<Vec<u8>>, String>;
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Command {
    Ping,
    FindNode,
    HolePunch,
    Unknown(String),
}

impl<T: AsRef<str>> From<T> for Command {
    fn from(s: T) -> Self {
        match s.as_ref() {
            "_holepunch" => Command::HolePunch,
            "_find_node" => Command::FindNode,
            "_ping" => Command::Ping,
            s => Command::Unknown(s.to_string()),
        }
    }
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
