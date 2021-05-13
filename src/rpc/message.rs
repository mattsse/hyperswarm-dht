use std::convert::TryFrom;
use std::fmt;
use std::fmt::Formatter;
use std::net::SocketAddr;

use prost::Message as ProstMessage;

use crate::kbucket;
use crate::peers::{decode_peer_ids, decode_peers};
use crate::rpc::{IdBytes, Peer, PeerId, RequestId};

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Holepunch {
    #[prost(bytes, optional, tag = "2")]
    pub from: ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(bytes, optional, tag = "3")]
    pub to: ::std::option::Option<std::vec::Vec<u8>>,
}

impl Holepunch {
    pub fn new(from: Vec<u8>, to: Vec<u8>) -> Self {
        Self {
            from: Some(from),
            to: Some(to),
        }
    }

    pub fn with_from(from: Vec<u8>) -> Self {
        Self {
            from: Some(from),
            to: None,
        }
    }

    pub fn with_to(to: Vec<u8>) -> Self {
        Self {
            from: None,
            to: Some(to),
        }
    }

    /// Decode the `to` field into [`SocketAddr`]
    pub fn decode_to_peer(&self) -> Option<SocketAddr> {
        self.to
            .as_ref()
            .and_then(|to| decode_peers(to.as_slice()).into_iter().next())
    }

    /// Decode the `from` field into [`SocketAddr`]
    pub fn decode_from_peer(&self) -> Option<SocketAddr> {
        self.from
            .as_ref()
            .and_then(|from| decode_peers(from.as_slice()).into_iter().next())
    }
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

    fn valid_key_bytes(key: Option<&Vec<u8>>) -> Option<IdBytes> {
        if let Some(id) = key {
            if id.len() == 32 {
                return Some(IdBytes::try_from(id.as_slice()).expect("s.a."));
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

    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }

    pub(crate) fn get_request_id(&self) -> RequestId {
        RequestId(self.rid as u16)
    }

    pub(crate) fn key(&self, peer: &Peer) -> Option<kbucket::Key<PeerId>> {
        self.valid_id_bytes()
            .map(|id| kbucket::Key::new(PeerId::new(peer.addr, id)))
    }

    /// Decode the `to` field into `PeerId`
    pub(crate) fn decode_to_peer(&self) -> Option<SocketAddr> {
        self.to
            .as_ref()
            .and_then(|to| decode_peers(to.as_slice()).into_iter().next())
    }

    /// Decode the `to` field into `PeerId`
    pub(crate) fn decode_closer_nodes(&self) -> Vec<PeerId> {
        self.closer_nodes
            .as_ref()
            .map(decode_peer_ids)
            .unwrap_or_default()
    }

    /// Decode the messages value into [`Holepunch`]
    pub fn decode_holepunch(&self) -> Option<Holepunch> {
        self.decode_value()
    }

    /// Decodes an instance of the message from the message's value.
    pub fn decode_value<T: prost::Message + Default>(&self) -> Option<T> {
        self.value
            .as_ref()
            .and_then(|val| T::decode(val.as_slice()).ok())
    }

    pub fn set_holepunch(&mut self, holepunch: &Holepunch) {
        let mut buf = Vec::with_capacity(holepunch.encoded_len());
        holepunch.encode(&mut buf).unwrap();
        self.value = Some(buf);
    }

    pub(crate) fn valid_id_bytes(&self) -> Option<IdBytes> {
        Self::valid_key_bytes(self.id.as_ref())
    }

    pub(crate) fn valid_target_id_bytes(&self) -> Option<IdBytes> {
        Self::valid_key_bytes(self.target.as_ref())
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Command {
    Ping,
    FindNode,
    Holepunch,
    Unknown(String),
}

impl Command {
    pub fn is_ping(&self) -> bool {
        match self {
            Command::Ping => true,
            _ => false,
        }
    }

    pub fn is_find_node(&self) -> bool {
        match self {
            Command::FindNode => true,
            _ => false,
        }
    }
    pub fn is_holepunch(&self) -> bool {
        match self {
            Command::Holepunch => true,
            _ => false,
        }
    }

    pub fn is_custom(&self, s: &str) -> bool {
        match self {
            Command::Unknown(cmd) => cmd.as_str() == s,
            _ => false,
        }
    }
}

impl<T: AsRef<str>> From<T> for Command {
    fn from(s: T) -> Self {
        match s.as_ref() {
            "_holepunch" => Command::Holepunch,
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
            Command::Holepunch => f.write_str("_holepunch"),
            Command::Unknown(s) => f.write_str(s),
        }
    }
}
