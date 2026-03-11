//! Builder functions for constructing DNSTAP protobuf messages.

use std::net::{IpAddr, SocketAddr};
use std::time::SystemTime;

use prost::Message as ProstMessage;

use crate::net::xfer::Protocol;

use super::client::DnstapMessageType;

/// Generated protobuf types for DNSTAP.
pub(crate) mod dnstap_proto {
    // Suppress warnings from generated code
    #![allow(
        clippy::use_self,
        missing_docs,
        clippy::default_trait_access,
        unreachable_pub,
        unnameable_types
    )]
    include!("proto.rs");
}

use dnstap_proto::{
    Dnstap, Message as DnstapMessage, SocketFamily, SocketProtocol, dnstap::Type as DnstapType,
    message::Type as MessageType,
};

fn socket_family(addr: &IpAddr) -> i32 {
    match addr {
        IpAddr::V4(_) => SocketFamily::Inet as i32,
        IpAddr::V6(_) => SocketFamily::Inet6 as i32,
    }
}

fn addr_bytes(addr: &IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

fn socket_protocol(protocol: Protocol) -> i32 {
    match protocol {
        Protocol::Udp => SocketProtocol::Udp as i32,
        Protocol::Tcp => SocketProtocol::Tcp as i32,
        #[cfg(feature = "__tls")]
        Protocol::Tls => SocketProtocol::Dot as i32,
        #[cfg(feature = "__https")]
        Protocol::Https => SocketProtocol::Doh as i32,
        #[cfg(feature = "__quic")]
        Protocol::Quic => SocketProtocol::Doq as i32,
        #[cfg(feature = "__h3")]
        Protocol::H3 => SocketProtocol::Doh as i32,
        // Protocol is non-exhaustive; fall back to UDP for unknown variants
        _ => SocketProtocol::Udp as i32,
    }
}

fn now_time() -> (u64, u32) {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    (now.as_secs(), now.subsec_nanos())
}

/// Map a `DnstapMessageType` to the corresponding query `MessageType`.
fn query_message_type(mt: &DnstapMessageType) -> MessageType {
    match mt {
        DnstapMessageType::Auth => MessageType::AuthQuery,
        DnstapMessageType::Client => MessageType::ClientQuery,
        DnstapMessageType::Resolver => MessageType::ResolverQuery,
    }
}

/// Map a `DnstapMessageType` to the corresponding response `MessageType`.
fn response_message_type(mt: &DnstapMessageType) -> MessageType {
    match mt {
        DnstapMessageType::Auth => MessageType::AuthResponse,
        DnstapMessageType::Client => MessageType::ClientResponse,
        DnstapMessageType::Resolver => MessageType::ResolverResponse,
    }
}

/// Common parameters for building DNSTAP query and response messages.
pub(super) struct DnstapEventParams<'a> {
    pub identity: &'a Option<Vec<u8>>,
    pub version: &'a Option<Vec<u8>>,
    pub src_addr: SocketAddr,
    pub server_addr: Option<SocketAddr>,
    pub protocol: Protocol,
    pub query_bytes: &'a [u8],
    pub message_type: &'a DnstapMessageType,
}

/// Build a query DNSTAP message with the given message type.
pub(super) fn build_query(params: &DnstapEventParams<'_>) -> Vec<u8> {
    let (time_sec, time_nsec) = now_time();

    let message = DnstapMessage {
        r#type: query_message_type(params.message_type) as i32,
        socket_family: Some(socket_family(&params.src_addr.ip())),
        socket_protocol: Some(socket_protocol(params.protocol)),
        query_address: Some(addr_bytes(&params.src_addr.ip())),
        query_port: Some(params.src_addr.port() as u32),
        query_time_sec: Some(time_sec),
        query_time_nsec: Some(time_nsec),
        query_message: Some(params.query_bytes.to_vec()),
        response_address: params.server_addr.map(|a| addr_bytes(&a.ip())),
        response_port: params.server_addr.map(|a| a.port() as u32),
        response_time_sec: None,
        response_time_nsec: None,
        response_message: None,
        query_zone: None,
        policy: None,
        http_protocol: None,
    };

    let dnstap = Dnstap {
        identity: params.identity.clone(),
        version: params.version.clone(),
        r#type: DnstapType::Message as i32,
        message: Some(message),
        extra: None,
    };

    dnstap.encode_to_vec()
}

/// Decode a DNSTAP message from protobuf bytes (for testing).
#[cfg(test)]
pub(super) fn decode(bytes: &[u8]) -> Dnstap {
    <Dnstap as ProstMessage>::decode(bytes).expect("failed to decode DNSTAP message")
}

/// Build a response DNSTAP message with the given message type.
pub(super) fn build_response(params: &DnstapEventParams<'_>, response_bytes: &[u8]) -> Vec<u8> {
    let (time_sec, time_nsec) = now_time();

    let message = DnstapMessage {
        r#type: response_message_type(params.message_type) as i32,
        socket_family: Some(socket_family(&params.src_addr.ip())),
        socket_protocol: Some(socket_protocol(params.protocol)),
        query_address: Some(addr_bytes(&params.src_addr.ip())),
        query_port: Some(params.src_addr.port() as u32),
        query_message: Some(params.query_bytes.to_vec()),
        response_time_sec: Some(time_sec),
        response_time_nsec: Some(time_nsec),
        response_message: Some(response_bytes.to_vec()),
        query_time_sec: None,
        query_time_nsec: None,
        response_address: params.server_addr.map(|a| addr_bytes(&a.ip())),
        response_port: params.server_addr.map(|a| a.port() as u32),
        query_zone: None,
        policy: None,
        http_protocol: None,
    };

    let dnstap = Dnstap {
        identity: params.identity.clone(),
        version: params.version.clone(),
        r#type: DnstapType::Message as i32,
        message: Some(message),
        extra: None,
    };

    dnstap.encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_query_ipv4_udp() {
        let identity = Some(b"test-server".to_vec());
        let version = Some(b"1.0".to_vec());
        let src_addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let query_bytes = b"\x00\x01\x01\x00";
        let message_type = DnstapMessageType::Auth;

        let encoded = build_query(&DnstapEventParams {
            identity: &identity,
            version: &version,
            src_addr,
            server_addr: None,
            protocol: Protocol::Udp,
            query_bytes,
            message_type: &message_type,
        });
        let decoded = decode(&encoded);

        assert_eq!(decoded.identity.as_deref(), Some(b"test-server".as_slice()));
        assert_eq!(decoded.version.as_deref(), Some(b"1.0".as_slice()));
        assert_eq!(decoded.r#type, DnstapType::Message as i32);

        let msg = decoded.message.unwrap();
        assert_eq!(msg.r#type, MessageType::AuthQuery as i32);
        assert_eq!(msg.socket_family, Some(SocketFamily::Inet as i32));
        assert_eq!(msg.socket_protocol, Some(SocketProtocol::Udp as i32));
        assert_eq!(
            msg.query_address.as_deref(),
            Some([192, 168, 1, 1].as_slice())
        );
        assert_eq!(msg.query_port, Some(12345));
        assert!(msg.query_time_sec.is_some());
        assert!(msg.query_time_nsec.is_some());
        assert_eq!(msg.query_message.as_deref(), Some(query_bytes.as_slice()));
        assert!(msg.response_message.is_none());
    }

    #[test]
    fn test_build_query_ipv6_tcp() {
        let src_addr: SocketAddr = "[::1]:53".parse().unwrap();
        let query_bytes = b"\xab\xcd";
        let message_type = DnstapMessageType::Auth;

        let encoded = build_query(&DnstapEventParams {
            identity: &None,
            version: &None,
            src_addr,
            server_addr: None,
            protocol: Protocol::Tcp,
            query_bytes,
            message_type: &message_type,
        });
        let decoded = decode(&encoded);

        assert!(decoded.identity.is_none());
        let msg = decoded.message.unwrap();
        assert_eq!(msg.socket_family, Some(SocketFamily::Inet6 as i32));
        assert_eq!(msg.socket_protocol, Some(SocketProtocol::Tcp as i32));
        assert_eq!(msg.query_address.as_ref().map(|a| a.len()), Some(16));
        assert_eq!(msg.query_port, Some(53));
    }

    #[test]
    fn test_build_response() {
        let src_addr: SocketAddr = "10.0.0.1:5353".parse().unwrap();
        let query_bytes = b"\x00\x01";
        let response_bytes = b"\x00\x01\x80\x00";
        let message_type = DnstapMessageType::Auth;

        let encoded = build_response(
            &DnstapEventParams {
                identity: &None,
                version: &None,
                src_addr,
                server_addr: None,
                protocol: Protocol::Udp,
                query_bytes,
                message_type: &message_type,
            },
            response_bytes,
        );
        let decoded = decode(&encoded);

        let msg = decoded.message.unwrap();
        assert_eq!(msg.r#type, MessageType::AuthResponse as i32);
        assert_eq!(msg.query_message.as_deref(), Some(query_bytes.as_slice()));
        assert_eq!(
            msg.response_message.as_deref(),
            Some(response_bytes.as_slice())
        );
        assert!(msg.response_time_sec.is_some());
        assert!(msg.response_time_nsec.is_some());
    }
}
