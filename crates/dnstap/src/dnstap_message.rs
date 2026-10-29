//! Builder functions for constructing DNSTAP protobuf messages.

use std::net::{IpAddr, SocketAddr};
use std::time::SystemTime;

#[cfg(test)]
use prost::Message as ProstMessage;

use crate::DnsTransport;
use crate::client::DnstapMessageType;

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

fn socket_protocol(transport: DnsTransport) -> i32 {
    match transport {
        DnsTransport::Udp => SocketProtocol::Udp as i32,
        DnsTransport::Tcp => SocketProtocol::Tcp as i32,
        DnsTransport::Tls => SocketProtocol::Dot as i32,
        DnsTransport::Https => SocketProtocol::Doh as i32,
        DnsTransport::Quic => SocketProtocol::Doq as i32,
    }
}

/// Local endpoint fields for a message; all four exist together or not at all.
fn socket_fields(
    src_addr: Option<SocketAddr>,
    transport: Option<DnsTransport>,
) -> (Option<i32>, Option<i32>, Option<Vec<u8>>, Option<u32>) {
    let Some(src_addr) = src_addr else {
        return (None, None, None, None);
    };
    (
        Some(socket_family(&src_addr.ip())),
        transport.map(socket_protocol),
        Some(addr_bytes(&src_addr.ip())),
        Some(src_addr.port() as u32),
    )
}

pub(crate) fn now_time() -> (u64, u32) {
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
        DnstapMessageType::Update => MessageType::UpdateQuery,
    }
}

/// Map a `DnstapMessageType` to the corresponding response `MessageType`.
fn response_message_type(mt: &DnstapMessageType) -> MessageType {
    match mt {
        DnstapMessageType::Auth => MessageType::AuthResponse,
        DnstapMessageType::Client => MessageType::ClientResponse,
        DnstapMessageType::Resolver => MessageType::ResolverResponse,
        DnstapMessageType::Update => MessageType::UpdateResponse,
    }
}

/// Common parameters for building DNSTAP query and response messages.
pub(crate) struct DnstapEventParams<'a> {
    pub identity: &'a Option<Vec<u8>>,
    pub version: &'a Option<Vec<u8>>,
    /// Local endpoint; omitted when unknown (e.g. resolver hops).
    pub src_addr: Option<SocketAddr>,
    pub server_addr: Option<SocketAddr>,
    pub transport: Option<DnsTransport>,
    pub query_time: (u64, u32),
    /// When the response was emitted; responses only.
    pub response_time: Option<(u64, u32)>,
    pub message_type: &'a DnstapMessageType,
    /// Bailiwick in wire format; set for authoritative responses and resolver
    /// hop events.
    pub query_zone: Option<&'a [u8]>,
}

/// Assemble the DNSTAP struct for a query or response event.
///
/// Exactly one of `query` and `response` is set; the response time comes from
/// `params.response_time` for responses, `None` for queries.
pub(crate) fn assemble(
    params: &DnstapEventParams<'_>,
    query: Option<&[u8]>,
    response: Option<&[u8]>,
) -> Dnstap {
    let (query_time_sec, query_time_nsec) = params.query_time;

    // Socket metadata exists only when the local endpoint is known.
    let (socket_family, socket_protocol, query_address, query_port) =
        socket_fields(params.src_addr, params.transport);

    let (r#type, response_time) = if query.is_some() {
        (query_message_type(params.message_type) as i32, None)
    } else {
        (
            response_message_type(params.message_type) as i32,
            Some(params.response_time.unwrap_or_else(now_time)),
        )
    };
    let (response_time_sec, response_time_nsec) = response_time
        .map(|(sec, nsec)| (Some(sec), Some(nsec)))
        .unwrap_or((None, None));

    let message = DnstapMessage {
        r#type,
        socket_family,
        socket_protocol,
        query_address,
        query_port,
        query_time_sec: Some(query_time_sec),
        query_time_nsec: Some(query_time_nsec),
        query_message: query.map(<[u8]>::to_vec),
        response_time_sec,
        response_time_nsec,
        response_message: response.map(<[u8]>::to_vec),
        response_address: params.server_addr.map(|a| addr_bytes(&a.ip())),
        response_port: params.server_addr.map(|a| a.port() as u32),
        query_zone: params.query_zone.map(<[u8]>::to_vec),
        policy: None,
        http_protocol: None,
    };
    Dnstap {
        identity: params.identity.clone(),
        version: params.version.clone(),
        r#type: DnstapType::Message as i32,
        message: Some(message),
        extra: None,
    }
}

/// Encode a query DNSTAP message (for testing).
#[cfg(test)]
pub(crate) fn build_query(params: &DnstapEventParams<'_>, query_bytes: &[u8]) -> Vec<u8> {
    assemble(params, Some(query_bytes), None).encode_to_vec()
}

/// Decode a DNSTAP message from protobuf bytes (for testing).
#[cfg(test)]
pub(crate) fn decode(bytes: &[u8]) -> Dnstap {
    <Dnstap as ProstMessage>::decode(bytes).expect("failed to decode DNSTAP message")
}

/// Encode a response DNSTAP message.
///
/// The response time is recorded at call; the query time comes from `params`.
#[cfg(test)]
pub(crate) fn build_response(params: &DnstapEventParams<'_>, response_bytes: &[u8]) -> Vec<u8> {
    assemble(params, None, Some(response_bytes)).encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_query_update() {
        let src_addr: SocketAddr = "10.0.0.1:53".parse().unwrap();
        let query_bytes = b"\x12\x34\x28\x00";
        let message_type = DnstapMessageType::Update;

        let encoded = build_query(
            &DnstapEventParams {
                identity: &None,
                version: &None,
                src_addr: Some(src_addr),
                server_addr: None,
                transport: Some(DnsTransport::Udp),
                query_time: (1_000_000, 0),
                response_time: Some((2_000_000, 0)),
                message_type: &message_type,
                query_zone: None,
            },
            query_bytes,
        );
        let decoded = decode(&encoded);

        let msg = decoded.message.unwrap();
        assert_eq!(msg.r#type, MessageType::UpdateQuery as i32);
        assert_eq!(msg.query_message.as_deref(), Some(query_bytes.as_slice()));
    }

    #[test]
    fn test_build_response_update() {
        let src_addr: SocketAddr = "10.0.0.1:53".parse().unwrap();
        let response_bytes = b"\x12\x34\xd8\x80";
        let message_type = DnstapMessageType::Update;

        let encoded = build_response(
            &DnstapEventParams {
                identity: &None,
                version: &None,
                src_addr: Some(src_addr),
                server_addr: None,
                transport: Some(DnsTransport::Udp),
                query_time: (1_000_000, 0),
                response_time: Some((2_000_000, 0)),
                message_type: &message_type,
                query_zone: None,
            },
            response_bytes,
        );
        let decoded = decode(&encoded);

        let msg = decoded.message.unwrap();
        assert_eq!(msg.r#type, MessageType::UpdateResponse as i32);
        assert_eq!(
            msg.response_message.as_deref(),
            Some(response_bytes.as_slice())
        );
    }

    #[test]
    fn test_build_query_ipv4_udp() {
        let identity = Some(b"test-server".to_vec());
        let version = Some(b"1.0".to_vec());
        let src_addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let query_bytes = b"\x00\x01\x01\x00";
        let message_type = DnstapMessageType::Auth;

        let encoded = build_query(
            &DnstapEventParams {
                identity: &identity,
                version: &version,
                src_addr: Some(src_addr),
                server_addr: None,
                transport: Some(DnsTransport::Udp),
                query_time: (1_000_000, 0),
                response_time: Some((2_000_000, 0)),
                message_type: &message_type,
                query_zone: None,
            },
            query_bytes,
        );
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
    fn test_build_query_resolver_hop() {
        // Resolver hops have no known local endpoints; socket metadata is
        // omitted and the bailiwick is set.
        let query_bytes = b"\x12\x34\x00\x00";
        let message_type = DnstapMessageType::Resolver;

        let encoded = build_query(
            &DnstapEventParams {
                identity: &None,
                version: &None,
                src_addr: None,
                server_addr: None,
                transport: None,
                query_time: (1_000_000, 0),
                response_time: Some((2_000_000, 0)),
                message_type: &message_type,
                query_zone: Some(b"\x03com\x00"),
            },
            query_bytes,
        );
        let decoded = decode(&encoded);

        let msg = decoded.message.unwrap();
        assert_eq!(msg.r#type, MessageType::ResolverQuery as i32);
        assert!(msg.socket_family.is_none());
        assert!(msg.socket_protocol.is_none());
        assert!(msg.query_address.is_none());
        assert!(msg.query_port.is_none());
        assert_eq!(msg.query_zone.as_deref(), Some(b"\x03com\x00".as_slice()));
    }

    #[test]
    fn test_build_query_ipv6_tcp() {
        let src_addr: SocketAddr = "[::1]:53".parse().unwrap();
        let query_bytes = b"\xab\xcd";
        let message_type = DnstapMessageType::Auth;

        let encoded = build_query(
            &DnstapEventParams {
                identity: &None,
                version: &None,
                src_addr: Some(src_addr),
                server_addr: None,
                transport: Some(DnsTransport::Tcp),
                query_time: (1_000_000, 0),
                response_time: Some((2_000_000, 0)),
                message_type: &message_type,
                query_zone: None,
            },
            query_bytes,
        );
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
        let response_bytes = b"\x00\x01\x80\x00";
        let message_type = DnstapMessageType::Auth;

        let encoded = build_response(
            &DnstapEventParams {
                identity: &None,
                version: &None,
                src_addr: Some(src_addr),
                server_addr: None,
                transport: Some(DnsTransport::Udp),
                query_time: (1_000_000, 0),
                response_time: Some((2_000_000, 0)),
                message_type: &message_type,
                query_zone: None,
            },
            response_bytes,
        );
        let decoded = decode(&encoded);

        let msg = decoded.message.unwrap();
        assert_eq!(msg.r#type, MessageType::AuthResponse as i32);
        assert!(msg.query_message.is_none());
        assert_eq!(
            msg.response_message.as_deref(),
            Some(response_bytes.as_slice())
        );
        assert_eq!(msg.query_time_sec, Some(1_000_000));
        assert_eq!(msg.query_time_nsec, Some(0));
        assert!(msg.response_time_sec.is_some());
        assert!(msg.response_time_nsec.is_some());
    }
}
