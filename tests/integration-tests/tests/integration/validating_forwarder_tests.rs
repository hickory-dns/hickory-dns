#![cfg(feature = "__dnssec")]

//! Test DNSSEC validation in the forwarder.
//!
//! Note that these tests configure an authoritative name server as the forwarder's name server, not
//! a recursive name server. This happens to work out because we only query the root zone. Any more
//! sophisticated tests would require setting up a recursive name server, which in turn would
//! require a virtual network of authoritative name servers to contact.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use hickory_client::client::{Client, ClientHandle};
use hickory_proto::{
    dnssec::{
        PublicKeyBuf, SigSigner, SigningKey, TrustAnchors, crypto::Ed25519SigningKey, rdata::DNSKEY,
    },
    op::ResponseCode,
    rr::{
        DNSClass, RData, Record, RecordType,
        rdata::{A, SOA},
    },
    runtime::TokioRuntimeProvider,
    udp::UdpClientStream,
};
use hickory_resolver::{
    Name,
    config::{NameServerConfig, ResolverOpts},
};
use hickory_server::{
    ServerFuture,
    authority::{AxfrPolicy, Catalog, ZoneType},
    store::{
        forwarder::{ForwardAuthority, ForwardConfig},
        in_memory::InMemoryAuthority,
    },
};
use test_support::subscribe;
use tokio::{net::UdpSocket, spawn};

#[tokio::test]
async fn query_validate_true_signed_zone_with_soa() {
    subscribe();

    let (name_server_addr, _name_server_future, public_key) =
        setup_authoritative_server(true, true).await;
    let (mut client, _forwarder_future) =
        setup_client_forwarder(name_server_addr, Some(&public_key)).await;
    let response = client
        .query(Name::root(), DNSClass::IN, RecordType::A)
        .await
        .unwrap();
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(response.answers().iter().any(|record| {
        record
            .data()
            .as_a()
            .is_some_and(|a| a.0 == Ipv4Addr::new(1, 2, 3, 4))
    }));
}

#[tokio::test]
async fn query_validate_true_signed_zone_no_soa() {
    subscribe();

    let (name_server_addr, _name_server_future, public_key) =
        setup_authoritative_server(true, false).await;
    let (mut client, _forwarder_future) =
        setup_client_forwarder(name_server_addr, Some(&public_key)).await;
    let response = client
        .query(Name::root(), DNSClass::IN, RecordType::A)
        .await
        .unwrap();
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(response.answers().iter().any(|record| {
        record
            .data()
            .as_a()
            .is_some_and(|a| a.0 == Ipv4Addr::new(1, 2, 3, 4))
    }));
}

#[tokio::test]
async fn query_validate_true_unsigned_zone_with_soa() {
    subscribe();

    let (name_server_addr, _name_server_future, public_key) =
        setup_authoritative_server(false, true).await;
    let (mut client, _forwarder_future) =
        setup_client_forwarder(name_server_addr, Some(&public_key)).await;
    let response = client
        .query(Name::root(), DNSClass::IN, RecordType::A)
        .await
        .unwrap();
    assert_eq!(response.response_code(), ResponseCode::ServFail);
    assert!(response.answers().is_empty());
}

#[tokio::test]
async fn query_validate_true_unsigned_zone_no_soa() {
    subscribe();

    let (name_server_addr, _name_server_future, public_key) =
        setup_authoritative_server(false, false).await;
    let (mut client, _forwarder_future) =
        setup_client_forwarder(name_server_addr, Some(&public_key)).await;
    let response = client
        .query(Name::root(), DNSClass::IN, RecordType::A)
        .await
        .unwrap();
    assert_eq!(response.response_code(), ResponseCode::ServFail);
    assert!(response.answers().is_empty());
}

#[tokio::test]
async fn query_validate_false_signed_zone_with_soa() {
    subscribe();

    let (name_server_addr, _name_server_future, _) = setup_authoritative_server(true, true).await;
    let (mut client, _forwarder_future) = setup_client_forwarder(name_server_addr, None).await;
    let response = client
        .query(Name::root(), DNSClass::IN, RecordType::A)
        .await
        .unwrap();
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(response.answers().iter().any(|record| {
        record
            .data()
            .as_a()
            .is_some_and(|a| a.0 == Ipv4Addr::new(1, 2, 3, 4))
    }));
}

#[tokio::test]
async fn query_validate_false_signed_zone_no_soa() {
    subscribe();

    let (name_server_addr, _name_server_future, _) = setup_authoritative_server(true, false).await;
    let (mut client, _forwarder_future) = setup_client_forwarder(name_server_addr, None).await;
    let response = client
        .query(Name::root(), DNSClass::IN, RecordType::A)
        .await
        .unwrap();
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(response.answers().iter().any(|record| {
        record
            .data()
            .as_a()
            .is_some_and(|a| a.0 == Ipv4Addr::new(1, 2, 3, 4))
    }));
}

#[tokio::test]
async fn query_validate_false_unsigned_zone_with_soa() {
    subscribe();

    let (name_server_addr, _name_server_future, _) = setup_authoritative_server(false, true).await;
    let (mut client, _forwarder_future) = setup_client_forwarder(name_server_addr, None).await;
    let response = client
        .query(Name::root(), DNSClass::IN, RecordType::A)
        .await
        .unwrap();
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(response.answers().iter().any(|record| {
        record
            .data()
            .as_a()
            .is_some_and(|a| a.0 == Ipv4Addr::new(1, 2, 3, 4))
    }));
}

#[tokio::test]
async fn query_validate_false_unsigned_zone_no_soa() {
    subscribe();

    let (name_server_addr, _name_server_future, _) = setup_authoritative_server(false, false).await;
    let (mut client, _forwarder_future) = setup_client_forwarder(name_server_addr, None).await;
    let response = client
        .query(Name::root(), DNSClass::IN, RecordType::A)
        .await
        .unwrap();
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(response.answers().iter().any(|record| {
        record
            .data()
            .as_a()
            .is_some_and(|a| a.0 == Ipv4Addr::new(1, 2, 3, 4))
    }));
}

async fn setup_authoritative_server(
    signed: bool,
    soa: bool,
) -> (SocketAddr, ServerFuture<Catalog>, PublicKeyBuf) {
    // Zone setup
    let key = Ed25519SigningKey::from_pkcs8(&Ed25519SigningKey::generate_pkcs8().unwrap()).unwrap();
    let public_key = key.to_public_key().unwrap();
    let mut authority = InMemoryAuthority::empty(
        Name::root(),
        ZoneType::Primary,
        AxfrPolicy::Deny,
        Some(hickory_server::dnssec::NxProofKind::Nsec),
    );
    authority.upsert_mut(
        Record::from_rdata(Name::root(), 3600, RData::A(A(Ipv4Addr::new(1, 2, 3, 4)))),
        0,
    );
    if soa {
        authority.upsert_mut(
            Record::from_rdata(
                Name::root(),
                3600,
                RData::SOA(SOA::new(
                    Name::parse("nameserver.", None).unwrap(),
                    Name::parse("admin.nameserver.", None).unwrap(),
                    0,
                    3600,
                    3600,
                    3600,
                    3600,
                )),
            ),
            0,
        );
    }
    if signed {
        authority
            .add_zone_signing_key_mut(SigSigner::dnssec(
                DNSKEY::from_key(&key.to_public_key().unwrap()),
                Box::new(key),
                Name::root(),
                Duration::from_secs(86400),
            ))
            .unwrap();
        authority.secure_zone_mut().unwrap();
    }

    // Server setup
    let udp_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let local_addr = udp_socket.local_addr().unwrap();
    let mut catalog = Catalog::new();
    catalog.upsert(Name::root().into(), vec![Arc::new(authority)]);
    let mut server = ServerFuture::new(catalog);
    server.register_socket(udp_socket);

    (local_addr, server, public_key)
}

async fn setup_client_forwarder(
    name_server_addr: SocketAddr,
    public_key: Option<&PublicKeyBuf>,
) -> (Client, ServerFuture<Catalog>) {
    // Server setup
    let mut config = NameServerConfig::udp(name_server_addr.ip());
    config.connections[0].port = name_server_addr.port();
    let mut authority_builder = ForwardAuthority::builder_tokio(ForwardConfig {
        name_servers: vec![config],
        options: Some(ResolverOpts::default()),
    });

    if let Some(public_key) = public_key {
        let mut anchors = TrustAnchors::empty();
        anchors.insert(public_key);
        authority_builder = authority_builder.with_trust_anchor(Arc::new(anchors));
    }
    let authority = authority_builder.build().unwrap();

    let udp_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let local_addr = udp_socket.local_addr().unwrap();
    let mut catalog = Catalog::new();
    catalog.upsert(Name::root().into(), vec![Arc::new(authority)]);
    let mut server = ServerFuture::new(catalog);
    server.register_socket(udp_socket);

    // Client setup
    let stream = UdpClientStream::builder(local_addr, TokioRuntimeProvider::new()).build();
    let (client, bg) = Client::connect(stream).await.unwrap();
    spawn(bg);

    (client, server)
}
