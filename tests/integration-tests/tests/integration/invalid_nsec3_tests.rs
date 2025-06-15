#![cfg(feature = "__dnssec")]

//! These tests confirm that NSEC3 validation fails when omitting any required NSEC3 record from
//! responses.

use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use hickory_client::client::{ClientHandle, DnssecClient};
use hickory_proto::{
    ProtoErrorKind,
    dnssec::{
        Algorithm, DigestType, Nsec3HashAlgorithm, Proof, PublicKeyBuf, SigSigner, SigningKey,
        TrustAnchors,
        crypto::Ed25519SigningKey,
        rdata::{DNSKEY, DNSSECRData, DS},
    },
    op::{Header, MessageType, ResponseCode},
    rr::{
        DNSClass, LowerName, RData, Record, RecordType,
        rdata::{A, AAAA, HINFO, MX, NS, SOA},
    },
    runtime::TokioRuntimeProvider,
    udp::UdpClientStream,
    xfer::DnsResponse,
};
use hickory_resolver::Name;
use hickory_server::{
    ServerFuture,
    authority::{AxfrPolicy, Catalog, MessageResponseBuilder, ZoneType},
    dnssec::NxProofKind,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    store::in_memory::InMemoryAuthority,
};
use test_support::subscribe;
use tokio::{net::UdpSocket, spawn};
use tracing::error;

/// Based on RFC 5155 section B.1.
#[tokio::test]
async fn name_error() {
    subscribe();

    let (key, public_key) = generate_key();
    let catalog = example_zone_catalog(key);
    let (mut client, _honest_server) = setup_client_server(catalog, &public_key).await;

    let query_name = Name::parse("a.c.x.w.example.", None).unwrap();
    let query_type = RecordType::A;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NXDomain);

    let dnskey_response = fetch_dnskey(&mut client).await;

    // Covers "next closer" name.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
    )
    .await;

    // Matches closest encloser.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "b4um86eghhds6nea196smvmlo4ors995",
    )
    .await;

    // Covers wildcard at closest encloser.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "35mthgpgcu1qg68fab165klnsnk3dpvl",
    )
    .await;
}

/// Based on RFC 5155 section B.2.
#[tokio::test]
async fn no_data_error() {
    subscribe();

    let (key, public_key) = generate_key();
    let catalog = example_zone_catalog(key);
    let (mut client, _honest_server) = setup_client_server(catalog, &public_key).await;

    let query_name = Name::parse("ns1.example.", None).unwrap();
    let query_type = RecordType::MX;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(response.answers().is_empty());

    let dnskey_response = fetch_dnskey(&mut client).await;

    // Matches query.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
    )
    .await;
}

/// Based on RFC 5155 section B.2.1.
#[tokio::test]
async fn no_data_error_empty_non_terminal() {
    subscribe();

    let (key, public_key) = generate_key();
    let catalog = example_zone_catalog(key);
    let (mut client, _honest_server) = setup_client_server(catalog, &public_key).await;

    let query_name = Name::parse("y.w.example.", None).unwrap();
    let query_type = RecordType::A;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(response.answers().is_empty());

    let dnskey_response = fetch_dnskey(&mut client).await;

    // Matches query.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "ji6neoaepv8b5o6k4ev33abha8ht9fgc",
    )
    .await;
}

/// Based on RFC 5155 section B.3.
#[ignore = "authority returns an NXDOMAIN for mc.c.example. instead of a referral to nameservers for c.example."]
#[tokio::test]
async fn referral_opt_out_unsigned() {
    subscribe();

    let (key, public_key) = generate_key();
    let catalog = example_zone_catalog(key);
    let (mut client, _honest_server) = setup_client_server(catalog, &public_key).await;

    let query_name = Name::parse("mc.c.example.", None).unwrap();
    let query_type = RecordType::MX;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert_eq!(response.answer_count(), 0);
    assert!(
        response
            .name_servers()
            .iter()
            .any(|record| record.record_type().is_ns())
    );

    let dnskey_response = fetch_dnskey(&mut client).await;

    // Covers "next closer" name.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "35mthgpgcu1qg68fab165klnsnk3dpvl",
    )
    .await;

    // Matches closest encloser.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
    )
    .await;
}

/// Based on RFC 5155 section B.4.
#[ignore = "validation fails for one NSEC3 record's signature"]
#[tokio::test]
async fn wildcard_expansion() {
    subscribe();

    let (key, public_key) = generate_key();
    let catalog = example_zone_catalog(key);
    let (mut client, _honest_server) = setup_client_server(catalog, &public_key).await;

    let query_name = Name::parse("a.z.w.example.", None).unwrap();
    let query_type = RecordType::MX;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(response.answer_count() > 0);

    let dnskey_response = fetch_dnskey(&mut client).await;

    // Covers "next closer" name.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "q04jkcevqvmu85r014c7dkba38o0ji5r",
    )
    .await;
}

/// Based on RFC 5155 section B.5.
#[ignore = "validation fails for one NSEC3 record's signature"]
#[tokio::test]
async fn wildcard_no_data_error() {
    subscribe();

    let (key, public_key) = generate_key();
    let catalog = example_zone_catalog(key);
    let (mut client, _honest_server) = setup_client_server(catalog, &public_key).await;

    let query_name = Name::parse("a.z.w.example.", None).unwrap();
    let query_type = RecordType::AAAA;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(response.answers().is_empty());

    let dnskey_response = fetch_dnskey(&mut client).await;

    // Matches closest encloser.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "k8udemvp1j2f7eg6jebps17vp3n8i58h",
    )
    .await;

    // Covers "next closer" name.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "q04jkcevqvmu85r014c7dkba38o0ji5r",
    )
    .await;

    // Matches wildcard at closest encloser.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "r53bq7cc2uvmubfu5ocmm6pers9tk9en",
    )
    .await;
}

/// Based on RFC 5155 section B.6.
#[tokio::test]
async fn ds_child_zone_no_data_error() {
    subscribe();

    let (key, public_key) = generate_key();
    let catalog = example_zone_catalog(key);
    let (mut client, _honest_server) = setup_client_server(catalog, &public_key).await;

    let query_name = Name::parse("example.", None).unwrap();
    let query_type = RecordType::DS;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(response.answers().is_empty());

    let dnskey_response = fetch_dnskey(&mut client).await;

    // Matches query.
    test_exclude_nsec3(
        &query_name,
        query_type,
        &response,
        &dnskey_response,
        "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
    )
    .await;
}

fn generate_key() -> (Box<dyn SigningKey>, PublicKeyBuf) {
    let signing_key =
        Ed25519SigningKey::from_pkcs8(&Ed25519SigningKey::generate_pkcs8().unwrap()).unwrap();
    let public_key = signing_key.to_public_key().unwrap();
    (Box::new(signing_key), public_key)
}

async fn fetch_dnskey(client: &mut DnssecClient) -> DnsResponse {
    let dnskey_response = client
        .query(
            Name::parse("example.", None).unwrap(),
            DNSClass::IN,
            RecordType::DNSKEY,
        )
        .await
        .unwrap();
    assert_eq!(dnskey_response.response_code(), ResponseCode::NoError);
    dnskey_response
}

fn print_response(response: &DnsResponse) {
    for (section_heading, section) in [
        ("; Answers", response.answers()),
        ("; Authorities", response.name_servers()),
        ("; Additionals", response.additionals()),
    ] {
        println!("{section_heading}");
        for record in section {
            println!("{record}");
        }
    }
}

async fn setup_client_server<H>(
    handler: H,
    public_key: &PublicKeyBuf,
) -> (DnssecClient, ServerFuture<H>)
where
    H: RequestHandler,
{
    // Server setup
    let udp_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let local_addr = udp_socket.local_addr().unwrap();
    let mut server = ServerFuture::new(handler);
    server.register_socket(udp_socket);

    // Client setup
    let mut trust_anchor = TrustAnchors::empty();
    trust_anchor.insert(public_key);
    let stream = UdpClientStream::builder(local_addr, TokioRuntimeProvider::new()).build();
    let (client, bg) = DnssecClient::builder(stream)
        .trust_anchor(trust_anchor)
        .build()
        .await
        .unwrap();
    spawn(bg);

    (client, server)
}

/// Replacement for `Catalog` that returns one of two canned responses.
struct MockHandler {
    query_name: LowerName,
    query_type: RecordType,
    response: DnsResponse,
    dnskey_name: LowerName,
    dnskey_response: DnsResponse,
}

impl MockHandler {
    fn new(
        query_name: LowerName,
        query_type: RecordType,
        response: DnsResponse,
        dnskey_response: DnsResponse,
    ) -> Self {
        let dnskey_name = Name::parse("example.", None).unwrap().into();
        Self {
            query_name,
            query_type,
            response,
            dnskey_name,
            dnskey_response,
        }
    }
}

#[async_trait]
impl RequestHandler for MockHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let request_info = request.request_info().unwrap();
        if request_info.query.name() == &self.query_name
            && request_info.query.query_type() == self.query_type
        {
            send_response(response_handle, request, &self.response).await
        } else if request_info.query.name() == &self.dnskey_name
            && request_info.query.query_type() == RecordType::DNSKEY
        {
            send_response(response_handle, request, &self.dnskey_response).await
        } else {
            error!(query = ?request_info.query, "unexpected request");
            let response_builder = MessageResponseBuilder::from_message_request(request);
            let mut response_header = Header::response_from_request(request.header());
            response_header.set_response_code(ResponseCode::ServFail);
            let result = response_handle
                .send_response(response_builder.build_no_records(response_header))
                .await;
            if let Err(e) = result {
                error!(error = %e, "error responding to request");
            }
            response_header.into()
        }
    }
}

/// Helper for implementation of `RequestHandler`.
///
/// Turns a `DnsResponse` into a `MessageResponse`, performs error handling, and produces a
/// `ResponseInfo`.
async fn send_response(
    mut response_handle: impl ResponseHandler,
    request: &Request,
    response: &DnsResponse,
) -> ResponseInfo {
    let mut response_header = *response.header();
    response_header.set_id(request.id());

    let mut message_response_builder = MessageResponseBuilder::from_message_request(request);
    if let Some(edns) = response.extensions() {
        message_response_builder.edns(edns.clone());
    }
    let message_response = message_response_builder.build(
        response_header,
        response.answers(),
        response.name_servers(),
        [],
        response.additionals(),
    );

    let result = response_handle.send_response(message_response).await;
    match result {
        Ok(info) => info,
        Err(e) => {
            error!(error = %e, "error responding to request");
            let mut header = Header::new(
                request.id(),
                MessageType::Response,
                request.header().op_code(),
            );
            header.set_response_code(ResponseCode::ServFail);
            ResponseInfo::from(header)
        }
    }
}

/// Modifies a response to remove a specific NSEC3 record, and confirms that the validating client
/// treats the response as bogus.
async fn test_exclude_nsec3(
    query_name: &Name,
    query_type: RecordType,
    original_response: &DnsResponse,
    dnskey_response: &DnsResponse,
    nsec3_owner_name: &str,
) {
    let zone = Name::parse("example.", None).unwrap();
    let nsec3_name = Name::parse(nsec3_owner_name, Some(&zone)).unwrap();

    let mut modified_response = original_response.clone();
    modified_response
        .name_servers_mut()
        .retain(|record| record.name() != &nsec3_name);
    let new_count = modified_response.name_servers().len().try_into().unwrap();
    modified_response.set_name_server_count(new_count);
    assert!(
        modified_response.name_servers().len() < original_response.name_servers().len(),
        "failed to remove expected NSEC3 record and signature at {nsec3_owner_name}: {modified_response:?}"
    );

    let public_key = dnskey_response.answers()[0]
        .data()
        .as_dnssec()
        .unwrap()
        .as_dnskey()
        .unwrap()
        .public_key();

    let mock = MockHandler::new(
        query_name.into(),
        query_type,
        modified_response,
        dnskey_response.clone(),
    );
    let (mut client, _mock_server) = setup_client_server(mock, public_key).await;

    let error = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap_err();
    let ProtoErrorKind::Nsec { proof, .. } = error.kind() else {
        panic!("wrong proto error kind {error}");
    };
    assert_eq!(proof, &Proof::Bogus);
}

/// Constructs a catalog based on the zone file described in RFC 5155 Appendix A.
fn example_zone_catalog(key: Box<dyn SigningKey>) -> Catalog {
    let origin = Name::parse("example.", None).unwrap();

    let authority = example_zone_authority(origin.clone(), key);

    let mut catalog = Catalog::new();
    catalog.upsert(origin.into(), vec![Arc::new(authority)]);
    catalog
}

/// Constructs an authority based on the zone file described in RFC 5155 Appendix A.
fn example_zone_authority(origin: Name, key: Box<dyn SigningKey>) -> InMemoryAuthority {
    let mut authority = InMemoryAuthority::empty(
        origin.clone(),
        ZoneType::Primary,
        AxfrPolicy::Deny,
        Some(NxProofKind::Nsec3 {
            algorithm: Nsec3HashAlgorithm::SHA1,
            salt: data_encoding::HEXLOWER_PERMISSIVE
                .decode(b"aabbccdd")
                .unwrap()
                .into(),
            iterations: 12,
            opt_out: true,
        }),
    );

    // Note that the serial will be incremented from 0 to 1 by `secure_zone_mut()`.
    authority.upsert_mut(
        Record::from_rdata(
            origin.clone(),
            3600,
            RData::SOA(SOA::new(
                Name::parse("ns1", Some(&origin)).unwrap(),
                Name::parse("bugs.x.w", Some(&origin)).unwrap(),
                0,
                3600,
                300,
                3600000,
                3600,
            )),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            origin.clone(),
            3600,
            RData::NS(NS(Name::parse("ns1", Some(&origin)).unwrap())),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            origin.clone(),
            3600,
            RData::NS(NS(Name::parse("ns2", Some(&origin)).unwrap())),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            origin.clone(),
            3600,
            RData::MX(MX::new(1, Name::parse("xx", Some(&origin)).unwrap())),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            Name::parse("2t7b4g4vsa5smi47k61mv5bv1a22bojr", Some(&origin)).unwrap(),
            3600,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 127))),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            Name::parse("a", Some(&origin)).unwrap(),
            3600,
            RData::NS(NS(Name::parse("ns1.a", Some(&origin)).unwrap())),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            Name::parse("a", Some(&origin)).unwrap(),
            3600,
            RData::NS(NS(Name::parse("ns2.a", Some(&origin)).unwrap())),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            Name::parse("a", Some(&origin)).unwrap(),
            3600,
            RData::DNSSEC(DNSSECRData::DS(DS::new(
                58470,
                #[allow(deprecated)]
                Algorithm::RSASHA1,
                #[allow(deprecated)]
                DigestType::SHA1,
                data_encoding::HEXUPPER_PERMISSIVE
                    .decode(b"3079F1593EBAD6DC121E202A8B766A6A4837206C")
                    .unwrap(),
            ))),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            Name::parse("ns1.a", Some(&origin)).unwrap(),
            3600,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 5))),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            Name::parse("ns2.a", Some(&origin)).unwrap(),
            3600,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 6))),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            Name::parse("ai", Some(&origin)).unwrap(),
            3600,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 9))),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            Name::parse("ai", Some(&origin)).unwrap(),
            3600,
            RData::HINFO(HINFO::new("KLH-10".to_owned(), "ITS".to_owned())),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            Name::parse("ai", Some(&origin)).unwrap(),
            3600,
            RData::AAAA(AAAA(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0xf00, 0xbaa9,
            ))),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            Name::parse("c", Some(&origin)).unwrap(),
            3600,
            RData::NS(NS(Name::parse("ns1.c", Some(&origin)).unwrap())),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            Name::parse("c", Some(&origin)).unwrap(),
            3600,
            RData::NS(NS(Name::parse("ns2.c", Some(&origin)).unwrap())),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            Name::parse("ns1.c", Some(&origin)).unwrap(),
            3600,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 7))),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            Name::parse("ns2.c", Some(&origin)).unwrap(),
            3600,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 8))),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            Name::parse("ns1", Some(&origin)).unwrap(),
            3600,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            Name::parse("ns2", Some(&origin)).unwrap(),
            3600,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 2))),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            Name::parse("*.w", Some(&origin)).unwrap(),
            3600,
            RData::MX(MX::new(1, Name::parse("ai", Some(&origin)).unwrap())),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            Name::parse("x.w", Some(&origin)).unwrap(),
            3600,
            RData::MX(MX::new(1, Name::parse("xx", Some(&origin)).unwrap())),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            Name::parse("x.y.w", Some(&origin)).unwrap(),
            3600,
            RData::MX(MX::new(1, Name::parse("xx", Some(&origin)).unwrap())),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            Name::parse("xx", Some(&origin)).unwrap(),
            3600,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 10))),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            Name::parse("xx", Some(&origin)).unwrap(),
            3600,
            RData::HINFO(HINFO::new("KLH-10".to_owned(), "TOPS-20".to_owned())),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            Name::parse("xx", Some(&origin)).unwrap(),
            3600,
            RData::AAAA(AAAA(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0xf00, 0xbaaa,
            ))),
        ),
        0,
    );

    // Add DNSKEY and sign zone
    authority
        .add_zone_signing_key_mut(SigSigner::dnssec(
            DNSKEY::from_key(&key.to_public_key().unwrap()),
            key,
            origin.clone(),
            Duration::from_secs(86400),
        ))
        .unwrap();
    authority.secure_zone_mut().unwrap();

    authority
}

/// Confirm that the generated NSEC3 chain matches the zone file from RFC 5155 Appendix A.
#[test]
fn example_zone_nsec3_chain() {
    let key = Ed25519SigningKey::from_pkcs8(&Ed25519SigningKey::generate_pkcs8().unwrap()).unwrap();
    let origin = Name::parse("example.", None).unwrap();
    let mut authority = example_zone_authority(origin.clone(), Box::new(key));

    let names = authority
        .records_get_mut()
        .keys()
        .map(|key| key.name.to_ascii())
        .collect::<HashSet<_>>();
    let expected = HashSet::from([
        "example.".to_owned(),
        "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.".to_owned(),
        "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.".to_owned(),
        "2vptu5timamqttgl4luu9kg21e0aor3s.example.".to_owned(),
        "35mthgpgcu1qg68fab165klnsnk3dpvl.example.".to_owned(),
        "a.example.".to_owned(),
        "ns1.a.example.".to_owned(),
        "ns2.a.example.".to_owned(),
        "ai.example.".to_owned(),
        "b4um86eghhds6nea196smvmlo4ors995.example.".to_owned(),
        "c.example.".to_owned(),
        "ns1.c.example.".to_owned(),
        "ns2.c.example.".to_owned(),
        "gjeqe526plbf1g8mklp59enfd789njgi.example.".to_owned(),
        "ji6neoaepv8b5o6k4ev33abha8ht9fgc.example.".to_owned(),
        "k8udemvp1j2f7eg6jebps17vp3n8i58h.example.".to_owned(),
        "kohar7mbb8dc2ce8a9qvl8hon4k53uhi.example.".to_owned(),
        "ns1.example.".to_owned(),
        "ns2.example.".to_owned(),
        "q04jkcevqvmu85r014c7dkba38o0ji5r.example.".to_owned(),
        "r53bq7cc2uvmubfu5ocmm6pers9tk9en.example.".to_owned(),
        "t644ebqk9bibcna874givr6joj62mlhv.example.".to_owned(),
        "*.w.example.".to_owned(),
        "x.w.example.".to_owned(),
        "x.y.w.example.".to_owned(),
        "xx.example.".to_owned(),
    ]);
    assert_eq!(names, expected);
}
