#![allow(clippy::dbg_macro)]

use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use futures_executor::block_on;

use hickory_proto::{
    op::{Header, Message, Query, ResponseCode},
    rr::{
        rdata::{A as A4, AAAA},
        Name, RData, Record, RecordType,
    },
    serialize::binary::BinDecodable,
};
use hickory_server::authority::{
    AuthLookup, Authority, LookupError, LookupOptions, MessageRequest,
};
use hickory_server::server::{Protocol, RequestInfo};

const TEST_HEADER: &Header = &Header::new();

pub fn test_a_lookup<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A).into();
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let lookup = block_on(authority.search(request_info, LookupOptions::default())).unwrap();

    match lookup
        .unwrap()
        .into_iter()
        .next()
        .expect("A record not found in authority")
        .data()
        .and_then(RData::as_a)
    {
        Some(ip) => assert_eq!(A4::new(127, 0, 0, 1), *ip),
        _ => panic!("wrong rdata type returned"),
    }
}

#[allow(clippy::unreadable_literal)]
pub fn test_soa<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let lookup = block_on(authority.soa()).unwrap();

    match lookup
        .into_iter()
        .next()
        .expect("SOA record not found in authority")
        .data()
    {
        Some(RData::SOA(soa)) => {
            assert_eq!(Name::from_str("hickory-dns.org.").unwrap(), *soa.mname());
            assert_eq!(
                Name::from_str("root.hickory-dns.org.").unwrap(),
                *soa.rname()
            );
            assert_eq!(199609203, soa.serial());
            assert_eq!(28800, soa.refresh());
            assert_eq!(7200, soa.retry());
            assert_eq!(604800, soa.expire());
            assert_eq!(86400, soa.minimum());
        }
        _ => panic!("wrong rdata type returned"),
    }
}

pub fn test_ns<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let lookup = block_on(authority.ns(LookupOptions::default())).unwrap();

    match lookup
        .into_iter()
        .next()
        .expect("NS record not found in authority")
        .data()
    {
        Some(RData::NS(name)) => assert_eq!(Name::from_str("bbb.example.com.").unwrap(), name.0),
        _ => panic!("wrong rdata type returned"),
    }
}

pub fn test_ns_lookup<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(Name::from_str("example.com.").unwrap(), RecordType::NS).into();
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let mut lookup = block_on(authority.search(request_info, LookupOptions::default()))
        .unwrap()
        .unwrap();

    let additionals = dbg!(lookup
        .take_additionals()
        .expect("no additionals in response"));

    let ns = lookup
        .into_iter()
        .next()
        .expect("NS record not found in authority")
        .data()
        .and_then(RData::as_ns)
        .expect("Not an NS record");

    assert_eq!(Name::from_str("bbb.example.com.").unwrap(), ns.0);

    let a = additionals
        .into_iter()
        .next()
        .expect("A record not found")
        .data()
        .and_then(RData::as_a)
        .expect("Not an A record");
    assert_eq!(A4::new(127, 0, 0, 2), *a);
}

pub fn test_mx<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(Name::from_str("example.com.").unwrap(), RecordType::MX).into();
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let mut lookup = block_on(authority.search(request_info, LookupOptions::default()))
        .unwrap()
        .unwrap();

    let additionals = dbg!(lookup
        .take_additionals()
        .expect("no additionals in response"));

    let mx = lookup
        .into_iter()
        .next()
        .expect("MX record not found in authority")
        .data()
        .and_then(RData::as_mx)
        .expect("Not an MX record");

    assert_eq!(
        Name::from_str("alias.example.com.").unwrap(),
        *mx.exchange()
    );

    // assert the A record is in the additionals section
    let mut additionals = additionals.into_iter();

    let cname = additionals
        .next()
        .expect("CNAME record not found")
        .data()
        .and_then(RData::as_cname)
        .expect("Not an CNAME record");
    assert_eq!(Name::from_str("www.example.com.").unwrap(), cname.0);

    let a = additionals
        .next()
        .expect("A record not found")
        .data()
        .and_then(RData::as_a)
        .expect("Not an A record");
    assert_eq!(A4::new(127, 0, 0, 1), *a);

    let aaaa = additionals
        .next()
        .expect("AAAA record not found")
        .data()
        .and_then(RData::as_aaaa)
        .expect("Not an AAAA record");
    assert_eq!(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1), *aaaa);
}

pub fn test_mx_to_null<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(
        Name::from_str("no-service.example.com.").unwrap(),
        RecordType::MX,
    )
    .into();
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let mut lookup = block_on(authority.search(request_info, LookupOptions::default()))
        .unwrap()
        .unwrap();

    // In this case there should be no additional records
    assert!(lookup.take_additionals().is_none());

    let mx = lookup
        .into_iter()
        .next()
        .expect("MX record not found in authority")
        .data()
        .and_then(RData::as_mx)
        .expect("Not an MX record");

    assert_eq!(Name::from_str(".").unwrap(), *mx.exchange());
}

pub fn test_cname<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(
        Name::from_str("alias.example.com.").unwrap(),
        RecordType::CNAME,
    )
    .into();
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let lookup = block_on(authority.search(request_info, LookupOptions::default()))
        .unwrap()
        .unwrap();

    let cname = lookup
        .into_iter()
        .next()
        .expect("CNAME record not found in authority")
        .data()
        .and_then(RData::as_cname)
        .expect("Not an A record");

    assert_eq!(Name::from_str("www.example.com.").unwrap(), cname.0);
}

pub fn test_cname_alias<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(Name::from_str("alias.example.com.").unwrap(), RecordType::A).into();
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let mut lookup = block_on(authority.search(request_info, LookupOptions::default()))
        .unwrap()
        .unwrap();

    let additionals = lookup
        .take_additionals()
        .expect("no additionals in response");

    // for cname lookups, we have a cname returned in the answer, the catalog will perform additional lookups
    let cname = lookup
        .into_iter()
        .next()
        .expect("CNAME record not found in authority")
        .data()
        .and_then(RData::as_cname)
        .expect("Not a CNAME record");

    assert_eq!(Name::from_str("www.example.com.").unwrap(), cname.0);

    // assert the A record is in the additionals section
    let a = additionals
        .into_iter()
        .next()
        .expect("A record not found")
        .data()
        .and_then(RData::as_a)
        .expect("Not an A record");
    assert_eq!(A4::new(127, 0, 0, 1), *a);
}

pub fn test_cname_chain<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(
        Name::from_str("alias-chain.example.com.").unwrap(),
        RecordType::A,
    )
    .into();
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let mut lookup = block_on(authority.search(request_info, LookupOptions::default()))
        .unwrap()
        .unwrap();

    let additionals = lookup
        .take_additionals()
        .expect("no additionals in response");

    // for cname lookups, we have a cname returned in the answer, the catalog will perform additional lookups
    let cname = lookup
        .into_iter()
        .next()
        .expect("CNAME record not found in authority")
        .data()
        .and_then(RData::as_cname)
        .expect("Not a CNAME record");

    assert_eq!(Name::from_str("alias.example.com.").unwrap(), cname.0);

    // assert the A record is in the additionals section
    let mut additionals = additionals.into_iter();

    let cname = additionals
        .next()
        .expect("CNAME record not found")
        .data()
        .and_then(RData::as_cname)
        .expect("Not an CNAME record");
    assert_eq!(Name::from_str("www.example.com.").unwrap(), cname.0);

    let a = additionals
        .next()
        .expect("A record not found")
        .data()
        .and_then(RData::as_a)
        .expect("Not an A record");
    assert_eq!(A4::new(127, 0, 0, 1), *a);
}

/// In this the ANAME , should, return A and AAAA records in additional section
/// the answer should be the A record
pub fn test_aname<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(Name::from_str("example.com.").unwrap(), RecordType::ANAME).into();
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let mut lookup = block_on(authority.search(request_info, LookupOptions::default()))
        .unwrap()
        .unwrap();

    let additionals = lookup
        .take_additionals()
        .expect("no additionals from ANAME");

    let aname = lookup
        .into_iter()
        .next()
        .expect("ANAME record not found in authority")
        .data()
        .and_then(RData::as_aname)
        .expect("Not an ANAME record");

    assert_eq!(Name::from_str("www.example.com.").unwrap(), aname.0);

    // check that additionals contain the info
    let a = additionals
        .iter()
        .find(|r| r.record_type() == RecordType::A)
        .and_then(Record::data)
        .and_then(RData::as_a)
        .expect("A not found");
    assert_eq!(A4::new(127, 0, 0, 1), *a);

    let aaaa = additionals
        .iter()
        .find(|r| r.record_type() == RecordType::AAAA)
        .and_then(Record::data)
        .and_then(RData::as_aaaa)
        .expect("AAAA not found");
    assert_eq!(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1), *aaaa);
}

/// In this test the A record that the ANAME resolves to should be returned as the answer,
///
/// The additionals should include the ANAME.
pub fn test_aname_a_lookup<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(Name::from_str("example.com.").unwrap(), RecordType::A).into();
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let mut lookup = block_on(authority.search(request_info, LookupOptions::default()))
        .unwrap()
        .unwrap();

    let additionals = lookup.take_additionals().expect("no additionals for aname");

    // the name should match the lookup, not the A records
    let (name, a) = lookup
        .into_iter()
        .next()
        .map(|r| (r.name(), r.data()))
        .expect("No A answer");

    let a = a.and_then(RData::as_a).expect("Not an A record");
    assert_eq!(A4::new(127, 0, 0, 1), *a);
    assert_eq!(Name::from_str("example.com.").unwrap(), *name);

    // check that additionals contain the info
    let aname = additionals
        .into_iter()
        .next()
        .expect("ANAME record not found in authority")
        .data()
        .and_then(RData::as_aname)
        .expect("Not an ANAME record");

    assert_eq!(Name::from_str("www.example.com.").unwrap(), aname.0);
}

/// In this test the A record that the ANAME resolves to should be returned as the answer, not at the apex
///
/// The additionals should include the ANAME, this one should include the CNAME chain as well.
pub fn test_aname_chain<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(
        Name::from_str("aname-chain.example.com.").unwrap(),
        RecordType::A,
    )
    .into();
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let mut lookup = block_on(authority.search(request_info, LookupOptions::default()))
        .unwrap()
        .unwrap();

    let additionals = lookup.take_additionals().expect("no additionals");

    let (name, a) = lookup
        .into_iter()
        .next()
        .map(|r| (r.name(), r.data()))
        .expect("Not an A record");

    let a = a.and_then(RData::as_a).expect("Not an A record");
    assert_eq!(A4::new(127, 0, 0, 1), *a);
    assert_eq!(Name::from_str("aname-chain.example.com.").unwrap(), *name);

    // the name should match the lookup, not the A records
    let mut additionals = additionals.into_iter();

    let aname = additionals
        .next()
        .expect("ANAME record not found in authority")
        .data()
        .and_then(RData::as_aname)
        .expect("Not an ANAME record");

    assert_eq!(Name::from_str("alias.example.com.").unwrap(), aname.0);

    let cname = additionals
        .next()
        .expect("CNAME record not found")
        .data()
        .and_then(RData::as_cname)
        .expect("Not an CNAME record");
    assert_eq!(Name::from_str("www.example.com.").unwrap(), cname.0);

    let a = additionals
        .next()
        .expect("A record not found")
        .data()
        .and_then(RData::as_a)
        .expect("Not an A record");
    assert_eq!(A4::new(127, 0, 0, 1), *a);
}

pub fn test_update_errors<A: Authority<Lookup = AuthLookup>>(mut authority: A) {
    let mut message = Message::default();
    message.add_query(Query::default());
    let bytes = message.to_vec().unwrap();
    let update = MessageRequest::from_bytes(&bytes).unwrap();

    // this is expected to fail, i.e. updates are not allowed
    assert!(block_on(authority.update(&update)).is_err());
}

#[allow(clippy::uninlined_format_args)]
pub fn test_dots_in_name<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(
        Name::from_str("this.has.dots.example.com.").unwrap(),
        RecordType::A,
    )
    .into();
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let lookup = block_on(authority.search(request_info, LookupOptions::default()))
        .unwrap()
        .unwrap();

    assert_eq!(
        *lookup
            .into_iter()
            .next()
            .expect("A record not found in authority")
            .data()
            .and_then(RData::as_a)
            .expect("wrong rdata type returned"),
        A4::new(127, 0, 0, 3)
    );

    // the rest should all be NameExists
    let query = Query::query(
        Name::from_str("has.dots.example.com.").unwrap(),
        RecordType::A,
    )
    .into();
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let lookup = block_on(authority.search(request_info, LookupOptions::default())).unwrap_err();

    assert!(lookup.is_name_exists(), "lookup: {}", lookup);

    // the rest should all be NameExists
    let query = Query::query(Name::from_str("dots.example.com.").unwrap(), RecordType::A).into();
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let lookup = block_on(authority.search(request_info, LookupOptions::default())).unwrap_err();

    assert!(lookup.is_name_exists());

    // and this should be an NXDOMAIN
    let query = Query::query(
        Name::from_str("not.this.has.dots.example.com.").unwrap(),
        RecordType::A,
    )
    .into();
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let lookup = block_on(authority.search(request_info, LookupOptions::default())).unwrap_err();

    assert!(lookup.is_nx_domain());
}

pub fn test_wildcard<A: Authority<Lookup = AuthLookup>>(authority: A) {
    // check direct lookup
    let query = Query::query(
        Name::from_str("*.wildcard.example.com.").unwrap(),
        RecordType::CNAME,
    )
    .into();
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let lookup = block_on(authority.search(request_info, LookupOptions::default()))
        .unwrap()
        .unwrap();

    assert_eq!(
        lookup
            .into_iter()
            .next()
            .expect("CNAME record not found in authority")
            .data()
            .and_then(RData::as_cname)
            .expect("wrong rdata type returned")
            .0,
        Name::from_str("www.example.com.").unwrap()
    );

    // check wildcard lookup
    let query = Query::query(
        Name::from_str("www.wildcard.example.com.").unwrap(),
        RecordType::CNAME,
    )
    .into();
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let lookup = block_on(authority.search(request_info, LookupOptions::default()))
        .expect("lookup of www.wildcard.example.com. failed");

    assert_eq!(
        lookup
            .unwrap()
            .into_iter()
            .next()
            .map(|r| {
                assert_eq!(
                    *r.name(),
                    Name::from_str("www.wildcard.example.com.").unwrap()
                );
                r
            })
            .expect("CNAME record not found in authority")
            .data()
            .and_then(RData::as_cname)
            .expect("wrong rdata type returned")
            .0,
        Name::from_str("www.example.com.").unwrap()
    );
}

pub fn test_wildcard_chain<A: Authority<Lookup = AuthLookup>>(authority: A) {
    // check wildcard lookup
    let query = Query::query(
        Name::from_str("www.wildcard.example.com.").unwrap(),
        RecordType::A,
    )
    .into();
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let mut lookup = block_on(authority.search(request_info, LookupOptions::default()))
        .unwrap()
        .expect("lookup of www.wildcard.example.com. failed");

    // the name should match the lookup, not the A records
    let additionals = lookup.take_additionals().expect("no additionals");

    assert_eq!(
        lookup
            .into_iter()
            .next()
            .expect("CNAME record not found in authority")
            .data()
            .and_then(RData::as_cname)
            .expect("wrong rdata type returned")
            .0,
        Name::from_str("www.example.com.").unwrap()
    );

    let mut additionals = additionals.into_iter();
    let a = additionals
        .next()
        .expect("A record not found")
        .data()
        .and_then(RData::as_a)
        .expect("Not an A record");
    assert_eq!(A4::new(127, 0, 0, 1), *a);
}

pub fn test_srv<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(
        Name::from_str("server.example.com.").unwrap(),
        RecordType::SRV,
    )
    .into();
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let mut lookup = block_on(authority.search(request_info, LookupOptions::default()))
        .unwrap()
        .unwrap();

    let additionals = dbg!(lookup
        .take_additionals()
        .expect("no additionals in response"));

    let srv = lookup
        .into_iter()
        .next()
        .expect("SRV record not found in authority")
        .data()
        .and_then(RData::as_srv)
        .expect("Not an SRV record");

    assert_eq!(Name::from_str("alias.example.com.").unwrap(), *srv.target());

    // assert the A record is in the additionals section
    let mut additionals = additionals.into_iter();

    let cname = additionals
        .next()
        .expect("CNAME record not found")
        .data()
        .and_then(RData::as_cname)
        .expect("Not an CNAME record");
    assert_eq!(Name::from_str("www.example.com.").unwrap(), cname.0);

    let a = additionals
        .next()
        .expect("A record not found")
        .data()
        .and_then(RData::as_a)
        .expect("Not an A record");
    assert_eq!(A4::new(127, 0, 0, 1), *a);

    let aaaa = additionals
        .next()
        .expect("AAAA record not found")
        .data()
        .and_then(RData::as_aaaa)
        .expect("Not an AAAA record");
    assert_eq!(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1), *aaaa);
}

pub fn test_invalid_lookup<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(Name::from_str("www.google.com.").unwrap(), RecordType::A).into();
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let lookup = block_on(authority.search(request_info, LookupOptions::default()));

    let err = lookup.expect_err("Lookup for www.google.com succeeded");
    match err {
        LookupError::ResponseCode(code) => assert_eq!(code, ResponseCode::Refused),
        _ => panic!("invalid error enum variant"),
    }
}

// test some additional record collections

macro_rules! define_basic_test {
    ($new:ident; $( $f:ident, )*) => {
        $(
            #[test]
            fn $f () {
                // Useful for getting debug logs
                // env_logger::try_init().ok();

                let authority = crate::$new("../../tests/test-data/test_configs/example.com.zone", module_path!(), stringify!($f));
                crate::authority_battery::basic::$f(authority);
            }
        )*
    }
}

macro_rules! basic_battery {
    ($new:ident) => {
        #[cfg(test)]
        mod basic {
            mod $new {
                define_basic_test!($new;
                    test_a_lookup,
                    test_soa,
                    test_ns,
                    test_ns_lookup,
                    test_mx,
                    test_mx_to_null,
                    test_cname,
                    test_cname_alias,
                    test_cname_chain,
                    test_aname,
                    test_aname_a_lookup,
                    test_aname_chain,
                    test_update_errors,
                    test_dots_in_name,
                    test_wildcard,
                    test_wildcard_chain,
                    test_srv,
                    test_invalid_lookup,
                );
            }
        }
    };
}
