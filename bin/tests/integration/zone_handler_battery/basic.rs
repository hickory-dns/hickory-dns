#![allow(unreachable_pub)]

use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;

use futures_executor::block_on;

use hickory_net::{
    runtime::{Time, TokioTime},
    xfer::Protocol,
};
use hickory_proto::{
    op::{Header, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, RecordType,
        rdata::{A as A4, AAAA},
    },
};
use hickory_server::{
    server::Request,
    zone_handler::{LookupError, LookupOptions, MessageRequest, ZoneHandler},
};

const TEST_HEADER: &Header = &Header::new(10, MessageType::Query, OpCode::Query);

pub fn test_a_lookup(handler: impl ZoneHandler) {
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::default()))
        .0
        .unwrap();

    let a = lookup
        .into_iter()
        .next()
        .expect("no record found in zone handler");

    match a.data() {
        RData::A(a) => assert_eq!(A4::new(127, 0, 0, 1), *a),
        _ => panic!("wrong rdata type returned"),
    }
}

#[allow(clippy::unreadable_literal)]
pub fn test_soa(handler: impl ZoneHandler) {
    let lookup = block_on(handler.lookup(
        handler.origin(),
        RecordType::SOA,
        None,
        LookupOptions::default(),
    ))
    .unwrap();

    match lookup
        .into_iter()
        .next()
        .expect("SOA record not found in zone handler")
        .data()
    {
        RData::SOA(soa) => {
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

pub fn test_ns(handler: impl ZoneHandler) {
    let lookup = block_on(handler.lookup(
        handler.origin(),
        RecordType::NS,
        None,
        LookupOptions::default(),
    ))
    .unwrap();

    match lookup
        .into_iter()
        .next()
        .expect("NS record not found in zone handler")
        .data()
    {
        RData::NS(name) => assert_eq!(Name::from_str("bbb.example.com.").unwrap(), name.0),
        _ => panic!("wrong rdata type returned"),
    }
}

pub fn test_ns_lookup(handler: impl ZoneHandler) {
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(Name::from_str("example.com.").unwrap(), RecordType::NS),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::default()))
        .0
        .unwrap();

    let additionals = lookup.additionals().expect("no additionals in response");
    let ns = lookup
        .into_iter()
        .next()
        .expect("no record found in zone handler");

    match ns.data() {
        RData::NS(ns) => assert_eq!(Name::from_str("bbb.example.com.").unwrap(), ns.0),
        _ => panic!("wrong record type returned"),
    }

    let a = additionals.into_iter().next().expect("no record found (2)");
    match a.data() {
        RData::A(a) => assert_eq!(A4::new(127, 0, 0, 2), *a),
        _ => panic!("wrong rdata type returned"),
    }
}

pub fn test_mx(handler: impl ZoneHandler) {
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(Name::from_str("example.com.").unwrap(), RecordType::MX),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::default()))
        .0
        .unwrap();

    let additionals = lookup.additionals().expect("no additionals in response");
    let mx = lookup
        .into_iter()
        .next()
        .expect("no record found in zone handler");

    match mx.data() {
        RData::MX(mx) => assert_eq!(
            Name::from_str("alias.example.com.").unwrap(),
            *mx.exchange()
        ),
        _ => panic!("wrong rdata type returned"),
    }

    // assert the A record is in the additionals section
    let mut additionals = additionals.into_iter();
    let cname = additionals.next().expect("CNAME record not found");
    match cname.data() {
        RData::CNAME(cname) => assert_eq!(Name::from_str("www.example.com.").unwrap(), cname.0),
        _ => panic!("wrong rdata type returned"),
    }

    let a = additionals.next().expect("A record not found");
    match a.data() {
        RData::A(a) => assert_eq!(A4::new(127, 0, 0, 1), *a),
        _ => panic!("wrong rdata type returned"),
    }

    let aaaa = additionals.next().expect("AAAA record not found");
    match aaaa.data() {
        RData::AAAA(aaaa) => assert_eq!(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1), *aaaa),
        _ => panic!("wrong rdata type returned"),
    }
}

pub fn test_mx_to_null(handler: impl ZoneHandler) {
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(
                Name::from_str("no-service.example.com.").unwrap(),
                RecordType::MX,
            ),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::default()))
        .0
        .unwrap();

    // In this case there should be no additional records
    assert!(lookup.additionals().is_none());

    let mx = lookup
        .into_iter()
        .next()
        .expect("MX record not found in zone handler");

    match mx.data() {
        RData::MX(mx) => assert_eq!(Name::from_str(".").unwrap(), *mx.exchange()),
        _ => panic!("wrong rdata type returned"),
    }
}

pub fn test_cname(handler: impl ZoneHandler) {
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(
                Name::from_str("alias.example.com.").unwrap(),
                RecordType::CNAME,
            ),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::default()))
        .0
        .unwrap();

    let cname = lookup
        .into_iter()
        .next()
        .expect("CNAME record not found in zone handler");

    match cname.data() {
        RData::CNAME(cname) => assert_eq!(Name::from_str("www.example.com.").unwrap(), cname.0),
        _ => panic!("wrong rdata type returned"),
    }
}

pub fn test_cname_alias(handler: impl ZoneHandler) {
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(Name::from_str("alias.example.com.").unwrap(), RecordType::A),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::default()))
        .0
        .unwrap();

    let additionals = lookup.additionals().expect("no additionals in response");

    // for cname lookups, we have a cname returned in the answer, the catalog will perform additional lookups
    let cname = lookup
        .into_iter()
        .next()
        .expect("CNAME record not found in zone handler");

    match cname.data() {
        RData::CNAME(cname) => {
            assert_eq!(Name::from_str("www.example.com.").unwrap(), cname.0)
        }
        _ => panic!("wrong rdata type returned"),
    }

    // assert the A record is in the additionals section
    let a = additionals.into_iter().next().expect("A record not found");
    match a.data() {
        RData::A(a) => assert_eq!(A4::new(127, 0, 0, 1), *a),
        _ => panic!("wrong rdata type returned"),
    }
}

pub fn test_cname_chain(handler: impl ZoneHandler) {
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(
                Name::from_str("alias-chain.example.com.").unwrap(),
                RecordType::A,
            ),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::default()))
        .0
        .unwrap();

    let additionals = lookup.additionals().expect("no additionals in response");

    // for cname lookups, we have a cname returned in the answer, the catalog will perform additional lookups
    let cname = lookup
        .into_iter()
        .next()
        .expect("CNAME record not found in zone handler");

    match cname.data() {
        RData::CNAME(cname) => {
            assert_eq!(Name::from_str("alias.example.com.").unwrap(), cname.0);
        }
        _ => panic!("wrong rdata type returned"),
    }

    // assert the A record is in the additionals section
    let mut additionals = additionals.into_iter();

    let cname = additionals.next().expect("CNAME record not found");
    match cname.data() {
        RData::CNAME(cname) => {
            assert_eq!(Name::from_str("www.example.com.").unwrap(), cname.0);
        }
        _ => panic!("wrong rdata type returned"),
    }

    let a = additionals.next().expect("A record not found");
    match a.data() {
        RData::A(a) => assert_eq!(A4::new(127, 0, 0, 1), *a),
        _ => panic!("wrong rdata type returned"),
    }
}

/// In this the ANAME , should, return A and AAAA records in additional section
/// the answer should be the A record
pub fn test_aname(handler: impl ZoneHandler) {
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(Name::from_str("example.com.").unwrap(), RecordType::ANAME),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::default()))
        .0
        .unwrap();

    let aname = lookup
        .into_iter()
        .next()
        .expect("ANAME record not found in zone handler");

    match aname.data() {
        RData::ANAME(aname) => {
            assert_eq!(Name::from_str("www.example.com.").unwrap(), aname.0);
        }
        _ => panic!("wrong rdata type returned"),
    }

    // check that additionals contain the info
    let a = lookup
        .additionals()
        .expect("no additionals from ANAME")
        .find(|r| r.record_type() == RecordType::A)
        .expect("A not found");

    match a.data() {
        RData::A(a) => assert_eq!(A4::new(127, 0, 0, 1), *a),
        _ => panic!("wrong rdata type returned"),
    }

    let aaaa = lookup
        .additionals()
        .unwrap()
        .find(|r| r.record_type() == RecordType::AAAA)
        .expect("AAAA not found");

    match aaaa.data() {
        RData::AAAA(aaaa) => assert_eq!(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1), *aaaa),
        _ => panic!("wrong rdata type returned"),
    }
}

/// In this test the A record that the ANAME resolves to should be returned as the answer,
///
/// The additionals should include the ANAME.
pub fn test_aname_a_lookup(handler: impl ZoneHandler) {
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(Name::from_str("example.com.").unwrap(), RecordType::A),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::default()))
        .0
        .unwrap();

    let additionals = lookup.additionals().expect("no additionals for aname");

    // the name should match the lookup, not the A records
    let a = lookup.into_iter().next().expect("No A answer");
    assert_eq!(Name::from_str("example.com.").unwrap(), *a.name());

    match a.data() {
        RData::A(a) => assert_eq!(A4::new(127, 0, 0, 1), *a),
        _ => panic!("wrong rdata type returned"),
    }

    // check that additionals contain the info
    let aname = additionals
        .into_iter()
        .next()
        .expect("ANAME record not found in zone handler");

    match aname.data() {
        RData::ANAME(aname) => {
            assert_eq!(Name::from_str("www.example.com.").unwrap(), aname.0);
        }
        _ => panic!("wrong rdata type returned"),
    }
}

/// In this test the A record that the ANAME resolves to should be returned as the answer, not at the apex
///
/// The additionals should include the ANAME, this one should include the CNAME chain as well.
pub fn test_aname_chain(handler: impl ZoneHandler) {
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(
                Name::from_str("aname-chain.example.com.").unwrap(),
                RecordType::A,
            ),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::default()))
        .0
        .unwrap();

    let additionals = lookup.additionals().expect("no additionals");

    let a = lookup.into_iter().next().expect("Not an A record");
    assert_eq!(
        Name::from_str("aname-chain.example.com.").unwrap(),
        *a.name()
    );

    match a.data() {
        RData::A(a) => assert_eq!(A4::new(127, 0, 0, 1), *a),
        _ => panic!("wrong rdata type returned"),
    }

    // the name should match the lookup, not the A records
    let mut additionals = additionals.into_iter();
    let aname = additionals
        .next()
        .expect("ANAME record not found in zone handler");

    match aname.data() {
        RData::ANAME(aname) => {
            assert_eq!(Name::from_str("alias.example.com.").unwrap(), aname.0);
        }
        _ => panic!("wrong rdata type returned"),
    }

    let cname = additionals.next().expect("CNAME record not found");
    match cname.data() {
        RData::CNAME(cname) => {
            assert_eq!(Name::from_str("www.example.com.").unwrap(), cname.0);
        }
        _ => panic!("wrong rdata type returned"),
    }

    let a = additionals.next().expect("A record not found");
    match a.data() {
        RData::A(a) => assert_eq!(A4::new(127, 0, 0, 1), *a),
        _ => panic!("wrong rdata type returned"),
    }
}

pub fn test_update_errors(handler: impl ZoneHandler) {
    let mut message = Message::query();
    message.add_query(Query::new());
    let bytes = message.to_vec().unwrap();
    let request = Request::from_bytes(
        bytes,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    // this is expected to fail, i.e. updates are not allowed
    assert!(
        block_on(handler.update(&request, TokioTime::current_time()))
            .0
            .is_err()
    );
}

#[allow(clippy::uninlined_format_args)]
pub fn test_dots_in_name(handler: impl ZoneHandler) {
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(
                Name::from_str("this.has.dots.example.com.").unwrap(),
                RecordType::A,
            ),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::default()))
        .0
        .unwrap();

    let record = lookup
        .into_iter()
        .next()
        .expect("A record not found in zone handler");

    match record.data() {
        RData::A(a) => assert_eq!(A4::new(127, 0, 0, 3), *a),
        _ => panic!("wrong rdata type returned"),
    }

    // the rest should all be NameExists
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(
                Name::from_str("has.dots.example.com.").unwrap(),
                RecordType::A,
            ),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::default()))
        .0
        .unwrap_err();

    assert!(
        matches!(lookup, LookupError::NameExists),
        "lookup: {}",
        lookup
    );

    // the rest should all be NameExists
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(Name::from_str("dots.example.com.").unwrap(), RecordType::A),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::default()))
        .0
        .unwrap_err();

    assert!(matches!(lookup, LookupError::NameExists));

    // and this should be an NXDOMAIN
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(
                Name::from_str("not.this.has.dots.example.com.").unwrap(),
                RecordType::A,
            ),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::default()))
        .0
        .unwrap_err();

    assert!(lookup.is_nx_domain());
}

pub fn test_wildcard(handler: impl ZoneHandler) {
    // check direct lookup
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(
                Name::from_str("*.wildcard.example.com.").unwrap(),
                RecordType::CNAME,
            ),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::default()))
        .0
        .unwrap();

    let record = lookup
        .into_iter()
        .next()
        .expect("CNAME record not found in zone handler");

    match record.data() {
        RData::CNAME(cname) => {
            assert_eq!(Name::from_str("www.example.com.").unwrap(), cname.0);
        }
        _ => panic!("wrong rdata type returned"),
    }

    // check wildcard lookup
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(
                Name::from_str("www.wildcard.example.com.").unwrap(),
                RecordType::CNAME,
            ),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::default()))
        .0
        .expect("lookup of www.wildcard.example.com. failed");

    let record = lookup
        .into_iter()
        .next()
        .inspect(|r| {
            assert_eq!(
                *r.name(),
                Name::from_str("www.wildcard.example.com.").unwrap()
            );
        })
        .expect("CNAME record not found in zone handler");

    match record.data() {
        RData::CNAME(cname) => {
            assert_eq!(Name::from_str("www.example.com.").unwrap(), cname.0);
        }
        _ => panic!("wrong rdata type returned"),
    }
}

pub fn test_wildcard_subdomain(handler: impl ZoneHandler) {
    // check wildcard lookup
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(
                Name::from_str("subdomain.www.wildcard.example.com.").unwrap(),
                RecordType::CNAME,
            ),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::default()))
        .0
        .expect("lookup of subdomain.www.wildcard.example.com. failed");

    let record = lookup
        .into_iter()
        .next()
        .inspect(|r| {
            assert_eq!(
                *r.name(),
                Name::from_str("subdomain.www.wildcard.example.com.").unwrap()
            );
        })
        .expect("CNAME record not found in zone handler");

    match record.data() {
        RData::CNAME(cname) => {
            assert_eq!(Name::from_str("www.example.com.").unwrap(), cname.0);
        }
        _ => panic!("wrong rdata type returned"),
    }
}

pub fn test_wildcard_chain(handler: impl ZoneHandler) {
    // check wildcard lookup
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(
                Name::from_str("www.wildcard.example.com.").unwrap(),
                RecordType::A,
            ),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::default()))
        .0
        .expect("lookup of www.wildcard.example.com. failed");

    // the name should match the lookup, not the A records
    let additionals = lookup.additionals().expect("no additionals");

    let record = lookup
        .into_iter()
        .next()
        .expect("CNAME record not found in zone handler");

    match record.data() {
        RData::CNAME(cname) => {
            assert_eq!(Name::from_str("www.example.com.").unwrap(), cname.0);
        }
        _ => panic!("wrong rdata type returned"),
    }

    let mut additionals = additionals.into_iter();
    let a = additionals.next().expect("A record not found");
    match a.data() {
        RData::A(a) => assert_eq!(A4::new(127, 0, 0, 1), *a),
        _ => panic!("wrong rdata type returned"),
    }
}

pub fn test_srv(handler: impl ZoneHandler) {
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(
                Name::from_str("server.example.com.").unwrap(),
                RecordType::SRV,
            ),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::default()))
        .0
        .unwrap();

    let additionals = lookup.additionals().expect("no additionals in response");

    let srv = lookup
        .into_iter()
        .next()
        .expect("SRV record not found in zone handler");

    match srv.data() {
        RData::SRV(srv) => assert_eq!(Name::from_str("alias.example.com.").unwrap(), *srv.target()),
        _ => panic!("wrong rdata type returned"),
    }

    // assert the A record is in the additionals section
    let mut additionals = additionals.into_iter();
    let cname = additionals.next().expect("CNAME record not found");
    match cname.data() {
        RData::CNAME(cname) => {
            assert_eq!(Name::from_str("www.example.com.").unwrap(), cname.0);
        }
        _ => panic!("wrong rdata type returned"),
    }

    let a = additionals.next().expect("A record not found");
    match a.data() {
        RData::A(a) => {
            assert_eq!(A4::new(127, 0, 0, 1), *a);
        }
        _ => panic!("wrong rdata type returned"),
    }

    let aaaa = additionals.next().expect("AAAA record not found");
    match aaaa.data() {
        RData::AAAA(aaaa) => {
            assert_eq!(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1), *aaaa);
        }
        _ => panic!("wrong rdata type returned"),
    }
}

pub fn test_invalid_lookup(handler: impl ZoneHandler) {
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(Name::from_str("www.google.com.").unwrap(), RecordType::A),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::default()));

    let err = lookup.0.expect_err("Lookup for www.google.com succeeded");
    match err {
        LookupError::ResponseCode(code) => assert_eq!(code, ResponseCode::Refused),
        _ => panic!("invalid error enum variant"),
    }
}

// test some additional record collections

macro_rules! define_basic_test {
    ($new:expr; $( $f:ident, )*) => {
        $(
            #[test]
            fn $f () {
                subscribe();
                use std::path::Path;
                let handler = $new(&Path::new("../tests/test-data/test_configs/example.com.zone"), module_path!(), stringify!($f));
                crate::zone_handler_battery::basic::$f(handler);
            }
        )*
    }
}

macro_rules! basic_battery {
    ($name:ident, $new:expr) => {
        #[cfg(test)]
        mod basic {
            mod $name {
                use test_support::subscribe;

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
                    test_wildcard_subdomain,
                    test_wildcard_chain,
                    test_srv,
                    test_invalid_lookup,
                );
            }
        }
    };
}
