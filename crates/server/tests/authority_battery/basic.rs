use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use futures::executor::block_on;
use futures::future::Future;

use trust_dns_client::op::{Message, Query};
use trust_dns_client::rr::dnssec::SupportedAlgorithms;
use trust_dns_client::rr::{Name, RData, Record, RecordType};
use trust_dns_server::authority::{AuthLookup, Authority, MessageRequest};

pub fn test_a_lookup<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let lookup =
        block_on(authority.search(&query.into(), false, SupportedAlgorithms::new())).unwrap();

    match lookup
        .into_iter()
        .next()
        .expect("A record not found in authority")
        .rdata()
    {
        RData::A(ip) => assert_eq!(Ipv4Addr::new(127, 0, 0, 1), *ip),
        _ => panic!("wrong rdata type returned"),
    }
}

#[allow(clippy::unreadable_literal)]
pub fn test_soa<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let lookup = block_on(authority.soa()).unwrap();

    match lookup
        .into_iter()
        .next()
        .expect("SOA record not found in authity")
        .rdata()
    {
        RData::SOA(soa) => {
            assert_eq!(Name::from_str("trust-dns.org.").unwrap(), *soa.mname());
            assert_eq!(Name::from_str("root.trust-dns.org.").unwrap(), *soa.rname());
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
    let lookup = block_on(authority.ns(false, SupportedAlgorithms::new())).unwrap();

    match lookup
        .into_iter()
        .next()
        .expect("NS record not found in authity")
        .rdata()
    {
        RData::NS(name) => assert_eq!(Name::from_str("bbb.example.com.").unwrap(), *name),
        _ => panic!("wrong rdata type returned"),
    }
}

pub fn test_ns_lookup<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(Name::from_str("example.com.").unwrap(), RecordType::NS);

    let mut lookup =
        block_on(authority.search(&query.into(), false, SupportedAlgorithms::new())).unwrap();

    let additionals = dbg!(lookup
        .take_additionals()
        .expect("no additionals in response"));

    let ns = lookup
        .into_iter()
        .next()
        .expect("NS record not found in authority")
        .rdata()
        .as_ns()
        .expect("Not an NS record");

    assert_eq!(Name::from_str("bbb.example.com.").unwrap(), *ns);

    let a = additionals
        .into_iter()
        .next()
        .expect("A record not found")
        .rdata()
        .as_a()
        .expect("Not an A record");
    assert_eq!(Ipv4Addr::new(127, 0, 0, 2), *a);
}

pub fn test_mx<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(Name::from_str("example.com.").unwrap(), RecordType::MX);

    let mut lookup =
        block_on(authority.search(&query.into(), false, SupportedAlgorithms::new())).unwrap();

    let additionals = dbg!(lookup
        .take_additionals()
        .expect("no additionals in response"));

    let mx = lookup
        .into_iter()
        .next()
        .expect("MX record not found in authority")
        .rdata()
        .as_mx()
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
        .rdata()
        .as_cname()
        .expect("Not an CNAME record");
    assert_eq!(Name::from_str("www.example.com.").unwrap(), *cname);

    let a = additionals
        .next()
        .expect("A record not found")
        .rdata()
        .as_a()
        .expect("Not an A record");
    assert_eq!(Ipv4Addr::new(127, 0, 0, 1), *a);

    let aaaa = additionals
        .next()
        .expect("AAAA record not found")
        .rdata()
        .as_aaaa()
        .expect("Not an AAAA record");
    assert_eq!(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), *aaaa);
}

pub fn test_cname<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(
        Name::from_str("alias.example.com.").unwrap(),
        RecordType::CNAME,
    );

    let lookup =
        block_on(authority.search(&query.into(), false, SupportedAlgorithms::new())).unwrap();

    let cname = lookup
        .into_iter()
        .next()
        .expect("CNAME record not found in authority")
        .rdata()
        .as_cname()
        .expect("Not an A record");

    assert_eq!(Name::from_str("www.example.com.").unwrap(), *cname);
}

pub fn test_cname_alias<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(Name::from_str("alias.example.com.").unwrap(), RecordType::A);

    let mut lookup =
        block_on(authority.search(&query.into(), false, SupportedAlgorithms::new())).unwrap();

    let additionals = lookup
        .take_additionals()
        .expect("no additionals in response");

    // for cname lookups, we have a cname returned in the answer, the catalog will perform additional lookups
    let cname = lookup
        .into_iter()
        .next()
        .expect("CNAME record not found in authority")
        .rdata()
        .as_cname()
        .expect("Not a CNAME record");

    assert_eq!(Name::from_str("www.example.com.").unwrap(), *cname);

    // assert the A record is in the additionals section
    let a = additionals
        .into_iter()
        .next()
        .expect("A record not found")
        .rdata()
        .as_a()
        .expect("Not an A record");
    assert_eq!(Ipv4Addr::new(127, 0, 0, 1), *a);
}

pub fn test_cname_chain<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(
        Name::from_str("alias-chain.example.com.").unwrap(),
        RecordType::A,
    );

    let mut lookup =
        block_on(authority.search(&query.into(), false, SupportedAlgorithms::new())).unwrap();

    let additionals = lookup
        .take_additionals()
        .expect("no additionals in response");

    // for cname lookups, we have a cname returned in the answer, the catalog will perform additional lookups
    let cname = lookup
        .into_iter()
        .next()
        .expect("CNAME record not found in authority")
        .rdata()
        .as_cname()
        .expect("Not a CNAME record");

    assert_eq!(Name::from_str("alias.example.com.").unwrap(), *cname);

    // assert the A record is in the additionals section
    let mut additionals = additionals.into_iter();

    let cname = additionals
        .next()
        .expect("CNAME record not found")
        .rdata()
        .as_cname()
        .expect("Not an CNAME record");
    assert_eq!(Name::from_str("www.example.com.").unwrap(), *cname);

    let a = additionals
        .next()
        .expect("A record not found")
        .rdata()
        .as_a()
        .expect("Not an A record");
    assert_eq!(Ipv4Addr::new(127, 0, 0, 1), *a);
}

/// In this the ANAME , should, return A and AAAA records in additional section
/// the answer should be the A record
pub fn test_aname<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(Name::from_str("example.com.").unwrap(), RecordType::ANAME);

    let mut lookup =
        block_on(authority.search(&query.into(), false, SupportedAlgorithms::new())).unwrap();

    let additionals = lookup
        .take_additionals()
        .expect("no additionals from ANAME");

    let aname = lookup
        .into_iter()
        .next()
        .expect("ANAME record not found in authority")
        .rdata()
        .as_aname()
        .expect("Not an ANAME record");

    assert_eq!(Name::from_str("www.example.com.").unwrap(), *aname);

    // check that additionals contain the info
    let a = additionals
        .iter()
        .find(|r| r.record_type() == RecordType::A)
        .map(Record::rdata)
        .and_then(RData::as_a)
        .expect("A not found");
    assert_eq!(Ipv4Addr::new(127, 0, 0, 1), *a);

    let aaaa = additionals
        .iter()
        .find(|r| r.record_type() == RecordType::AAAA)
        .map(Record::rdata)
        .and_then(RData::as_aaaa)
        .expect("AAAA not found");
    assert_eq!(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), *aaaa);
}

/// In this test the A record that the ANAME resolves to should be returned as the answer,
///
/// The additionals should include the ANAME.
pub fn test_aname_a_lookup<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(Name::from_str("example.com.").unwrap(), RecordType::A);

    let mut lookup =
        block_on(authority.search(&query.into(), false, SupportedAlgorithms::new())).unwrap();

    let additionals = lookup.take_additionals().expect("no additionals for aname");

    // the name should match the lookup, not the A records
    let (name, a) = lookup
        .into_iter()
        .next()
        .map(|r| (r.name(), dbg!(r.rdata())))
        .expect("No A answer");

    let a = a.as_a().expect("Not an A record");
    assert_eq!(Ipv4Addr::new(127, 0, 0, 1), *a);
    assert_eq!(Name::from_str("example.com.").unwrap(), *name);

    // check that additionals contain the info
    let aname = additionals
        .into_iter()
        .next()
        .expect("ANAME record not found in authority")
        .rdata()
        .as_aname()
        .expect("Not an ANAME record");

    assert_eq!(Name::from_str("www.example.com.").unwrap(), *aname);
}

/// In this test the A record that the ANAME resolves to should be returned as the answer, not at the apex
///
/// The additionals should include the ANAME, this one should include the CNAME chain as well.
pub fn test_aname_chain<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(
        Name::from_str("aname-chain.example.com.").unwrap(),
        RecordType::A,
    );

    let mut lookup =
        block_on(authority.search(&query.into(), false, SupportedAlgorithms::new())).unwrap();

    let additionals = lookup.take_additionals().expect("no additionals");

    let (name, a) = lookup
        .into_iter()
        .next()
        .map(|r| (r.name(), r.rdata()))
        .expect("Not an A record");

    let a = a.as_a().expect("Not an A record");
    assert_eq!(Ipv4Addr::new(127, 0, 0, 1), *a);
    assert_eq!(Name::from_str("aname-chain.example.com.").unwrap(), *name);

    // the name should match the lookup, not the A records
    let mut additionals = additionals.into_iter();

    let aname = additionals
        .next()
        .expect("ANAME record not found in authority")
        .rdata()
        .as_aname()
        .expect("Not an ANAME record");

    assert_eq!(Name::from_str("alias.example.com.").unwrap(), *aname);

    let cname = additionals
        .next()
        .expect("CNAME record not found")
        .rdata()
        .as_cname()
        .expect("Not an CNAME record");
    assert_eq!(Name::from_str("www.example.com.").unwrap(), *cname);

    let a = additionals
        .next()
        .expect("A record not found")
        .rdata()
        .as_a()
        .expect("Not an A record");
    assert_eq!(Ipv4Addr::new(127, 0, 0, 1), *a);
}

pub fn test_update_errors<A: Authority<Lookup = AuthLookup>>(mut authority: A) {
    use trust_dns_client::serialize::binary::BinDecodable;

    let message = Message::default();
    let bytes = message.to_vec().unwrap();
    let update = MessageRequest::from_bytes(&bytes).unwrap();

    // this is expected to fail, i.e. updates are not allowed
    assert!(authority.update(&update).is_err());
}

pub fn test_dots_in_name<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(
        Name::from_str("this.has.dots.example.com.").unwrap(),
        RecordType::A,
    );
    let lookup =
        block_on(authority.search(&query.into(), false, SupportedAlgorithms::new())).unwrap();

    assert_eq!(
        *lookup
            .into_iter()
            .next()
            .expect("A record not found in authity")
            .rdata()
            .as_a()
            .expect("wrong rdata type returned"),
        Ipv4Addr::new(127, 0, 0, 3)
    );

    // the rest should all be NameExists
    let query = Query::query(
        Name::from_str("has.dots.example.com.").unwrap(),
        RecordType::A,
    );
    let lookup =
        block_on(authority.search(&query.into(), false, SupportedAlgorithms::new())).unwrap_err();

    assert!(lookup.is_name_exists(), "lookup: {}", lookup);

    // the rest should all be NameExists
    let query = Query::query(Name::from_str("dots.example.com.").unwrap(), RecordType::A);
    let lookup =
        block_on(authority.search(&query.into(), false, SupportedAlgorithms::new())).unwrap_err();

    assert!(lookup.is_name_exists());

    // and this should be an NXDOMAIN
    let query = Query::query(
        Name::from_str("not.this.has.dots.example.com.").unwrap(),
        RecordType::A,
    );
    let lookup =
        block_on(authority.search(&query.into(), false, SupportedAlgorithms::new())).unwrap_err();

    assert!(lookup.is_nx_domain());
}

pub fn test_wildcard<A: Authority<Lookup = AuthLookup>>(authority: A) {
    // check direct lookup
    let query = Query::query(
        Name::from_str("*.wildcard.example.com.").unwrap(),
        RecordType::CNAME,
    );
    let lookup =
        block_on(authority.search(&query.into(), false, SupportedAlgorithms::new())).unwrap();

    assert_eq!(
        *lookup
            .into_iter()
            .next()
            .expect("CNAME record not found in authority")
            .rdata()
            .as_cname()
            .expect("wrong rdata type returned"),
        Name::from_str("www.example.com.").unwrap()
    );

    // check wildcard lookup
    let query = Query::query(
        Name::from_str("www.wildcard.example.com.").unwrap(),
        RecordType::CNAME,
    );
    let lookup = block_on(authority.search(&query.into(), false, SupportedAlgorithms::new()))
        .expect("lookup of www.wildcard.example.com. failed");

    assert_eq!(
        *lookup
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
            .rdata()
            .as_cname()
            .expect("wrong rdata type returned"),
        Name::from_str("www.example.com.").unwrap()
    );
}

pub fn test_wildcard_chain<A: Authority<Lookup = AuthLookup>>(authority: A) {
    // check wildcard lookup
    let query = Query::query(
        Name::from_str("www.wildcard.example.com.").unwrap(),
        RecordType::A,
    );
    let mut lookup = block_on(authority.search(&query.into(), false, SupportedAlgorithms::new()))
        .expect("lookup of www.wildcard.example.com. failed");

    // the name should match the lookup, not the A records
    let additionals = lookup.take_additionals().expect("no additionals");

    assert_eq!(
        *lookup
            .into_iter()
            .next()
            .expect("CNAME record not found in authority")
            .rdata()
            .as_cname()
            .expect("wrong rdata type returned"),
        Name::from_str("www.example.com.").unwrap()
    );

    let mut additionals = additionals.into_iter();
    let a = additionals
        .next()
        .expect("A record not found")
        .rdata()
        .as_a()
        .expect("Not an A record");
    assert_eq!(Ipv4Addr::new(127, 0, 0, 1), *a);
}

pub fn test_srv<A: Authority<Lookup = AuthLookup>>(authority: A) {
    let query = Query::query(
        Name::from_str("server.example.com.").unwrap(),
        RecordType::SRV,
    );

    let mut lookup =
        block_on(authority.search(&query.into(), false, SupportedAlgorithms::new())).unwrap();

    let additionals = dbg!(lookup
        .take_additionals()
        .expect("no additionals in response"));

    let srv = lookup
        .into_iter()
        .next()
        .expect("SRV record not found in authority")
        .rdata()
        .as_srv()
        .expect("Not an SRV record");

    assert_eq!(Name::from_str("alias.example.com.").unwrap(), *srv.target());

    // assert the A record is in the additionals section
    let mut additionals = additionals.into_iter();

    let cname = additionals
        .next()
        .expect("CNAME record not found")
        .rdata()
        .as_cname()
        .expect("Not an CNAME record");
    assert_eq!(Name::from_str("www.example.com.").unwrap(), *cname);

    let a = additionals
        .next()
        .expect("A record not found")
        .rdata()
        .as_a()
        .expect("Not an A record");
    assert_eq!(Ipv4Addr::new(127, 0, 0, 1), *a);

    let aaaa = additionals
        .next()
        .expect("AAAA record not found")
        .rdata()
        .as_aaaa()
        .expect("Not an AAAA record");
    assert_eq!(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), *aaaa);
}

// test some additional record collections

macro_rules! define_basic_test {
    ($new:ident; $( $f:ident, )*) => {
        $(
            #[test]
            fn $f () {
                let authority = crate::$new("../../tests/test-data/named_test_configs/example.com.zone", module_path!(), stringify!($f));
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
                );
            }
        }
    };
}
