use std::net::Ipv4Addr;
use std::str::FromStr;

use trust_dns::op::{Message, Query};
use trust_dns::rr::dnssec::SupportedAlgorithms;
use trust_dns::rr::{Name, RData, RecordType};
use trust_dns_server::authority::{Authority, MessageRequest};

pub fn test_a_lookup<A: Authority>(authority: A) {
    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let lookup = authority.search(&query.into(), false, SupportedAlgorithms::new());

    match lookup
        .into_iter()
        .next()
        .expect("A record not found in authity")
        .rdata()
    {
        RData::A(ip) => assert_eq!(Ipv4Addr::new(127, 0, 0, 1), *ip),
        _ => panic!("wrong rdata type returned"),
    }
}

pub fn test_soa<A: Authority>(authority: A) {
    let lookup = authority.soa();

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

pub fn test_ns<A: Authority>(authority: A) {
    let lookup = authority.ns(false, SupportedAlgorithms::new());

    match lookup
        .into_iter()
        .next()
        .expect("NS record not found in authity")
        .rdata()
    {
        RData::NS(name) => assert_eq!(Name::from_str("trust-dns.org.").unwrap(), *name),
        _ => panic!("wrong rdata type returned"),
    }
}

pub fn test_update_errors<A: Authority>(mut authority: A) {
    use trust_dns::serialize::binary::BinDecodable;

    let message = Message::default();
    let bytes = message.to_vec().unwrap();
    let update = MessageRequest::from_bytes(&bytes).unwrap();

    // this is expected to fail, i.e. updates are not allowed
    assert!(authority.update(&update).is_err());
}

macro_rules! define_basic_test {
    ($new:ident; $( $f:ident, )*) => {
        $(
            #[test]
            fn $f () {
                let authority = ::$new("tests/named_test_configs/example.com.zone", module_path!(), stringify!($f));
                ::authority_battery::basic::$f(authority);
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
                    test_update_errors,
                );
            }
        }
    };
}
