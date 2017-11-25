// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! An LRU cache designed for work with DNS lookups

use std::sync::Arc;
use std::time::{Duration, Instant};

use trust_dns_proto::op::Query;
use trust_dns_proto::rr::RData;

use error::*;
use lookup::Lookup;
use lru_cache::LruCache;

/// Maximum TTL as defined in https://tools.ietf.org/html/rfc2181
const MAX_TTL: u32 = 2147483647_u32;

#[derive(Debug)]
struct LruValue {
    // In the None case, this represents an NXDomain
    lookup: Option<Lookup>,
    ttl_until: Instant,
}

impl LruValue {
    /// Returns true if this set of ips is still valid
    fn is_current(&self, now: Instant) -> bool {
        now <= self.ttl_until
    }
}

#[derive(Debug)]
pub(crate) struct DnsLru(LruCache<Query, LruValue>);

impl DnsLru {
    pub(crate) fn new(capacity: usize) -> Self {
        DnsLru(LruCache::new(capacity))
    }

    pub(crate) fn insert(
        &mut self,
        query: Query,
        rdatas_and_ttl: Vec<(RData, u32)>,
        now: Instant,
    ) -> Lookup {
        let len = rdatas_and_ttl.len();
        // collapse the values, we're going to take the Minimum TTL as the correct one
        let (rdatas, ttl): (Vec<RData>, u32) =
            rdatas_and_ttl.into_iter().fold(
                (Vec::with_capacity(len), MAX_TTL),
                |(mut rdatas, mut min_ttl),
                 (rdata, ttl)| {
                    rdatas.push(rdata);
                    min_ttl = if ttl < min_ttl { ttl } else { min_ttl };
                    (rdatas, min_ttl)
                },
            );

        let ttl = Duration::from_secs(ttl as u64);
        let ttl_until = now + ttl;

        // insert into the LRU
        let lookup = Lookup::new(Arc::new(rdatas));
        self.0.insert(
            query,
            LruValue {
                lookup: Some(lookup.clone()),
                ttl_until,
            },
        );

        lookup
    }

    /// Generally for inserting a set of records that have already been cached, but with a different Query.
    pub(crate) fn duplicate(
        &mut self,
        query: Query,
        lookup: Lookup,
        ttl: u32,
        now: Instant,
    ) -> Lookup {
        let ttl = Duration::from_secs(ttl as u64);
        let ttl_until = now + ttl;

        self.0.insert(
            query,
            LruValue {
                lookup: Some(lookup.clone()),
                ttl_until,
            },
        );

        lookup
    }

    pub(crate) fn nx_error(query: Query) -> ResolveError {
        ResolveErrorKind::NoRecordsFound(query).into()
    }

    pub(crate) fn negative(&mut self, query: Query, ttl: u32, now: Instant) -> ResolveError {
        // TODO: if we are getting a negative response, should we instead fallback to cache?
        //   this would cache indefinitely, probably not correct

        let ttl = Duration::from_secs(ttl as u64);
        let ttl_until = now + ttl;

        self.0.insert(
            query.clone(),
            LruValue {
                lookup: None,
                ttl_until,
            },
        );

        Self::nx_error(query)
    }

    /// This needs to be mut b/c it's an LRU, meaning the ordering of elements will potentially change on retrieval...
    pub(crate) fn get(&mut self, query: &Query, now: Instant) -> Option<Lookup> {
        let mut out_of_date = false;
        let lookup = self.0.get_mut(query).and_then(
            |value| if value.is_current(now) {
                out_of_date = false;
                value.lookup.clone()
            } else {
                out_of_date = true;
                None
            },
        );

        // in this case, we can preemtively remove out of data elements
        // this assumes time is always moving forward, this would only not be true in contrived situations where now
        //  is not current time, like tests...
        if out_of_date {
            self.0.remove(query);
        }

        lookup
    }
}

#[cfg(test)]
mod tests {
    use std::net::*;
    use std::str::FromStr;
    use std::time::*;

    use trust_dns_proto::op::Query;
    use trust_dns_proto::rr::{Name, RecordType};

    use super::*;
    use lookup_ip::tests::*;

    #[test]
    fn test_is_current() {
        let now = Instant::now();
        let not_the_future = now + Duration::from_secs(4);
        let future = now + Duration::from_secs(5);
        let past_the_future = now + Duration::from_secs(6);

        let value = LruValue {
            lookup: None,
            ttl_until: future,
        };

        assert!(value.is_current(now));
        assert!(value.is_current(not_the_future));
        assert!(value.is_current(future));
        assert!(!value.is_current(past_the_future));
    }

    #[test]
    fn test_insert() {
        let now = Instant::now();
        let name = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        let ips_ttl = vec![(RData::A(Ipv4Addr::new(127, 0, 0, 1)), 1)];
        let ips = vec![RData::A(Ipv4Addr::new(127, 0, 0, 1))];
        let mut lru = DnsLru::new(1);

        let rc_ips = lru.insert(name.clone(), ips_ttl, now);
        assert_eq!(*rc_ips.iter().next().unwrap(), ips[0]);

        let rc_ips = lru.get(&name, now).unwrap();
        assert_eq!(*rc_ips.iter().next().unwrap(), ips[0]);
    }

    #[test]
    fn test_insert_ttl() {
        let now = Instant::now();
        let name = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        // TTL should be 1
        let ips_ttl = vec![
            (RData::A(Ipv4Addr::new(127, 0, 0, 1)), 1),
            (RData::A(Ipv4Addr::new(127, 0, 0, 2)), 2),
        ];
        let ips = vec![
            RData::A(Ipv4Addr::new(127, 0, 0, 1)),
            RData::A(Ipv4Addr::new(127, 0, 0, 2)),
        ];
        let mut lru = DnsLru::new(1);

        lru.insert(name.clone(), ips_ttl, now);

        // still valid
        let rc_ips = lru.get(&name, now + Duration::from_secs(1)).unwrap();
        assert_eq!(*rc_ips.iter().next().unwrap(), ips[0]);

        // 2 should be one too far
        let rc_ips = lru.get(&name, now + Duration::from_secs(2));
        assert!(rc_ips.is_none());
    }
}