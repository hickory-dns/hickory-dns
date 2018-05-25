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
pub const MAX_TTL: u32 = 2147483647_u32;

#[derive(Debug)]
struct LruValue {
    // In the None case, this represents an NXDomain
    lookup: Option<Lookup>,
    valid_until: Instant,
}

impl LruValue {
    /// Returns true if this set of ips is still valid
    fn is_current(&self, now: Instant) -> bool {
        now <= self.valid_until
    }
}

#[derive(Debug)]
pub(crate) struct DnsLru {
    cache: LruCache<Query, LruValue>,
    /// A minimum TTL value for positive responses.
    ///
    /// Positive responses with TTLs under `positive_max_ttl` will use
    /// `positive_max_ttl` instead.
    ///
    /// If this value is not set on the `TtlConfig` used to construct this
    /// `DnsLru`, it will default to 0.
    positive_min_ttl: Duration,
    /// A minimum TTL value for negative (`NXDOMAIN`) responses.
    ///
    /// `NXDOMAIN` responses with TTLs under `negative_min_ttl` will use
    /// `negative_min_ttl` instead.
    ///
    /// If this value is not set on the `TtlConfig` used to construct this
    /// `DnsLru`, it will default to 0.
    negative_min_ttl: Duration,
    /// A maximum TTL value for positive responses.
    ///
    /// Positive responses with TTLs over `positive_max_ttl` will use
    /// `positive_max_ttl` instead.
    ///
    ///  If this value is not set on the `TtlConfig` used to construct this
    /// `DnsLru`, it will default to [`MAX_TTL`] seconds.
    ///
    /// [`MAX_TTL`]: const.MAX_TTL.html
    positive_max_ttl: Duration,
    /// A maximum TTL value for negative (`NXDOMAIN`) responses.
    ///
    /// `NXDOMAIN` responses with TTLs over `negative_max_ttl` will use
    /// `negative_max_ttl` instead.
    ///
    ///  If this value is not set on the `TtlConfig` used to construct this
    /// `DnsLru`, it will default to [`MAX_TTL`] seconds.
    ///
    /// [`MAX_TTL`]: const.MAX_TTL.html
    negative_max_ttl: Duration,

}

#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct TtlConfig {
    /// An optional minimum TTL value for positive responses.
    ///
    /// Positive responses with TTLs under `positive_min_ttl` will use
    /// `positive_min_ttl` instead.
    pub positive_min_ttl: Option<Duration>,
    /// An optional minimum TTL value for negative (`NXDOMAIN`) responses.
    ///
    /// `NXDOMAIN` responses with TTLs under `negative_min_ttl will use
    /// `negative_min_ttl` instead.
    pub negative_min_ttl: Option<Duration>,
    /// An optional maximum TTL value for positive responses.
    ///
    /// Positive responses with TTLs positive `positive_max_ttl` will use
    /// `positive_max_ttl` instead.
    pub positive_max_ttl: Option<Duration>,
    /// An optional maximum TTL value for negative (`NXDOMAIN`) responses.
    ///
    /// `NXDOMAIN` responses with TTLs over `negative_max_ttl` will use
    /// `negative_max_ttl` instead.
    pub negative_max_ttl: Option<Duration>,
}

impl DnsLru {
    pub(crate) fn new(capacity: usize, ttl_cfg: TtlConfig) -> Self {
        let TtlConfig {
            positive_min_ttl,
            negative_min_ttl,
            positive_max_ttl,
            negative_max_ttl,
        } = ttl_cfg;
        let cache = LruCache::new(capacity);
        Self {
            cache,
            positive_min_ttl: positive_min_ttl.unwrap_or_else(|| Duration::from_secs(0)),
            negative_min_ttl: negative_min_ttl.unwrap_or_else(|| Duration::from_secs(0)),
            positive_max_ttl: positive_max_ttl
                .unwrap_or_else(|| Duration::from_secs(MAX_TTL as u64)),
            negative_max_ttl: negative_max_ttl
                .unwrap_or_else(|| Duration::from_secs(MAX_TTL as u64)),
        }
    }

    pub(crate) fn insert(
        &mut self,
        query: Query,
        rdatas_and_ttl: Vec<(RData, u32)>,
        now: Instant,
    ) -> Lookup {
        let len = rdatas_and_ttl.len();
        // collapse the values, we're going to take the Minimum TTL as the correct one
        let (rdatas, ttl): (Vec<RData>, u32) = rdatas_and_ttl.into_iter().fold(
            (Vec::with_capacity(len), MAX_TTL),
            |(mut rdatas, mut min_ttl), (rdata, ttl)| {
                rdatas.push(rdata);
                min_ttl = min_ttl.min(ttl);
                (rdatas, min_ttl)
            },
        );

        let ttl = Duration::from_secs(ttl as u64);
        // If the cache was configured with a minimum TTL, and that value is higher
        // than the minimum TTL in the values, use it instead.
        let ttl = self.positive_min_ttl.max(ttl);
        let valid_until = now + ttl;

        // insert into the LRU
        let lookup = Lookup::new_with_deadline(Arc::new(rdatas), valid_until);
        self.cache.insert(
            query,
            LruValue {
                lookup: Some(lookup.clone()),
                valid_until,
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
        let valid_until = now + ttl;

        self.cache.insert(
            query,
            LruValue {
                lookup: Some(lookup.clone()),
                valid_until,
            },
        );

        lookup
    }

    pub(crate) fn nx_error(query: Query, valid_until: Option<Instant>) -> ResolveError {
        ResolveErrorKind::NoRecordsFound { query, valid_until }.into()
    }

    pub(crate) fn negative(&mut self, query: Query, ttl: u32, now: Instant) -> ResolveError {
        // TODO: if we are getting a negative response, should we instead fallback to cache?
        //   this would cache indefinitely, probably not correct

        let ttl = Duration::from_secs(ttl as u64);
        // If the cache was configured with a min TTL for negative responses,
        // and that TTL is higher than the response's TTL, use it instead.
        let ttl = self.negative_min_ttl.max(ttl);
        let valid_until = now + ttl;

        self.cache.insert(
            query.clone(),
            LruValue {
                lookup: None,
                valid_until,
            },
        );

        Self::nx_error(query, Some(valid_until))
    }

    /// This needs to be mut b/c it's an LRU, meaning the ordering of elements will potentially change on retrieval...
    pub(crate) fn get(&mut self, query: &Query, now: Instant) -> Option<Lookup> {
        let mut out_of_date = false;
        let lookup = self.cache.get_mut(query).and_then(|value| {
            if value.is_current(now) {
                out_of_date = false;
                value.lookup.clone()
            } else {
                out_of_date = true;
                None
            }
        });

        // in this case, we can preemtively remove out of data elements
        // this assumes time is always moving forward, this would only not be true in contrived situations where now
        //  is not current time, like tests...
        if out_of_date {
            self.cache.remove(query);
        }

        lookup
    }
}

// see also the lookup_tests.rs in integration-tests crate
#[cfg(test)]
mod tests {
    use std::net::*;
    use std::str::FromStr;
    use std::time::*;

    use trust_dns_proto::op::Query;
    use trust_dns_proto::rr::{Name, RecordType};

    use super::*;

    #[test]
    fn test_is_current() {
        let now = Instant::now();
        let not_the_future = now + Duration::from_secs(4);
        let future = now + Duration::from_secs(5);
        let past_the_future = now + Duration::from_secs(6);

        let value = LruValue {
            lookup: None,
            valid_until: future,
        };

        assert!(value.is_current(now));
        assert!(value.is_current(not_the_future));
        assert!(value.is_current(future));
        assert!(!value.is_current(past_the_future));
    }

    #[test]
    fn test_lookup_uses_positive_min_ttl() {
        let now = Instant::now();

        let name = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        // record should have TTL of 1 second.
        let ips_ttl = vec![(RData::A(Ipv4Addr::new(127, 0, 0, 1)), 1)];
        let ips = vec![RData::A(Ipv4Addr::new(127, 0, 0, 1))];

        // configure the cache with a minimum TTL of 2 seconds.
        let ttls = TtlConfig {
            positive_min_ttl: Some(Duration::from_secs(2)),
            ..Default::default()
        };
        let mut lru = DnsLru::new(1, ttls);

        let rc_ips = lru.insert(name.clone(), ips_ttl, now);
        assert_eq!(*rc_ips.iter().next().unwrap(), ips[0]);
        // the returned lookup should use the cache's min TTL, since the
        // query's TTL was below the minimum.
        assert_eq!(rc_ips.valid_until(), now + Duration::from_secs(2));

        // record should have TTL of 3 seconds.
        let ips_ttl = vec![(RData::A(Ipv4Addr::new(127, 0, 0, 1)), 3)];

        let rc_ips = lru.insert(name.clone(), ips_ttl, now);
        assert_eq!(*rc_ips.iter().next().unwrap(), ips[0]);
        // the returned lookup should use the record's TTL, since it's
        // greater than the cache's minimum.
        assert_eq!(rc_ips.valid_until(), now + Duration::from_secs(3));
    }

    #[test]
    fn test_insert() {
        let now = Instant::now();
        let name = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        let ips_ttl = vec![(RData::A(Ipv4Addr::new(127, 0, 0, 1)), 1)];
        let ips = vec![RData::A(Ipv4Addr::new(127, 0, 0, 1))];
        let mut lru = DnsLru::new(1, TtlConfig::default());

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
        let mut lru = DnsLru::new(1, TtlConfig::default());

        lru.insert(name.clone(), ips_ttl, now);

        // still valid
        let rc_ips = lru.get(&name, now + Duration::from_secs(1)).unwrap();
        assert_eq!(*rc_ips.iter().next().unwrap(), ips[0]);

        // 2 should be one too far
        let rc_ips = lru.get(&name, now + Duration::from_secs(2));
        assert!(rc_ips.is_none());
    }

    #[test]
    fn test_insert_positive_min_ttl() {
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

        // this cache should override the TTL of 1 seconds with the configured
        // minimum TTL of 3 seconds.
        let ttls = TtlConfig {
            positive_min_ttl: Some(Duration::from_secs(3)),
            ..Default::default()
        };
        let mut lru = DnsLru::new(1, ttls);
        lru.insert(name.clone(), ips_ttl, now);

        // still valid
        let rc_ips = lru.get(&name, now + Duration::from_secs(1)).unwrap();
        for (rc_ip, ip) in rc_ips.iter().zip(ips.iter()) {
            assert_eq!(rc_ip, ip, "after 1 second");
        }

        let rc_ips = lru.get(&name, now + Duration::from_secs(2)).unwrap();
        for (rc_ip, ip) in rc_ips.iter().zip(ips.iter()) {
            assert_eq!(rc_ip, ip, "after 2 seconds");
        }

        let rc_ips = lru.get(&name, now + Duration::from_secs(3)).unwrap();
        for (rc_ip, ip) in rc_ips.iter().zip(ips.iter()) {
            assert_eq!(rc_ip, ip, "after 3 seconds");
        }

        // after 4 seconds, the records should be invalid.
        let rc_ips = lru.get(&name, now + Duration::from_secs(4));
        assert!(rc_ips.is_none());
    }
}
