// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! An LRU cache designed for work with DNS lookups

use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru_cache::LruCache;
use parking_lot::Mutex;

use proto::op::Query;
use proto::rr::Record;

use crate::config;
use crate::error::*;
use crate::lookup::Lookup;

/// Maximum TTL as defined in https://tools.ietf.org/html/rfc2181, 2147483647
///   Setting this to a value of 1 day, in seconds
pub(crate) const MAX_TTL: u32 = 86400_u32;

#[derive(Debug)]
struct LruValue {
    // In the None case, this represents an NXDomain
    lookup: Result<Lookup, ResolveError>,
    valid_until: Instant,
}

impl LruValue {
    /// Returns true if this set of ips is still valid
    fn is_current(&self, now: Instant) -> bool {
        now <= self.valid_until
    }

    /// Returns the ttl as a Duration of time remaining.
    fn ttl(&self, now: Instant) -> Duration {
        self.valid_until.saturating_duration_since(now)
    }
}

/// And LRU eviction cache specifically for storing DNS records
#[derive(Clone, Debug)]
pub struct DnsLru {
    cache: Arc<Mutex<LruCache<Query, LruValue>>>,
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

/// The time-to-live, TTL, configuration for use by the cache.
///
/// It should be understood that the TTL in DNS is expressed with a u32.
///   We use Duration here for tracking this which can express larger values
///   than the DNS standard. Generally a Duration greater than u32::MAX_VALUE
///   shouldn't cause any issue as this will never be used in serialization,
///   but understand that this would be outside the standard range.
#[derive(Copy, Clone, Debug, Default)]
pub struct TtlConfig {
    /// An optional minimum TTL value for positive responses.
    ///
    /// Positive responses with TTLs under `positive_min_ttl` will use
    /// `positive_min_ttl` instead.
    pub(crate) positive_min_ttl: Option<Duration>,
    /// An optional minimum TTL value for negative (`NXDOMAIN`) responses.
    ///
    /// `NXDOMAIN` responses with TTLs under `negative_min_ttl will use
    /// `negative_min_ttl` instead.
    pub(crate) negative_min_ttl: Option<Duration>,
    /// An optional maximum TTL value for positive responses.
    ///
    /// Positive responses with TTLs positive `positive_max_ttl` will use
    /// `positive_max_ttl` instead.
    pub(crate) positive_max_ttl: Option<Duration>,
    /// An optional maximum TTL value for negative (`NXDOMAIN`) responses.
    ///
    /// `NXDOMAIN` responses with TTLs over `negative_max_ttl` will use
    /// `negative_max_ttl` instead.
    pub(crate) negative_max_ttl: Option<Duration>,
}

impl TtlConfig {
    /// Construct the LRU based on the ResolverOpts configuration
    pub fn from_opts(opts: &config::ResolverOpts) -> Self {
        Self {
            positive_min_ttl: opts.positive_min_ttl,
            negative_min_ttl: opts.negative_min_ttl,
            positive_max_ttl: opts.positive_max_ttl,
            negative_max_ttl: opts.negative_max_ttl,
        }
    }
}

impl DnsLru {
    /// Construct a new cache
    ///
    /// # Arguments
    ///
    /// * `capacity` - size in number of records, this can be the max size of 2048 (record size) * `capacity`
    /// * `ttl_cfg` - force minimums and maximums for cached records
    pub fn new(capacity: usize, ttl_cfg: TtlConfig) -> Self {
        let TtlConfig {
            positive_min_ttl,
            negative_min_ttl,
            positive_max_ttl,
            negative_max_ttl,
        } = ttl_cfg;
        let cache = Arc::new(Mutex::new(LruCache::new(capacity)));
        Self {
            cache,
            positive_min_ttl: positive_min_ttl.unwrap_or_else(|| Duration::from_secs(0)),
            negative_min_ttl: negative_min_ttl.unwrap_or_else(|| Duration::from_secs(0)),
            positive_max_ttl: positive_max_ttl
                .unwrap_or_else(|| Duration::from_secs(u64::from(MAX_TTL))),
            negative_max_ttl: negative_max_ttl
                .unwrap_or_else(|| Duration::from_secs(u64::from(MAX_TTL))),
        }
    }

    pub(crate) fn clear(&self) {
        self.cache.lock().clear();
    }

    pub(crate) fn insert(
        &self,
        query: Query,
        records_and_ttl: Vec<(Record, u32)>,
        now: Instant,
    ) -> Lookup {
        let len = records_and_ttl.len();
        // collapse the values, we're going to take the Minimum TTL as the correct one
        let (records, ttl): (Vec<Record>, Duration) = records_and_ttl.into_iter().fold(
            (Vec::with_capacity(len), self.positive_max_ttl),
            |(mut records, mut min_ttl), (record, ttl)| {
                records.push(record);
                let ttl = Duration::from_secs(u64::from(ttl));
                min_ttl = min_ttl.min(ttl);
                (records, min_ttl)
            },
        );

        // If the cache was configured with a minimum TTL, and that value is higher
        // than the minimum TTL in the values, use it instead.
        let ttl = self.positive_min_ttl.max(ttl);
        let valid_until = now + ttl;

        // insert into the LRU
        let lookup = Lookup::new_with_deadline(query.clone(), Arc::from(records), valid_until);
        self.cache.lock().insert(
            query,
            LruValue {
                lookup: Ok(lookup.clone()),
                valid_until,
            },
        );

        lookup
    }

    /// inserts a record based on the name and type.
    ///
    /// # Arguments
    ///
    /// * `original_query` - is used for matching the records that should be returned
    /// * `records` - the records will be partitioned by type and name for storage in the cache
    /// * `now` - current time for use in associating TTLs
    ///
    /// # Return
    ///
    /// This should always return some records, but will be None if there are no records or the original_query matches none
    pub fn insert_records(
        &self,
        original_query: Query,
        records: impl Iterator<Item = Record>,
        now: Instant,
    ) -> Option<Lookup> {
        // collect all records by name
        let records = records.fold(
            HashMap::<Query, Vec<(Record, u32)>>::new(),
            |mut map, record| {
                let mut query = Query::query(record.name().clone(), record.record_type());
                query.set_query_class(record.dns_class());

                let ttl = record.ttl();

                map.entry(query)
                    .or_insert_with(Vec::default)
                    .push((record, ttl));

                map
            },
        );

        // now insert by record type and name
        let mut lookup = None;
        for (query, records_and_ttl) in records {
            let is_query = original_query == query;
            let inserted = self.insert(query, records_and_ttl, now);

            if is_query {
                lookup = Some(inserted)
            }
        }

        lookup
    }

    /// Generally for inserting a set of records that have already been cached, but with a different Query.
    pub(crate) fn duplicate(&self, query: Query, lookup: Lookup, ttl: u32, now: Instant) -> Lookup {
        let ttl = Duration::from_secs(u64::from(ttl));
        let valid_until = now + ttl;

        self.cache.lock().insert(
            query,
            LruValue {
                lookup: Ok(lookup.clone()),
                valid_until,
            },
        );

        lookup
    }

    /// This converts the ResolveError to set the inner negative_ttl value to be the
    ///  current expiration ttl.
    fn nx_error_with_ttl(error: &mut ResolveError, new_ttl: Duration) {
        if let ResolveError {
            kind:
                ResolveErrorKind::NoRecordsFound {
                    ref mut negative_ttl,
                    ..
                },
            ..
        } = error
        {
            *negative_ttl = Some(u32::try_from(new_ttl.as_secs()).unwrap_or(MAX_TTL));
        }
    }

    pub(crate) fn negative(
        &self,
        query: Query,
        mut error: ResolveError,
        now: Instant,
    ) -> ResolveError {
        // TODO: if we are getting a negative response, should we instead fallback to cache?
        //   this would cache indefinitely, probably not correct
        if let ResolveError {
            kind:
                ResolveErrorKind::NoRecordsFound {
                    negative_ttl: Some(ttl),
                    ..
                },
            ..
        } = error
        {
            let ttl_duration = Duration::from_secs(u64::from(ttl))
                // Clamp the TTL so that it's between the cache's configured
                // minimum and maximum TTLs for negative responses.
                .clamp(self.negative_min_ttl, self.negative_max_ttl);
            let valid_until = now + ttl_duration;

            {
                let error = error.clone();

                self.cache.lock().insert(
                    query,
                    LruValue {
                        lookup: Err(error),
                        valid_until,
                    },
                );
            }

            Self::nx_error_with_ttl(&mut error, ttl_duration);
        }

        error
    }

    /// Based on the query, see if there are any records available
    pub fn get(&self, query: &Query, now: Instant) -> Option<Result<Lookup, ResolveError>> {
        let mut out_of_date = false;
        let mut cache = self.cache.lock();
        let lookup = cache.get_mut(query).and_then(|value| {
            if value.is_current(now) {
                out_of_date = false;
                let mut result = value.lookup.clone();

                if let Err(ref mut err) = result {
                    Self::nx_error_with_ttl(err, value.ttl(now));
                }
                Some(result)
            } else {
                out_of_date = true;
                None
            }
        });

        // in this case, we can preemptively remove out of data elements
        // this assumes time is always moving forward, this would only not be true in contrived situations where now
        //  is not current time, like tests...
        if out_of_date {
            cache.remove(query);
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

    use proto::op::{Query, ResponseCode};
    use proto::rr::{Name, RData, RecordType};

    use super::*;

    #[test]
    fn test_is_current() {
        let now = Instant::now();
        let not_the_future = now + Duration::from_secs(4);
        let future = now + Duration::from_secs(5);
        let past_the_future = now + Duration::from_secs(6);

        let value = LruValue {
            lookup: Err(ResolveErrorKind::Message("test error").into()),
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

        let name = Name::from_str("www.example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);
        // record should have TTL of 1 second.
        let ips_ttl = vec![(
            Record::from_rdata(name.clone(), 1, RData::A(Ipv4Addr::new(127, 0, 0, 1))),
            1,
        )];
        let ips = vec![RData::A(Ipv4Addr::new(127, 0, 0, 1))];

        // configure the cache with a minimum TTL of 2 seconds.
        let ttls = TtlConfig {
            positive_min_ttl: Some(Duration::from_secs(2)),
            ..TtlConfig::default()
        };
        let lru = DnsLru::new(1, ttls);

        let rc_ips = lru.insert(query.clone(), ips_ttl, now);
        assert_eq!(*rc_ips.iter().next().unwrap(), ips[0]);
        // the returned lookup should use the cache's min TTL, since the
        // query's TTL was below the minimum.
        assert_eq!(rc_ips.valid_until(), now + Duration::from_secs(2));

        // record should have TTL of 3 seconds.
        let ips_ttl = vec![(
            Record::from_rdata(name, 3, RData::A(Ipv4Addr::new(127, 0, 0, 1))),
            3,
        )];

        let rc_ips = lru.insert(query, ips_ttl, now);
        assert_eq!(*rc_ips.iter().next().unwrap(), ips[0]);
        // the returned lookup should use the record's TTL, since it's
        // greater than the cache's minimum.
        assert_eq!(rc_ips.valid_until(), now + Duration::from_secs(3));
    }

    #[test]
    fn test_error_uses_negative_min_ttl() {
        let now = Instant::now();

        let name = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

        // configure the cache with a maximum TTL of 2 seconds.
        let ttls = TtlConfig {
            negative_min_ttl: Some(Duration::from_secs(2)),
            ..TtlConfig::default()
        };
        let lru = DnsLru::new(1, ttls);

        // neg response should have TTL of 1 seconds.
        let err = ResolveErrorKind::NoRecordsFound {
            query: Box::new(name.clone()),
            soa: None,
            negative_ttl: Some(1),
            response_code: ResponseCode::NoError,
            trusted: false,
        };
        let nx_error = lru.negative(name.clone(), err.into(), now);
        match nx_error.kind() {
            &ResolveErrorKind::NoRecordsFound { negative_ttl, .. } => {
                let valid_until = negative_ttl.expect("resolve error should have a deadline");
                // the error's `valid_until` field should have been limited to 2 seconds.
                assert_eq!(valid_until, 2);
            }
            other => panic!("expected ResolveErrorKind::NoRecordsFound, got {:?}", other),
        }

        // neg response should have TTL of 3 seconds.
        let err = ResolveErrorKind::NoRecordsFound {
            query: Box::new(name.clone()),
            soa: None,
            negative_ttl: Some(3),
            response_code: ResponseCode::NoError,
            trusted: false,
        };
        let nx_error = lru.negative(name, err.into(), now);
        match nx_error.kind() {
            &ResolveErrorKind::NoRecordsFound { negative_ttl, .. } => {
                let negative_ttl = negative_ttl.expect("ResolveError should have a deadline");
                // the error's `valid_until` field should not have been limited, as it was
                // over the min TTL.
                assert_eq!(negative_ttl, 3);
            }
            other => panic!("expected ResolveErrorKind::NoRecordsFound, got {:?}", other),
        }
    }

    #[test]
    fn test_lookup_uses_positive_max_ttl() {
        let now = Instant::now();

        let name = Name::from_str("www.example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);
        // record should have TTL of 62 seconds.
        let ips_ttl = vec![(
            Record::from_rdata(name.clone(), 62, RData::A(Ipv4Addr::new(127, 0, 0, 1))),
            62,
        )];
        let ips = vec![RData::A(Ipv4Addr::new(127, 0, 0, 1))];

        // configure the cache with a maximum TTL of 60 seconds.
        let ttls = TtlConfig {
            positive_max_ttl: Some(Duration::from_secs(60)),
            ..TtlConfig::default()
        };
        let lru = DnsLru::new(1, ttls);

        let rc_ips = lru.insert(query.clone(), ips_ttl, now);
        assert_eq!(*rc_ips.iter().next().unwrap(), ips[0]);
        // the returned lookup should use the cache's min TTL, since the
        // query's TTL was above the maximum.
        assert_eq!(rc_ips.valid_until(), now + Duration::from_secs(60));

        // record should have TTL of 59 seconds.
        let ips_ttl = vec![(
            Record::from_rdata(name, 59, RData::A(Ipv4Addr::new(127, 0, 0, 1))),
            59,
        )];

        let rc_ips = lru.insert(query, ips_ttl, now);
        assert_eq!(*rc_ips.iter().next().unwrap(), ips[0]);
        // the returned lookup should use the record's TTL, since it's
        // below than the cache's maximum.
        assert_eq!(rc_ips.valid_until(), now + Duration::from_secs(59));
    }

    #[test]
    fn test_error_uses_negative_max_ttl() {
        let now = Instant::now();

        let name = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

        // configure the cache with a maximum TTL of 60 seconds.
        let ttls = TtlConfig {
            negative_max_ttl: Some(Duration::from_secs(60)),
            ..TtlConfig::default()
        };
        let lru = DnsLru::new(1, ttls);

        // neg response should have TTL of 62 seconds.
        let err = ResolveErrorKind::NoRecordsFound {
            query: Box::new(name.clone()),
            soa: None,
            negative_ttl: Some(62),
            response_code: ResponseCode::NoError,
            trusted: false,
        };
        let nx_error = lru.negative(name.clone(), err.into(), now);
        match nx_error.kind() {
            &ResolveErrorKind::NoRecordsFound { negative_ttl, .. } => {
                let negative_ttl = negative_ttl.expect("resolve error should have a deadline");
                // the error's `valid_until` field should have been limited to 60 seconds.
                assert_eq!(negative_ttl, 60);
            }
            other => panic!("expected ResolveErrorKind::NoRecordsFound, got {:?}", other),
        }

        // neg response should have TTL of 59 seconds.
        let err = ResolveErrorKind::NoRecordsFound {
            query: Box::new(name.clone()),
            soa: None,
            negative_ttl: Some(59),
            response_code: ResponseCode::NoError,
            trusted: false,
        };
        let nx_error = lru.negative(name, err.into(), now);
        match nx_error.kind() {
            &ResolveErrorKind::NoRecordsFound { negative_ttl, .. } => {
                let negative_ttl = negative_ttl.expect("resolve error should have a deadline");
                // the error's `valid_until` field should not have been limited, as it was
                // under the max TTL.
                assert_eq!(negative_ttl, 59);
            }
            other => panic!("expected ResolveErrorKind::NoRecordsFound, got {:?}", other),
        }
    }

    #[test]
    fn test_insert() {
        let now = Instant::now();

        let name = Name::from_str("www.example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);
        let ips_ttl = vec![(
            Record::from_rdata(name, 1, RData::A(Ipv4Addr::new(127, 0, 0, 1))),
            1,
        )];
        let ips = vec![RData::A(Ipv4Addr::new(127, 0, 0, 1))];
        let lru = DnsLru::new(1, TtlConfig::default());

        let rc_ips = lru.insert(query.clone(), ips_ttl, now);
        assert_eq!(*rc_ips.iter().next().unwrap(), ips[0]);

        let rc_ips = lru.get(&query, now).unwrap().expect("records should exist");
        assert_eq!(*rc_ips.iter().next().unwrap(), ips[0]);
    }

    #[test]
    fn test_insert_ttl() {
        let now = Instant::now();
        let name = Name::from_str("www.example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);
        // TTL should be 1
        let ips_ttl = vec![
            (
                Record::from_rdata(name.clone(), 1, RData::A(Ipv4Addr::new(127, 0, 0, 1))),
                1,
            ),
            (
                Record::from_rdata(name, 2, RData::A(Ipv4Addr::new(127, 0, 0, 2))),
                2,
            ),
        ];
        let ips = vec![
            RData::A(Ipv4Addr::new(127, 0, 0, 1)),
            RData::A(Ipv4Addr::new(127, 0, 0, 2)),
        ];
        let lru = DnsLru::new(1, TtlConfig::default());

        lru.insert(query.clone(), ips_ttl, now);

        // still valid
        let rc_ips = lru
            .get(&query, now + Duration::from_secs(1))
            .unwrap()
            .expect("records should exist");
        assert_eq!(*rc_ips.iter().next().unwrap(), ips[0]);

        // 2 should be one too far
        let rc_ips = lru.get(&query, now + Duration::from_secs(2));
        assert!(rc_ips.is_none());
    }

    #[test]
    fn test_insert_positive_min_ttl() {
        let now = Instant::now();
        let name = Name::from_str("www.example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);
        // TTL should be 1
        let ips_ttl = vec![
            (
                Record::from_rdata(name.clone(), 1, RData::A(Ipv4Addr::new(127, 0, 0, 1))),
                1,
            ),
            (
                Record::from_rdata(name, 2, RData::A(Ipv4Addr::new(127, 0, 0, 2))),
                2,
            ),
        ];
        let ips = vec![
            RData::A(Ipv4Addr::new(127, 0, 0, 1)),
            RData::A(Ipv4Addr::new(127, 0, 0, 2)),
        ];

        // this cache should override the TTL of 1 seconds with the configured
        // minimum TTL of 3 seconds.
        let ttls = TtlConfig {
            positive_min_ttl: Some(Duration::from_secs(3)),
            ..TtlConfig::default()
        };
        let lru = DnsLru::new(1, ttls);
        lru.insert(query.clone(), ips_ttl, now);

        // still valid
        let rc_ips = lru
            .get(&query, now + Duration::from_secs(1))
            .unwrap()
            .expect("records should exist");
        for (rc_ip, ip) in rc_ips.iter().zip(ips.iter()) {
            assert_eq!(rc_ip, ip, "after 1 second");
        }

        let rc_ips = lru
            .get(&query, now + Duration::from_secs(2))
            .unwrap()
            .expect("records should exist");
        for (rc_ip, ip) in rc_ips.iter().zip(ips.iter()) {
            assert_eq!(rc_ip, ip, "after 2 seconds");
        }

        let rc_ips = lru
            .get(&query, now + Duration::from_secs(3))
            .unwrap()
            .expect("records should exist");
        for (rc_ip, ip) in rc_ips.iter().zip(ips.iter()) {
            assert_eq!(rc_ip, ip, "after 3 seconds");
        }

        // after 4 seconds, the records should be invalid.
        let rc_ips = lru.get(&query, now + Duration::from_secs(4));
        assert!(rc_ips.is_none());
    }

    #[test]
    fn test_insert_positive_max_ttl() {
        let now = Instant::now();
        let name = Name::from_str("www.example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);
        // TTL should be 500
        let ips_ttl = vec![
            (
                Record::from_rdata(name.clone(), 400, RData::A(Ipv4Addr::new(127, 0, 0, 1))),
                400,
            ),
            (
                Record::from_rdata(name, 500, RData::A(Ipv4Addr::new(127, 0, 0, 2))),
                500,
            ),
        ];
        let ips = vec![
            RData::A(Ipv4Addr::new(127, 0, 0, 1)),
            RData::A(Ipv4Addr::new(127, 0, 0, 2)),
        ];

        // this cache should override the TTL of 500 seconds with the configured
        // minimum TTL of 2 seconds.
        let ttls = TtlConfig {
            positive_max_ttl: Some(Duration::from_secs(2)),
            ..TtlConfig::default()
        };
        let lru = DnsLru::new(1, ttls);
        lru.insert(query.clone(), ips_ttl, now);

        // still valid
        let rc_ips = lru
            .get(&query, now + Duration::from_secs(1))
            .unwrap()
            .expect("records should exist");
        for (rc_ip, ip) in rc_ips.iter().zip(ips.iter()) {
            assert_eq!(rc_ip, ip, "after 1 second");
        }

        let rc_ips = lru
            .get(&query, now + Duration::from_secs(2))
            .unwrap()
            .expect("records should exist");
        for (rc_ip, ip) in rc_ips.iter().zip(ips.iter()) {
            assert_eq!(rc_ip, ip, "after 2 seconds");
        }

        // after 3 seconds, the records should be invalid.
        let rc_ips = lru.get(&query, now + Duration::from_secs(3));
        assert!(rc_ips.is_none());
    }
}
