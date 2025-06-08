// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! An LRU cache designed for work with DNS lookups

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use moka::{Expiry, sync::Cache};

use crate::lookup::Lookup;
#[cfg(feature = "__dnssec")]
use crate::proto::dnssec::rdata::RRSIG;
use crate::proto::op::Query;
#[cfg(feature = "__dnssec")]
use crate::proto::rr::RecordData;
use crate::proto::rr::{Record, RecordType};
use crate::proto::{NoRecords, ProtoError, ProtoErrorKind};
use crate::response_cache::{MAX_TTL, TtlConfig};

#[derive(Debug, Clone)]
struct LruValue {
    // In the Err case, this represents an NXDomain
    lookup: Result<Lookup, ProtoError>,
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

    fn with_updated_ttl(&self, now: Instant) -> Self {
        let lookup = match &self.lookup {
            Ok(lookup) => {
                let records = lookup
                    .records()
                    .iter()
                    .map(|record| {
                        let mut record = record.clone();
                        record.set_ttl(self.ttl(now).as_secs() as u32);
                        record
                    })
                    .collect::<Vec<Record>>();
                Ok(Lookup::new_with_deadline(
                    lookup.query().clone(),
                    Arc::from(records),
                    self.valid_until,
                ))
            }
            Err(e) => Err(e.clone()),
        };
        Self {
            lookup,
            valid_until: self.valid_until,
        }
    }
}

/// A cache specifically for storing DNS records.
///
/// This is named `DnsLru` for historical reasons. It currently uses a "TinyLFU" policy, implemented
/// in the `moka` library.
#[derive(Clone, Debug)]
pub struct DnsLru {
    cache: Cache<Query, LruValue>,
    ttl_config: Arc<TtlConfig>,
}

impl DnsLru {
    /// Construct a new cache
    ///
    /// # Arguments
    ///
    /// * `capacity` - size in number of cached queries
    /// * `ttl_config` - minimum and maximum TTLs for cached records
    pub fn new(capacity: usize, ttl_config: TtlConfig) -> Self {
        let cache = Cache::builder()
            .max_capacity(capacity.try_into().unwrap_or(u64::MAX))
            .expire_after(LruValueExpiry)
            .build();
        Self {
            cache,
            ttl_config: Arc::new(ttl_config),
        }
    }

    pub(crate) fn clear(&self) {
        self.cache.invalidate_all();
    }

    pub(crate) fn insert(
        &self,
        query: Query,
        records_and_ttl: Vec<(Record, u32)>,
        now: Instant,
    ) -> Lookup {
        let len = records_and_ttl.len();
        let (positive_min_ttl, positive_max_ttl) = self
            .ttl_config
            .positive_response_ttl_bounds(query.query_type())
            .into_inner();

        // collapse the values, we're going to take the Minimum TTL as the correct one
        let (records, ttl): (Vec<Record>, Duration) = records_and_ttl.into_iter().fold(
            (Vec::with_capacity(len), positive_max_ttl),
            |(mut records, mut min_ttl), (record, ttl)| {
                records.push(record);
                let ttl = Duration::from_secs(u64::from(ttl));
                min_ttl = min_ttl.min(ttl);
                (records, min_ttl)
            },
        );

        // If the cache was configured with a minimum TTL, and that value is higher
        // than the minimum TTL in the values, use it instead.
        let ttl = positive_min_ttl.max(ttl);
        let valid_until = now + ttl;

        // insert into the LRU
        let lookup = Lookup::new_with_deadline(query.clone(), Arc::from(records), valid_until);
        self.cache.insert(
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
                // it's not useful to cache RRSIGs on their own using `name()` as a key because
                // there can be multiple RRSIG associated to the same domain name where each
                // RRSIG is *covering* a different record type
                //
                // an example of this is shown below
                //
                // ``` console
                // $ dig @a.iana-servers.net. +norecurse +dnssec A example.com.
                // example.com.     3600    IN  A   93.184.215.14
                // example.com.     3600    IN  RRSIG   A 13 2 3600 20240705065834 (..)
                //
                // $ dig @a.iana-servers.net. +norecurse +dnssec A example.com.
                // example.com.     86400   IN  NS  a.iana-servers.net.
                // example.com.     86400   IN  NS  b.iana-servers.net.
                // example.com.     86400   IN  RRSIG   NS 13 2 86400 20240705060635 (..)
                // ```
                //
                // note that there are two RRSIG records associated to `example.com.` but they are
                // covering different record types. the first RRSIG covers the
                // `A example.com.` record. the second RRSIG covers two `NS example.com.` records
                //
                // if we use ("example.com.", RecordType::RRSIG) as a key in our cache these two
                // consecutive queries will cause the entry to be overwritten, losing the RRSIG
                // covering the A record
                //
                // to avoid this problem, we'll cache the RRSIG along the record it covers using
                // the record's type along the record's `name()` as the key in the cache
                //
                // For CNAME records, we want to preserve the original request query type, since
                // that's what would be used to retrieve the cached query.
                let rtype = match record.record_type() {
                    RecordType::CNAME => original_query.query_type(),
                    #[cfg(feature = "__dnssec")]
                    RecordType::RRSIG => match RRSIG::try_borrow(record.data()) {
                        Some(rrsig) => rrsig.input().type_covered,
                        None => record.record_type(),
                    },
                    _ => record.record_type(),
                };

                let mut query = Query::query(record.name().clone(), rtype);
                query.set_query_class(record.dns_class());

                let ttl = record.ttl();

                map.entry(query).or_default().push((record, ttl));

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

        self.cache.insert(
            query,
            LruValue {
                lookup: Ok(lookup.clone()),
                valid_until,
            },
        );

        lookup
    }

    /// This converts the Error to set the inner negative_ttl value to be the
    ///  current expiration ttl.
    fn nx_error_with_ttl(error: &mut ProtoError, new_ttl: Duration) {
        let ProtoError { kind, .. } = error;

        if let ProtoErrorKind::NoRecordsFound(NoRecords { negative_ttl, .. }) = kind.as_mut() {
            *negative_ttl = Some(u32::try_from(new_ttl.as_secs()).unwrap_or(MAX_TTL));
        }
    }

    pub(crate) fn negative(&self, query: Query, mut error: ProtoError, now: Instant) -> ProtoError {
        let ProtoError { kind, .. } = &error;

        // TODO: if we are getting a negative response, should we instead fallback to cache?
        //   this would cache indefinitely, probably not correct
        if let ProtoErrorKind::NoRecordsFound(NoRecords {
            negative_ttl: Some(ttl),
            ..
        }) = kind.as_ref()
        {
            let (negative_min_ttl, negative_max_ttl) = self
                .ttl_config
                .negative_response_ttl_bounds(query.query_type())
                .into_inner();

            let ttl_duration = Duration::from_secs(u64::from(*ttl))
                // Clamp the TTL so that it's between the cache's configured
                // minimum and maximum TTLs for negative responses.
                .clamp(negative_min_ttl, negative_max_ttl);
            let valid_until = now + ttl_duration;

            {
                let error = error.clone();

                self.cache.insert(
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
    pub fn get(&self, query: &Query, now: Instant) -> Option<Result<Lookup, ProtoError>> {
        let value = self.cache.get(query)?;
        if !value.is_current(now) {
            return None;
        }
        let mut result = value.with_updated_ttl(now).lookup;
        if let Err(err) = &mut result {
            Self::nx_error_with_ttl(err, value.ttl(now));
        }
        Some(result)
    }
}

struct LruValueExpiry;

impl Expiry<Query, LruValue> for LruValueExpiry {
    fn expire_after_create(
        &self,
        _key: &Query,
        value: &LruValue,
        created_at: Instant,
    ) -> Option<Duration> {
        Some(value.ttl(created_at))
    }

    fn expire_after_update(
        &self,
        _key: &Query,
        value: &LruValue,
        updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        Some(value.ttl(updated_at))
    }
}

// see also the lookup_tests.rs in integration-tests crate
#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::time::*;

    use crate::proto::op::{Query, ResponseCode};
    use crate::proto::rr::rdata::{A, TXT};
    use crate::proto::rr::{Name, RData, RecordType};

    use super::*;

    #[test]
    fn test_is_current() {
        let now = Instant::now();
        let not_the_future = now + Duration::from_secs(4);
        let future = now + Duration::from_secs(5);
        let past_the_future = now + Duration::from_secs(6);

        let value = LruValue {
            lookup: Err(ProtoErrorKind::Message("test error").into()),
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
            Record::from_rdata(name.clone(), 1, RData::A(A::new(127, 0, 0, 1))),
            1,
        )];
        let ips = [RData::A(A::new(127, 0, 0, 1))];

        // configure the cache with a minimum TTL of 2 seconds.
        let ttls = TtlConfig::new(Some(Duration::from_secs(2)), None, None, None);
        let lru = DnsLru::new(1, ttls);

        let rc_ips = lru.insert(query.clone(), ips_ttl, now);
        assert_eq!(*rc_ips.iter().next().unwrap(), ips[0]);
        // the returned lookup should use the cache's min TTL, since the
        // query's TTL was below the minimum.
        assert_eq!(rc_ips.valid_until(), now + Duration::from_secs(2));

        // record should have TTL of 3 seconds.
        let ips_ttl = vec![(
            Record::from_rdata(name, 3, RData::A(A::new(127, 0, 0, 1))),
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
        let ttls = TtlConfig::new(None, Some(Duration::from_secs(2)), None, None);
        let lru = DnsLru::new(1, ttls);

        // neg response should have TTL of 1 seconds.
        let mut no_records = NoRecords::new(name.clone(), ResponseCode::NoError);
        no_records.negative_ttl = Some(1);
        let nx_error = lru.negative(name.clone(), no_records.into(), now);
        match nx_error.kind() {
            &ProtoErrorKind::NoRecordsFound(NoRecords { negative_ttl, .. }) => {
                let valid_until = negative_ttl.expect("resolve error should have a deadline");
                // the error's `valid_until` field should have been limited to 2 seconds.
                assert_eq!(valid_until, 2);
            }
            other => panic!("expected ProtoErrorKind::NoRecordsFound, got {other:?}"),
        }

        // neg response should have TTL of 3 seconds.
        let mut no_records = NoRecords::new(name.clone(), ResponseCode::NoError);
        no_records.negative_ttl = Some(3);
        let nx_error = lru.negative(name, no_records.into(), now);
        match nx_error.kind() {
            &ProtoErrorKind::NoRecordsFound(NoRecords { negative_ttl, .. }) => {
                let negative_ttl = negative_ttl.expect("ProtoError should have a deadline");
                // the error's `valid_until` field should not have been limited, as it was
                // over the min TTL.
                assert_eq!(negative_ttl, 3);
            }
            other => panic!("expected ProtoErrorKind::NoRecordsFound, got {other:?}"),
        }
    }

    #[test]
    fn test_lookup_uses_positive_max_ttl() {
        let now = Instant::now();

        let name = Name::from_str("www.example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);
        // record should have TTL of 62 seconds.
        let ips_ttl = vec![(
            Record::from_rdata(name.clone(), 62, RData::A(A::new(127, 0, 0, 1))),
            62,
        )];
        let ips = [RData::A(A::new(127, 0, 0, 1))];

        // configure the cache with a maximum TTL of 60 seconds.
        let ttls = TtlConfig::new(None, None, Some(Duration::from_secs(60)), None);
        let lru = DnsLru::new(1, ttls);

        let rc_ips = lru.insert(query.clone(), ips_ttl, now);
        assert_eq!(*rc_ips.iter().next().unwrap(), ips[0]);
        // the returned lookup should use the cache's min TTL, since the
        // query's TTL was above the maximum.
        assert_eq!(rc_ips.valid_until(), now + Duration::from_secs(60));

        // record should have TTL of 59 seconds.
        let ips_ttl = vec![(
            Record::from_rdata(name, 59, RData::A(A::new(127, 0, 0, 1))),
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
        let ttls = TtlConfig::new(None, None, None, Some(Duration::from_secs(60)));
        let lru = DnsLru::new(1, ttls);

        // neg response should have TTL of 62 seconds.
        let mut no_records = NoRecords::new(name.clone(), ResponseCode::NoError);
        no_records.negative_ttl = Some(62);
        let nx_error = lru.negative(name.clone(), no_records.into(), now);
        match nx_error.kind() {
            &ProtoErrorKind::NoRecordsFound(NoRecords { negative_ttl, .. }) => {
                let negative_ttl = negative_ttl.expect("resolve error should have a deadline");
                // the error's `valid_until` field should have been limited to 60 seconds.
                assert_eq!(negative_ttl, 60);
            }
            other => panic!("expected ProtoErrorKind::NoRecordsFound, got {other:?}"),
        }

        // neg response should have TTL of 59 seconds.
        let mut no_records = NoRecords::new(name.clone(), ResponseCode::NoError);
        no_records.negative_ttl = Some(59);
        let nx_error = lru.negative(name, no_records.into(), now);
        match nx_error.kind() {
            &ProtoErrorKind::NoRecordsFound(NoRecords { negative_ttl, .. }) => {
                let negative_ttl = negative_ttl.expect("resolve error should have a deadline");
                // the error's `valid_until` field should not have been limited, as it was
                // under the max TTL.
                assert_eq!(negative_ttl, 59);
            }
            other => panic!("expected ProtoErrorKind::NoRecordsFound, got {other:?}"),
        }
    }

    #[test]
    fn test_insert() {
        let now = Instant::now();

        let name = Name::from_str("www.example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);
        let ips_ttl = vec![(
            Record::from_rdata(name, 1, RData::A(A::new(127, 0, 0, 1))),
            1,
        )];
        let ips = [RData::A(A::new(127, 0, 0, 1))];
        let lru = DnsLru::new(1, TtlConfig::default());

        let rc_ips = lru.insert(query.clone(), ips_ttl, now);
        assert_eq!(*rc_ips.iter().next().unwrap(), ips[0]);

        let rc_ips = lru.get(&query, now).unwrap().expect("records should exist");
        assert_eq!(*rc_ips.iter().next().unwrap(), ips[0]);
    }

    #[test]
    fn test_update_ttl() {
        let now = Instant::now();

        let name = Name::from_str("www.example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);
        let ips_ttl = vec![(
            Record::from_rdata(name, 10, RData::A(A::new(127, 0, 0, 1))),
            10,
        )];
        let ips = [RData::A(A::new(127, 0, 0, 1))];
        let lru = DnsLru::new(1, TtlConfig::default());

        let rc_ips = lru.insert(query.clone(), ips_ttl, now);
        assert_eq!(*rc_ips.iter().next().unwrap(), ips[0]);

        let ttl = lru
            .get(&query, now + Duration::from_secs(2))
            .unwrap()
            .expect("records should exist")
            .record_iter()
            .next()
            .unwrap()
            .ttl();
        assert!(ttl <= 8);
    }

    #[test]
    fn test_insert_ttl() {
        let now = Instant::now();
        let name = Name::from_str("www.example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);
        // TTL should be 1
        let ips_ttl = vec![
            (
                Record::from_rdata(name.clone(), 1, RData::A(A::new(127, 0, 0, 1))),
                1,
            ),
            (
                Record::from_rdata(name, 2, RData::A(A::new(127, 0, 0, 2))),
                2,
            ),
        ];
        let ips = vec![
            RData::A(A::new(127, 0, 0, 1)),
            RData::A(A::new(127, 0, 0, 2)),
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
                Record::from_rdata(name.clone(), 1, RData::A(A::new(127, 0, 0, 1))),
                1,
            ),
            (
                Record::from_rdata(name, 2, RData::A(A::new(127, 0, 0, 2))),
                2,
            ),
        ];
        let ips = vec![
            RData::A(A::new(127, 0, 0, 1)),
            RData::A(A::new(127, 0, 0, 2)),
        ];

        // this cache should override the TTL of 1 seconds with the configured
        // minimum TTL of 3 seconds.
        let ttls = TtlConfig::new(Some(Duration::from_secs(3)), None, None, None);
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
                Record::from_rdata(name.clone(), 400, RData::A(A::new(127, 0, 0, 1))),
                400,
            ),
            (
                Record::from_rdata(name, 500, RData::A(A::new(127, 0, 0, 2))),
                500,
            ),
        ];
        let ips = vec![
            RData::A(A::new(127, 0, 0, 1)),
            RData::A(A::new(127, 0, 0, 2)),
        ];

        // this cache should override the TTL of 500 seconds with the configured
        // minimum TTL of 2 seconds.
        let ttls = TtlConfig::new(None, None, Some(Duration::from_secs(2)), None);
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

    #[test]
    fn test_lookup_positive_min_ttl_different_query_types() {
        let now = Instant::now();

        let name = Name::from_str("www.example.com.").unwrap();
        let query_a = Query::query(name.clone(), RecordType::A);
        let query_txt = Query::query(name.clone(), RecordType::TXT);
        let rdata_a = RData::A(A::new(127, 0, 0, 1));
        let rdata_txt = RData::TXT(TXT::new(vec!["data".to_string()]));
        // store records with a TTL of 1 second.
        let records_ttl_a = vec![(Record::from_rdata(name.clone(), 1, rdata_a.clone()), 1)];
        let records_ttl_txt = vec![(Record::from_rdata(name.clone(), 1, rdata_txt.clone()), 1)];

        // set separate positive_min_ttl limits for TXT queries and all others
        let mut ttl_config = TtlConfig::new(Some(Duration::from_secs(2)), None, None, None);
        ttl_config.with_query_type_ttl_bounds(
            RecordType::TXT,
            Some(Duration::from_secs(5)),
            None,
            None,
            None,
        );
        let lru = DnsLru::new(2, ttl_config);

        let rc_a = lru.insert(query_a.clone(), records_ttl_a, now);
        assert_eq!(*rc_a.iter().next().unwrap(), rdata_a);
        // the returned lookup should use the cache's default min TTL, since the
        // response's TTL was below the minimum.
        assert_eq!(rc_a.valid_until(), now + Duration::from_secs(2));

        let rc_txt = lru.insert(query_txt.clone(), records_ttl_txt, now);
        assert_eq!(*rc_txt.iter().next().unwrap(), rdata_txt);
        // the returned lookup should use the min TTL for TXT records, since the
        // response's TTL was below the minimum.
        assert_eq!(rc_txt.valid_until(), now + Duration::from_secs(5));

        // store records with a TTL of 7 seconds.
        let records_ttl_a = vec![(Record::from_rdata(name.clone(), 1, rdata_a.clone()), 7)];
        let records_ttl_txt = vec![(Record::from_rdata(name.clone(), 1, rdata_txt.clone()), 7)];

        let rc_a = lru.insert(query_a, records_ttl_a, now);
        assert_eq!(*rc_a.iter().next().unwrap(), rdata_a);
        // the returned lookup should use the record's TTL, since it's
        // greater than the default min TTL.
        assert_eq!(rc_a.valid_until(), now + Duration::from_secs(7));

        let rc_txt = lru.insert(query_txt, records_ttl_txt, now);
        assert_eq!(*rc_txt.iter().next().unwrap(), rdata_txt);
        // the returned lookup should use the record's TTL, since it's
        // greater than the min TTL for TXT records.
        assert_eq!(rc_txt.valid_until(), now + Duration::from_secs(7));
    }
}
