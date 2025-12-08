//! A cache for DNS responses.

use std::{
    collections::HashMap,
    ops::RangeInclusive,
    sync::Arc,
    time::{Duration, Instant},
};

use moka::{Expiry, sync::Cache};
#[cfg(feature = "serde")]
use serde::Deserialize;

use crate::{
    config,
    net::{DnsError, NetError, NoRecords},
    proto::{
        op::{Message, Query},
        rr::RecordType,
    },
};

/// A cache for DNS responses.
#[derive(Clone, Debug)]
pub struct ResponseCache {
    cache: Cache<Query, Entry>,
    ttl_config: Arc<TtlConfig>,
}

impl ResponseCache {
    /// Construct a new response cache.
    ///
    /// # Arguments
    ///
    /// * `capacity` - size in number of cached responses
    /// * `ttl_config` - minimum and maximum TTLs for cached records
    pub fn new(capacity: u64, ttl_config: TtlConfig) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(capacity)
                .expire_after(EntryExpiry)
                .build(),
            ttl_config: Arc::new(ttl_config),
        }
    }

    /// Insert a response into the cache.
    pub fn insert(&self, query: Query, result: Result<Message, NetError>, now: Instant) {
        let ttl = match &result {
            Ok(message) => {
                let (positive_min_ttl, positive_max_ttl) = self
                    .ttl_config
                    .positive_response_ttl_bounds(query.query_type())
                    .into_inner();
                message
                    .all_sections()
                    .map(|record| Duration::from_secs(record.ttl().into()))
                    .min()
                    .unwrap_or(positive_min_ttl)
                    .clamp(positive_min_ttl, positive_max_ttl)
            }
            Err(NetError::Dns(DnsError::NoRecordsFound(no_records))) => {
                let (negative_min_ttl, negative_max_ttl) = self
                    .ttl_config
                    .negative_response_ttl_bounds(query.query_type())
                    .into_inner();
                if let Some(ttl) = no_records.negative_ttl {
                    Duration::from_secs(u64::from(ttl)).clamp(negative_min_ttl, negative_max_ttl)
                } else {
                    negative_min_ttl
                }
            }
            Err(_) => return,
        };
        let valid_until = now + ttl;
        self.cache.insert(
            query,
            Entry {
                result: Arc::new(result),
                original_time: now,
                valid_until,
            },
        );
    }

    /// Try to retrieve a cached response with the given query.
    pub fn get(&self, query: &Query, now: Instant) -> Option<Result<Message, NetError>> {
        let entry = self.cache.get(query)?;
        if !entry.is_current(now) {
            return None;
        }
        Some(entry.updated_ttl(now))
    }

    pub(crate) fn clear(&self) {
        self.cache.invalidate_all();
    }

    pub(crate) fn clear_query(&self, query: &Query) {
        self.cache.invalidate(query);
    }
}

/// An entry in the response cache.
///
/// This contains the response itself (or an error), the time it was received, and the time at which
/// it expires.
#[derive(Debug, Clone)]
struct Entry {
    result: Arc<Result<Message, NetError>>,
    original_time: Instant,
    valid_until: Instant,
}

impl Entry {
    /// Return the `Result` stored in this entry, with modified TTLs, subtracting the elapsed time
    /// since the response was received.
    fn updated_ttl(&self, now: Instant) -> Result<Message, NetError> {
        let elapsed = u32::try_from(now.saturating_duration_since(self.original_time).as_secs())
            .unwrap_or(u32::MAX);
        match &*self.result {
            Ok(response) => {
                let mut response = response.clone();
                for section_fn in [
                    Message::answers_mut,
                    Message::authorities_mut,
                    Message::additionals_mut,
                ] {
                    for record in section_fn(&mut response) {
                        record.decrement_ttl(elapsed);
                    }
                }
                Ok(response)
            }
            Err(e) => {
                let mut e = e.clone();

                // The NoRecords error may contain up to four fields with TTL values present: negative_ttl, soa, authorities, and ns.
                // For completeness, we update each field, if present.
                if let NetError::Dns(DnsError::NoRecordsFound(NoRecords {
                    negative_ttl,
                    soa,
                    authorities,
                    ns,
                    ..
                })) = &mut e
                {
                    if let Some(ttl) = negative_ttl {
                        *ttl = ttl.saturating_sub(elapsed);
                    }

                    if let Some(soa) = soa {
                        soa.decrement_ttl(elapsed);
                    }

                    if let Some(recs) = authorities.take() {
                        authorities.replace(Arc::from(
                            recs.iter()
                                .cloned()
                                .map(|mut rec| {
                                    rec.decrement_ttl(elapsed);
                                    rec
                                })
                                .collect::<Vec<_>>(),
                        ));
                    }

                    if let Some(ns_recs) = ns.take() {
                        ns.replace(Arc::from(
                            ns_recs
                                .iter()
                                .cloned()
                                .map(|mut ns| {
                                    ns.ns.decrement_ttl(elapsed);
                                    ns.glue = Arc::from(
                                        ns.glue
                                            .iter()
                                            .cloned()
                                            .map(|mut glue| {
                                                glue.decrement_ttl(elapsed);
                                                glue
                                            })
                                            .collect::<Vec<_>>(),
                                    );

                                    ns
                                })
                                .collect::<Vec<_>>(),
                        ));
                    }
                }
                Err(e)
            }
        }
    }

    /// Returns whether this cache entry is still valid.
    fn is_current(&self, now: Instant) -> bool {
        now <= self.valid_until
    }

    /// Returns the remaining time that this cache entry is valid for.
    fn ttl(&self, now: Instant) -> Duration {
        self.valid_until.saturating_duration_since(now)
    }
}

struct EntryExpiry;

impl Expiry<Query, Entry> for EntryExpiry {
    fn expire_after_create(
        &self,
        _key: &Query,
        value: &Entry,
        created_at: Instant,
    ) -> Option<Duration> {
        Some(value.ttl(created_at))
    }

    fn expire_after_update(
        &self,
        _key: &Query,
        value: &Entry,
        updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        Some(value.ttl(updated_at))
    }
}

/// The time-to-live (TTL) configuration used by the cache.
///
/// Minimum and maximum TTLs can be set for both positive responses and negative responses. Separate
/// limits may be set depending on the query type. If a minimum value is not provided, it will
/// default to 0 seconds. If a maximum value is not provided, it will default to one day.
///
/// Note that TTLs in DNS are represented as a number of seconds stored in a 32-bit unsigned
/// integer. We use `Duration` here, instead of `u32`, which can express larger values than the DNS
/// standard. Generally, a `Duration` greater than `u32::MAX_VALUE` shouldn't cause any issue, as
/// this will never be used in serialization, but note that this would be outside the standard
/// range.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(from = "ttl_config_deserialize::TtlConfigMap")
)]
pub struct TtlConfig {
    /// TTL limits applied to all queries.
    default: TtlBounds,

    /// TTL limits applied to queries with specific query types.
    by_query_type: HashMap<RecordType, TtlBounds>,
}

impl TtlConfig {
    /// Construct the LRU's TTL configuration based on the ResolverOpts configuration.
    pub fn from_opts(opts: &config::ResolverOpts) -> Self {
        Self::from(TtlBounds {
            positive_min_ttl: opts.positive_min_ttl,
            negative_min_ttl: opts.negative_min_ttl,
            positive_max_ttl: opts.positive_max_ttl,
            negative_max_ttl: opts.negative_max_ttl,
        })
    }

    /// Override the minimum and maximum TTL values for a specific query type.
    ///
    /// If a minimum value is not provided, it will default to 0 seconds. If a maximum value is not
    /// provided, it will default to one day.
    pub fn with_query_type_ttl_bounds(
        &mut self,
        query_type: RecordType,
        bounds: TtlBounds,
    ) -> &mut Self {
        self.by_query_type.insert(query_type, bounds);
        self
    }

    /// Retrieves the minimum and maximum TTL values for positive responses.
    pub fn positive_response_ttl_bounds(&self, query_type: RecordType) -> RangeInclusive<Duration> {
        let bounds = self.by_query_type.get(&query_type).unwrap_or(&self.default);
        let min = bounds
            .positive_min_ttl
            .unwrap_or_else(|| Duration::from_secs(0));
        let max = bounds
            .positive_max_ttl
            .unwrap_or_else(|| Duration::from_secs(u64::from(MAX_TTL)));
        min..=max
    }

    /// Retrieves the minimum and maximum TTL values for negative responses.
    pub fn negative_response_ttl_bounds(&self, query_type: RecordType) -> RangeInclusive<Duration> {
        let bounds = self.by_query_type.get(&query_type).unwrap_or(&self.default);
        let min = bounds
            .negative_min_ttl
            .unwrap_or_else(|| Duration::from_secs(0));
        let max = bounds
            .negative_max_ttl
            .unwrap_or_else(|| Duration::from_secs(u64::from(MAX_TTL)));
        min..=max
    }
}

impl From<TtlBounds> for TtlConfig {
    fn from(default: TtlBounds) -> Self {
        Self {
            default,
            by_query_type: HashMap::default(),
        }
    }
}

/// Minimum and maximum TTL values for positive and negative responses.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct TtlBounds {
    /// An optional minimum TTL value for positive responses.
    ///
    /// Positive responses with TTLs under `positive_min_ttl` will use
    /// `positive_min_ttl` instead.
    #[cfg_attr(
        feature = "serde",
        serde(default, deserialize_with = "config::duration_opt::deserialize")
    )]
    positive_min_ttl: Option<Duration>,

    /// An optional minimum TTL value for negative (`NXDOMAIN`) responses.
    ///
    /// `NXDOMAIN` responses with TTLs under `negative_min_ttl` will use
    /// `negative_min_ttl` instead.
    #[cfg_attr(
        feature = "serde",
        serde(default, deserialize_with = "config::duration_opt::deserialize")
    )]
    negative_min_ttl: Option<Duration>,

    /// An optional maximum TTL value for positive responses.
    ///
    /// Positive responses with TTLs over `positive_max_ttl` will use
    /// `positive_max_ttl` instead.
    #[cfg_attr(
        feature = "serde",
        serde(default, deserialize_with = "config::duration_opt::deserialize")
    )]
    positive_max_ttl: Option<Duration>,

    /// An optional maximum TTL value for negative (`NXDOMAIN`) responses.
    ///
    /// `NXDOMAIN` responses with TTLs over `negative_max_ttl` will use
    /// `negative_max_ttl` instead.
    #[cfg_attr(
        feature = "serde",
        serde(default, deserialize_with = "config::duration_opt::deserialize")
    )]
    negative_max_ttl: Option<Duration>,
}

#[cfg(feature = "serde")]
mod ttl_config_deserialize {
    use std::collections::HashMap;

    use serde::Deserialize;

    use super::{TtlBounds, TtlConfig};
    use crate::proto::rr::RecordType;

    #[derive(Deserialize)]
    pub(super) struct TtlConfigMap(HashMap<TtlConfigField, TtlBounds>);

    impl From<TtlConfigMap> for TtlConfig {
        fn from(value: TtlConfigMap) -> Self {
            let mut default = TtlBounds::default();
            let mut by_query_type = HashMap::new();
            for (field, bounds) in value.0.into_iter() {
                match field {
                    TtlConfigField::RecordType(record_type) => {
                        by_query_type.insert(record_type, bounds);
                    }
                    TtlConfigField::Default => default = bounds,
                }
            }
            Self {
                default,
                by_query_type,
            }
        }
    }

    #[derive(PartialEq, Eq, Hash, Deserialize)]
    enum TtlConfigField {
        #[serde(rename = "default")]
        Default,
        #[serde(untagged)]
        RecordType(RecordType),
    }
}

/// Maximum TTL. This is set to one day (in seconds).
///
/// [RFC 2181, section 8](https://tools.ietf.org/html/rfc2181#section-8) says
/// that the maximum TTL value is 2147483647, but implementations may place an
/// upper bound on received TTLs.
pub const MAX_TTL: u32 = 86400_u32;

#[cfg(test)]
mod tests {
    use std::{
        str::FromStr,
        time::{Duration, Instant},
    };

    #[cfg(feature = "serde")]
    use serde::Deserialize;

    use super::*;
    use crate::{
        net::{ForwardNSData, NetError},
        proto::{
            op::{Message, OpCode, Query, ResponseCode},
            rr::{
                Name, RData, Record, RecordType,
                rdata::{A, NS, SOA, TXT},
            },
        },
    };
    use test_support::subscribe;

    #[test]
    fn test_is_current() {
        let now = Instant::now();
        let not_the_future = now + Duration::from_secs(4);
        let future = now + Duration::from_secs(5);
        let past_the_future = now + Duration::from_secs(6);

        let entry = Entry {
            result: Err(NetError::Message("test error")).into(),
            original_time: now,
            valid_until: future,
        };

        assert!(entry.is_current(now));
        assert!(entry.is_current(not_the_future));
        assert!(entry.is_current(future));
        assert!(!entry.is_current(past_the_future));
    }

    #[test]
    fn test_positive_min_ttl() {
        let now = Instant::now();

        let name = Name::from_str("www.example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);
        // Record should have TTL of 1 second.
        let mut message = Message::response(0, OpCode::Query);
        message.add_answer(Record::from_rdata(
            name.clone(),
            1,
            RData::A(A::new(127, 0, 0, 1)),
        ));

        // Configure the cache with a minimum TTL of 2 seconds.
        let ttls = TtlConfig::from(TtlBounds {
            positive_min_ttl: Some(Duration::from_secs(2)),
            ..TtlBounds::default()
        });
        let cache = ResponseCache::new(1, ttls);

        cache.insert(query.clone(), Ok(message), now);
        let valid_until = cache.cache.get(&query).unwrap().valid_until;
        // The returned lookup should use the cache's minimum TTL, since the
        // query's TTL was below the minimum.
        assert_eq!(valid_until, now + Duration::from_secs(2));

        // Record should have TTL of 3 seconds.
        let mut message = Message::response(0, OpCode::Query);
        message.add_answer(Record::from_rdata(
            name.clone(),
            3,
            RData::A(A::new(127, 0, 0, 1)),
        ));

        cache.insert(query.clone(), Ok(message), now);
        let valid_until = cache.cache.get(&query).unwrap().valid_until;
        // The returned lookup should use the record's TTL, since it's
        // greater than the cache's minimum.
        assert_eq!(valid_until, now + Duration::from_secs(3));
    }

    #[test]
    fn test_negative_min_ttl() {
        let now = Instant::now();

        let name = Name::from_str("www.example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);

        // Configure the cache with a minimum TTL of 2 seconds.
        let ttls = TtlConfig::from(TtlBounds {
            negative_min_ttl: Some(Duration::from_secs(2)),
            ..TtlBounds::default()
        });
        let cache = ResponseCache::new(1, ttls);

        // Negative response should have TTL of 1 second.
        let mut no_records = NoRecords::new(query.clone(), ResponseCode::NoError);
        no_records.negative_ttl = Some(1);
        cache.insert(query.clone(), Err(no_records.into()), now);
        let valid_until = cache.cache.get(&query).unwrap().valid_until;
        // The error's `valid_until` field should have been limited to 2 seconds.
        assert_eq!(valid_until, now + Duration::from_secs(2));

        // Negative response should have TTL of 3 seconds.
        let mut no_records = NoRecords::new(query.clone(), ResponseCode::NoError);
        no_records.negative_ttl = Some(3);
        cache.insert(query.clone(), Err(no_records.into()), now);
        let valid_until = cache.cache.get(&query).unwrap().valid_until;
        // The error's `valid_until` field should not have been limited, as it was over the minimum
        // TTL.
        assert_eq!(valid_until, now + Duration::from_secs(3));
    }

    #[test]
    fn test_positive_max_ttl() {
        let now = Instant::now();

        let name = Name::from_str("www.example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);
        // Record should have TTL of 62 seconds.
        let mut message = Message::response(0, OpCode::Query);
        message.add_answer(Record::from_rdata(
            name.clone(),
            62,
            RData::A(A::new(127, 0, 0, 1)),
        ));

        // Configure the cache with a maximum TTL of 60 seconds.
        let ttls = TtlConfig::from(TtlBounds {
            positive_max_ttl: Some(Duration::from_secs(60)),
            ..Default::default()
        });
        let cache = ResponseCache::new(1, ttls);

        cache.insert(query.clone(), Ok(message), now);
        let valid_until = cache.cache.get(&query).unwrap().valid_until;
        // The returned lookup should use the cache's minimum TTL, since the
        // query's TTL was above the maximum.
        assert_eq!(valid_until, now + Duration::from_secs(60));

        // Record should have TTL of 59 seconds.
        let mut message = Message::response(0, OpCode::Query);
        message.add_answer(Record::from_rdata(
            name.clone(),
            59,
            RData::A(A::new(127, 0, 0, 1)),
        ));

        cache.insert(query.clone(), Ok(message), now);
        let valid_until = cache.cache.get(&query).unwrap().valid_until;
        // The returned lookup should use the record's TTL, since it's
        // below than the cache's maximum.
        assert_eq!(valid_until, now + Duration::from_secs(59));
    }

    #[test]
    fn test_negative_max_ttl() {
        let now = Instant::now();

        let name = Name::from_str("www.example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);

        // Configure the cache with a maximum TTL of 60 seconds.
        let ttls = TtlConfig::from(TtlBounds {
            negative_max_ttl: Some(Duration::from_secs(60)),
            ..TtlBounds::default()
        });
        let cache = ResponseCache::new(1, ttls);

        // Negative response should have TTL of 62 seconds.
        let mut no_records = NoRecords::new(query.clone(), ResponseCode::NoError);
        no_records.negative_ttl = Some(62);
        cache.insert(query.clone(), Err(no_records.into()), now);
        let valid_until = cache.cache.get(&query).unwrap().valid_until;
        // The error's `valid_until` field should have been limited to 60 seconds.
        assert_eq!(valid_until, now + Duration::from_secs(60));

        // Negative response should have TTL of 59 seconds.
        let mut no_records = NoRecords::new(query.clone(), ResponseCode::NoError);
        no_records.negative_ttl = Some(59);
        cache.insert(query.clone(), Err(no_records.into()), now);
        let valid_until = cache.cache.get(&query).unwrap().valid_until;
        // The error's `valid_until` field should not have been limited, as it was under the maximum
        // TTL.
        assert_eq!(valid_until, now + Duration::from_secs(59));
    }

    #[test]
    fn test_insert() {
        let now = Instant::now();

        let name = Name::from_str("www.example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);
        let mut message = Message::response(0, OpCode::Query);
        message.add_answer(Record::from_rdata(
            name.clone(),
            1,
            RData::A(A::new(127, 0, 0, 1)),
        ));
        let cache = ResponseCache::new(1, TtlConfig::default());
        cache.insert(query.clone(), Ok(message.clone()), now);

        let result = cache.get(&query, now).unwrap();
        let cache_message = result.unwrap();
        assert_eq!(cache_message.answers(), message.answers());
    }

    #[test]
    fn test_insert_negative() {
        subscribe();
        let now = Instant::now();

        let query = Query::query(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::AAAA,
        );

        let mut norecs = NoRecords::new(query.clone(), ResponseCode::NXDomain);
        norecs.negative_ttl = Some(10);
        let error = NetError::from(norecs);
        let cache = ResponseCache::new(1, TtlConfig::default());

        cache.insert(query.clone(), Err(error), now);

        let cache_err = cache.get(&query, now).unwrap().unwrap_err();
        let NetError::Dns(DnsError::NoRecordsFound(_no_records)) = &cache_err else {
            panic!("expected NoRecordsFound");
        };

        // Cache should be expired
        assert!(cache.get(&query, now + Duration::from_secs(11)).is_none());
    }

    #[test]
    fn test_update_ttl() {
        let now = Instant::now();

        let name = Name::from_str("www.example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);
        let mut message = Message::response(0, OpCode::Query);
        message.add_answer(Record::from_rdata(
            name.clone(),
            10,
            RData::A(A::new(127, 0, 0, 1)),
        ));
        let cache = ResponseCache::new(1, TtlConfig::default());
        cache.insert(query.clone(), Ok(message), now);

        let result = cache.get(&query, now + Duration::from_secs(2)).unwrap();
        let cache_message = result.unwrap();
        let record = cache_message.answers().first().unwrap();
        assert_eq!(record.ttl(), 8);
    }

    #[test]
    fn test_update_ttl_negative() -> Result<(), NetError> {
        subscribe();
        let now = Instant::now();
        let name = Name::from_str("www.example.com.")?;
        let ns_name = Name::from_str("ns1.example.com")?;
        let zone_name = name.base_name();
        let query = Query::query(name.clone(), RecordType::AAAA);

        let mut norecs = NoRecords::new(query.clone(), ResponseCode::NXDomain);
        norecs.negative_ttl = Some(10);
        norecs.soa = Some(Box::new(Record::from_rdata(
            zone_name.clone(),
            10,
            SOA::new(name.base_name(), name.clone(), 1, 1, 1, 1, 1),
        )));
        norecs.authorities = Some(Arc::new([Record::from_rdata(
            zone_name.clone(),
            10,
            RData::NS(NS(ns_name.clone())),
        )]));
        norecs.ns = Some(Arc::new([ForwardNSData {
            ns: Record::from_rdata(zone_name.clone(), 10, RData::NS(NS(ns_name.clone()))),
            glue: Arc::new([Record::from_rdata(
                ns_name.clone(),
                10,
                RData::A(A([192, 0, 2, 1].into())),
            )]),
        }]));

        let error = NetError::from(norecs);

        let cache = ResponseCache::new(1, TtlConfig::default());
        cache.insert(query.clone(), Err(error), now);

        let cache_err = cache.get(&query, now).unwrap().unwrap_err();
        let NetError::Dns(DnsError::NoRecordsFound(no_records)) = &cache_err else {
            panic!("expected NoRecordsFound");
        };

        let Some(soa) = no_records.soa.clone() else {
            panic!("no SOA in NoRecordsFound");
        };
        assert_eq!(soa.ttl(), 10);

        let cache_err = cache
            .get(&query, now + Duration::from_secs(2))
            .unwrap()
            .unwrap_err();
        let NetError::Dns(DnsError::NoRecordsFound(NoRecords {
            negative_ttl: Some(negative_ttl),
            soa: Some(soa),
            authorities: Some(authorities),
            ns: Some(ns),
            ..
        })) = &cache_err
        else {
            panic!("expected NoRecordsFound with negative_ttl, soa, authorities, and ns");
        };

        assert_eq!(*negative_ttl, 8);
        assert_eq!(soa.ttl(), 8);
        assert_eq!(authorities[0].ttl(), 8);
        assert_eq!(ns[0].ns.ttl(), 8);

        // Cache should be expired
        assert!(cache.get(&query, now + Duration::from_secs(11)).is_none());
        Ok(())
    }

    #[test]
    fn test_insert_ttl() {
        let now = Instant::now();

        let name = Name::from_str("www.example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);

        // TTL of entry should be 1.
        let mut message = Message::response(0, OpCode::Query);
        message.add_answer(Record::from_rdata(
            name.clone(),
            1,
            RData::A(A::new(127, 0, 0, 1)),
        ));
        message.add_answer(Record::from_rdata(name, 2, RData::A(A::new(127, 0, 0, 2))));

        let cache = ResponseCache::new(1, TtlConfig::default());
        cache.insert(query.clone(), Ok(message), now);

        // Entry is still valid.
        cache
            .get(&query, now + Duration::from_secs(1))
            .unwrap()
            .unwrap();

        // Entry is expired.
        let option = cache.get(&query, now + Duration::from_secs(2));
        assert!(option.is_none());
    }

    #[test]
    fn test_ttl_different_query_types() {
        let now = Instant::now();
        let name = Name::from_str("www.example.com.").unwrap();

        // Store records with a TTL of 1 second.
        let query_a = Query::query(name.clone(), RecordType::A);
        let rdata_a = RData::A(A::new(127, 0, 0, 1));
        let mut message_a = Message::response(0, OpCode::Query);
        message_a.add_answer(Record::from_rdata(name.clone(), 1, rdata_a.clone()));

        let query_txt = Query::query(name.clone(), RecordType::TXT);
        let rdata_txt = RData::TXT(TXT::new(vec!["data".to_string()]));
        let mut message_txt = Message::response(0, OpCode::Query);
        message_txt.add_answer(Record::from_rdata(name.clone(), 1, rdata_txt.clone()));

        // Set separate positive_min_ttl limits for TXT queries and all others.
        let mut ttl_config = TtlConfig::from(TtlBounds {
            positive_min_ttl: Some(Duration::from_secs(2)),
            ..TtlBounds::default()
        });
        ttl_config.with_query_type_ttl_bounds(
            RecordType::TXT,
            TtlBounds {
                positive_min_ttl: Some(Duration::from_secs(5)),
                ..TtlBounds::default()
            },
        );
        let cache = ResponseCache::new(2, ttl_config);

        cache.insert(query_a.clone(), Ok(message_a), now);
        // This should use the cache's default minimum TTL, since the record's TTL was below the
        // minimum.
        assert_eq!(
            cache.cache.get(&query_a).unwrap().valid_until,
            now + Duration::from_secs(2)
        );

        cache.insert(query_txt.clone(), Ok(message_txt), now);
        // This should use the minimum for TTL records, since the record's TTL was below the
        // minimum.
        assert_eq!(
            cache.cache.get(&query_txt).unwrap().valid_until,
            now + Duration::from_secs(5)
        );

        // store records with a TTL of 7 seconds.
        let mut message_a = Message::response(0, OpCode::Query);
        message_a.add_answer(Record::from_rdata(name.clone(), 7, rdata_a));

        let mut message_txt = Message::response(0, OpCode::Query);
        message_txt.add_answer(Record::from_rdata(name.clone(), 7, rdata_txt));

        cache.insert(query_a.clone(), Ok(message_a), now);
        // This should use the record's TTL, since it's greater than the default minimum TTL.
        assert_eq!(
            cache.cache.get(&query_a).unwrap().valid_until,
            now + Duration::from_secs(7)
        );

        cache.insert(query_txt.clone(), Ok(message_txt), now);
        // This should use the record's TTL, since it's greater than the minimum TTL for TXT records.
        assert_eq!(
            cache.cache.get(&query_txt).unwrap().valid_until,
            now + Duration::from_secs(7)
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn ttl_config_deserialize_errors() {
        // Duplicate of "default"
        let input = r#"[default]
positive_max_ttl = 3600
[default]
positive_max_ttl = 3599"#;
        let error = toml::from_str::<TtlConfig>(input).unwrap_err();
        assert!(
            error.message().contains("duplicate key"),
            "wrong error message: {error}"
        );

        // Duplicate of a record type
        let input = r#"[default]
positive_max_ttl = 86400
[OPENPGPKEY]
positive_max_ttl = 3600
[OPENPGPKEY]
negative_min_ttl = 60"#;
        let error = toml::from_str::<TtlConfig>(input).unwrap_err();
        assert!(
            error.message().contains("duplicate key"),
            "wrong error message: {error}"
        );

        // Neither "default" nor a record type
        let input = r#"[not_a_record_type]
positive_max_ttl = 3600"#;
        let error = toml::from_str::<TtlConfig>(input).unwrap_err();
        assert!(
            error.message().contains("data did not match any variant"),
            "wrong error message: {error}"
        );

        // Array instead of table
        #[derive(Debug, Deserialize)]
        struct Wrapper {
            #[allow(unused)]
            cache_policy: TtlConfig,
        }
        let input = r#"cache_policy = []"#;
        let error = toml::from_str::<Wrapper>(input).unwrap_err();
        assert!(
            error.message().contains("invalid type: sequence"),
            "wrong error message: {error}"
        );

        // String instead of table
        let input = r#"cache_policy = "yes""#;
        let error = toml::from_str::<Wrapper>(input).unwrap_err();
        assert!(
            error.message().contains("invalid type: string"),
            "wrong error message: {error}"
        );
    }
}
