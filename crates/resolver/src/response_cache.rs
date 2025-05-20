//! A cache for DNS responses.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use moka::{Expiry, sync::Cache};

use crate::dns_lru::TtlConfig;
use crate::proto::{
    NoRecords, ProtoError, ProtoErrorKind,
    op::{Message, Query},
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
    pub fn insert(&self, query: Query, result: Result<Message, ProtoError>, now: Instant) {
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
            Err(e) => {
                let ProtoErrorKind::NoRecordsFound(no_records) = e.kind() else {
                    return;
                };
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
    pub fn get(&self, query: &Query, now: Instant) -> Option<Result<Message, ProtoError>> {
        let entry = self.cache.get(query)?;
        if !entry.is_current(now) {
            return None;
        }
        Some(entry.updated_ttl(now))
    }
}

/// An entry in the response cache.
///
/// This contains the response itself (or an error), the time it was received, and the time at which
/// it expires.
#[derive(Debug, Clone)]
struct Entry {
    result: Arc<Result<Message, ProtoError>>,
    original_time: Instant,
    valid_until: Instant,
}

impl Entry {
    /// Return the `Result` stored in this entry, with modified TTLs, subtracting the elapsed time
    /// since the response was received.
    fn updated_ttl(&self, now: Instant) -> Result<Message, ProtoError> {
        let elapsed = u32::try_from(now.saturating_duration_since(self.original_time).as_secs())
            .unwrap_or(u32::MAX);
        match &*self.result {
            Ok(response) => {
                let mut response = response.clone();
                for section_fn in [
                    Message::answers_mut,
                    Message::name_servers_mut,
                    Message::additionals_mut,
                ] {
                    for record in section_fn(&mut response) {
                        record.set_ttl(record.ttl().saturating_sub(elapsed));
                    }
                }
                Ok(response)
            }
            Err(e) => {
                let mut e = e.clone();
                if let ProtoErrorKind::NoRecordsFound(NoRecords {
                    negative_ttl: Some(ttl),
                    ..
                }) = e.kind.as_mut()
                {
                    *ttl = ttl.saturating_sub(elapsed);
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

#[cfg(test)]
mod tests {
    use std::{
        str::FromStr,
        time::{Duration, Instant},
    };

    use crate::{
        dns_lru::TtlConfig,
        proto::{
            NoRecords, ProtoErrorKind,
            op::{Message, OpCode, Query, ResponseCode},
            rr::{
                Name, RData, Record, RecordType,
                rdata::{A, TXT},
            },
        },
        response_cache::{Entry, ResponseCache},
    };

    #[test]
    fn test_is_current() {
        let now = Instant::now();
        let not_the_future = now + Duration::from_secs(4);
        let future = now + Duration::from_secs(5);
        let past_the_future = now + Duration::from_secs(6);

        let entry = Entry {
            result: Err(ProtoErrorKind::Message("test error").into()).into(),
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
        let ttls = TtlConfig::new(Some(Duration::from_secs(2)), None, None, None);
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
        let ttls = TtlConfig::new(None, Some(Duration::from_secs(2)), None, None);
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
        let ttls = TtlConfig::new(None, None, Some(Duration::from_secs(60)), None);
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
        let ttls = TtlConfig::new(None, None, None, Some(Duration::from_secs(60)));
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
        let mut ttl_config = TtlConfig::new(Some(Duration::from_secs(2)), None, None, None);
        ttl_config.with_query_type_ttl_bounds(
            RecordType::TXT,
            Some(Duration::from_secs(5)),
            None,
            None,
            None,
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
}
