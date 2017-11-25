// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Caching related functionality for the Resolver.

use std::borrow::Cow;
use std::cell::RefCell;
use std::mem;
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant};

use futures::{task, Async, Future, Poll};

use trust_dns_proto::DnsHandle;
use trust_dns_proto::op::{Message, Query, ResponseCode};
use trust_dns_proto::rr::{RData, RecordType};

use error::*;
use lookup::Lookup;
use lru_cache::LruCache;

/// Maximum TTL as defined in https://tools.ietf.org/html/rfc2181
const MAX_TTL: u32 = 2147483647_u32;
const MAX_QUERY_DEPTH: u8 = 8; // arbitrarily chosen number...

thread_local! {
    static QUERY_DEPTH: RefCell<u8> = RefCell::new(0);
}

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

    fn insert(&mut self, query: Query, rdatas_and_ttl: Vec<(RData, u32)>, now: Instant) -> Lookup {
        let len = rdatas_and_ttl.len();
        // collapse the values, we're going to take the Minimum TTL as the correct one
        let (rdatas, ttl): (Vec<RData>, u32) = rdatas_and_ttl.into_iter().fold(
            (Vec::with_capacity(len), MAX_TTL),
            |(mut rdatas, mut min_ttl), (rdata, ttl)| {
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

    fn duplicate(&mut self, query: Query, lookup: Lookup, ttl: u32, now: Instant) -> Lookup {
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

    fn nx_error(query: Query) -> ResolveError {
        ResolveErrorKind::NoRecordsFound(query).into()
    }

    fn negative(&mut self, query: Query, ttl: u32, now: Instant) -> ResolveError {
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
    fn get(&mut self, query: &Query, now: Instant) -> Option<Lookup> {
        let mut out_of_date = false;
        let lookup = self.0.get_mut(query).and_then(|value| {
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
            self.0.remove(query);
        }

        lookup
    }
}

// TODO: need to consider this storage type as it compares to Authority in server...
//       should it just be an variation on Authority?
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct CachingClient<C: DnsHandle<Error = ResolveError>> {
    // TODO: switch to FuturesMutex (Mutex will have some undesireable locking)
    lru: Arc<Mutex<DnsLru>>,
    client: C,
}

impl<C: DnsHandle<Error = ResolveError> + 'static> CachingClient<C> {
    #[doc(hidden)]
    pub fn new(max_size: usize, client: C) -> Self {
        Self::with_cache(Arc::new(Mutex::new(DnsLru::new(max_size))), client)
    }

    pub(crate) fn with_cache(lru: Arc<Mutex<DnsLru>>, client: C) -> Self {
        CachingClient { lru, client }
    }

    /// Perform a lookup against this caching client, looking first in the cache for a result
    pub fn lookup(&mut self, query: Query) -> Box<Future<Item = Lookup, Error = ResolveError>> {
        QUERY_DEPTH.with(|c| *c.borrow_mut() += 1);

        Box::new(
            QueryState::lookup(query, &mut self.client, self.lru.clone()).then(|f| {
                QUERY_DEPTH.with(|c| *c.borrow_mut() -= 1);
                f
            }),
        )
    }
}

struct FromCache {
    query: Query,
    cache: Arc<Mutex<DnsLru>>,
}

impl Future for FromCache {
    type Item = Option<Lookup>;
    type Error = ResolveError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // first transition any polling that is needed (mutable refs...)
        match self.cache.try_lock() {
            Err(TryLockError::WouldBlock) => {
                task::current().notify(); // yield
                return Ok(Async::NotReady);
            }
            // TODO: need to figure out a way to recover from this.
            // It requires unwrapping the poisoned error and recreating the Mutex at a higher layer...
            Err(TryLockError::Poisoned(poison)) => {
                Err(ResolveErrorKind::Msg(format!("poisoned: {}", poison)).into())
            }
            Ok(mut lru) => {
                return Ok(Async::Ready(lru.get(&self.query, Instant::now())));
            }
        }
    }
}

/// This is the Future responsible for performing an actual query.
struct QueryFuture<C: DnsHandle<Error = ResolveError> + 'static> {
    message_future: Box<Future<Item = Message, Error = ResolveError>>,
    query: Query,
    cache: Arc<Mutex<DnsLru>>,
    /// is this a DNSSec validating client?
    dnssec: bool,
    client: CachingClient<C>,
}

enum Records {
    /// The records exists, a vec of rdata with ttl
    Exists(Vec<(RData, u32)>),
    /// Records do not exist, ttl for negative caching
    NoData(Option<u32>),
    /// Future lookup for recursive cname records
    CnameChain(Box<Future<Item = Lookup, Error = ResolveError>>, u32),
    /// Already cached, chained queries
    Chained(Lookup, u32),
}

impl<C: DnsHandle<Error = ResolveError> + 'static> QueryFuture<C> {
    fn next_query(&mut self, query: Query, cname_ttl: u32, message: Message) -> Records {
        if QUERY_DEPTH.with(|c| *c.borrow() >= MAX_QUERY_DEPTH) {
            // TODO: This should return an error
            self.handle_nxdomain(message, true)
        } else {
            Records::CnameChain(self.client.lookup(query), cname_ttl)
        }
    }

    fn handle_noerror(&mut self, mut message: Message) -> Poll<Records, ResolveError> {
        // seek out CNAMES
        let (search_name, cname_ttl, was_cname) = {
            let (search_name, cname_ttl, was_cname) = message.answers().iter().fold(
                (Cow::Borrowed(self.query.name()), 0, false),
                |(search_name, cname_ttl, was_cname), r| {
                    if let &RData::CNAME(ref cname) = r.rdata() {
                        debug_assert_eq!(r.rr_type(), RecordType::CNAME);
                        if search_name.as_ref() == r.name() {
                            return (Cow::Owned(cname.clone()), r.ttl(), true);
                        }
                    }
                    (search_name, cname_ttl, was_cname)
                },
            );

            // After following all the CNAMES to the last one, try and lookup the final name
            let records = message
                .take_answers()
                .into_iter()
                .chain(message.take_additionals().into_iter())
                .filter_map(|r| {
                    let ttl = r.ttl();
                    // TODO: disable name validation with ResolverOpts?
                    // restrict to the RData type requested
                    if self.query.query_type() == r.rr_type() && search_name.as_ref() == r.name() {
                        Some((r.unwrap_rdata(), ttl))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();

            if !records.is_empty() {
                return Ok(Async::Ready(Records::Exists(records)));
            }

            (search_name.into_owned(), cname_ttl, was_cname)
        };

        // It was a CNAME, but not included in the request...
        if was_cname {
            let next_query = Query::query(search_name, self.query.query_type());
            Ok(Async::Ready(
                self.next_query(next_query, cname_ttl, message),
            ))
        } else {
            // TODO: review See https://tools.ietf.org/html/rfc2308 for NoData section
            // Note on DNSSec, in secure_client_hanle, if verify_nsec fails then the request fails.
            //   this will mean that no unverified negative caches will make it to this point and be stored
            Ok(Async::Ready(self.handle_nxdomain(message, true)))
        }
    }

    /// See https://tools.ietf.org/html/rfc2308
    ///
    /// For now we will regard NXDomain to strictly mean the query failed
    ///  and a record for the name, regardless of CNAME presence, what have you
    ///  ultimately does not exist.
    ///
    /// This also handles empty responses in the same way. When performing DNSSec enabled queries, we should
    ///  never enter here, and should never cache unless verified requests.
    ///
    /// # Arguments
    ///
    /// * `message` - message to extract SOA, etc, from for caching failed requests
    /// * `valid_nsec` - species that in DNSSec mode, this request is safe to cache
    fn handle_nxdomain(&self, mut message: Message, valid_nsec: bool) -> Records {
        if valid_nsec || !self.dnssec {
            //  if there were validated NSEC records
            let soa = message
                .take_name_servers()
                .into_iter()
                .find(|r| r.rr_type() == RecordType::SOA);

            let ttl = if let Some(RData::SOA(soa)) = soa.map(|r| r.unwrap_rdata()) {
                Some(soa.minimum())
            } else {
                // TODO: figure out a looping lookup to get SOA
                None
            };

            Records::NoData(ttl)
        } else {
            Records::NoData(None)
        }
    }
}

impl<C: DnsHandle<Error = ResolveError> + 'static> Future for QueryFuture<C> {
    type Item = Records;
    type Error = ResolveError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.message_future.poll() {
            Ok(Async::Ready(message)) => {
                // TODO: take all records and cache them?
                //  if it's DNSSec they must be signed, otherwise?

                match message.response_code() {
                    ResponseCode::NXDomain => Ok(Async::Ready(self.handle_nxdomain(
                        message,
                        false, /* false b/c DNSSec should not cache NXDomain */
                    ))),
                    ResponseCode::NoError => self.handle_noerror(message),
                    r @ _ => Err(ResolveErrorKind::Msg(format!("DNS Error: {}", r)).into()),
                }
            }
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(err) => Err(err.into()),
        }
    }
}

struct InsertCache {
    rdatas: Records,
    query: Query,
    cache: Arc<Mutex<DnsLru>>,
}

impl Future for InsertCache {
    type Item = Lookup;
    type Error = ResolveError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // first transition any polling that is needed (mutable refs...)
        match self.cache.try_lock() {
            Err(TryLockError::WouldBlock) => {
                task::current().notify(); // yield
                return Ok(Async::NotReady);
            }
            // TODO: need to figure out a way to recover from this.
            // It requires unwrapping the poisoned error and recreating the Mutex at a higher layer...
            Err(TryLockError::Poisoned(poison)) => {
                Err(ResolveErrorKind::Msg(format!("poisoned: {}", poison)).into())
            }
            Ok(mut lru) => {
                // this will put this object into an inconsistent state, but no one should call poll again...
                let query = mem::replace(&mut self.query, Query::new());
                let rdata = mem::replace(&mut self.rdatas, Records::NoData(None));

                match rdata {
                    Records::Exists(rdata) => {
                        Ok(Async::Ready(lru.insert(query, rdata, Instant::now())))
                    }
                    Records::Chained(lookup, ttl) => Ok(Async::Ready(
                        lru.duplicate(query, lookup, ttl, Instant::now()),
                    )),
                    Records::NoData(Some(ttl)) => Err(lru.negative(query, ttl, Instant::now())),
                    Records::NoData(None) | Records::CnameChain(..) => Err(DnsLru::nx_error(query)),
                }
            }
        }
    }
}

enum QueryState<C: DnsHandle<Error = ResolveError> + 'static> {
    /// In the FromCache state we evaluate cache entries for any results
    FromCache(FromCache, C),
    /// In the query state there is an active query that's been started, see Self::lookup()
    Query(QueryFuture<C>),
    /// CNAME lookup (internally it is making cached queries
    CnameChain(
        Box<Future<Item = Lookup, Error = ResolveError>>,
        Query,
        u32,
        Arc<Mutex<DnsLru>>,
    ),
    /// State of adding the item to the cache
    InsertCache(InsertCache),
    /// A state which should not occur
    Error,
}

impl<C: DnsHandle<Error = ResolveError> + 'static> QueryState<C> {
    pub(crate) fn lookup(query: Query, client: &mut C, cache: Arc<Mutex<DnsLru>>) -> QueryState<C> {
        QueryState::FromCache(FromCache { query, cache }, client.clone())
    }

    /// Query after a failed cache lookup
    ///
    /// # Panics
    ///
    /// This will panic if the current state is not FromCache.
    fn query_after_cache(&mut self) {
        let from_cache_state = mem::replace(self, QueryState::Error);

        // TODO: with specialization, could we define a custom query only on the FromCache type?
        match from_cache_state {
            QueryState::FromCache(from_cache, mut client) => {
                let cache = from_cache.cache;
                let query = from_cache.query;
                let message_future = client.lookup(query.clone());
                mem::replace(
                    self,
                    QueryState::Query(QueryFuture {
                        message_future,
                        query,
                        cache: cache.clone(),
                        dnssec: client.is_verifying_dnssec(),
                        client: CachingClient::with_cache(cache, client),
                    }),
                );
            }
            _ => panic!("bad state, expected FromCache"),
        }
    }

    fn cname(&mut self, future: Box<Future<Item = Lookup, Error = ResolveError>>, cname_ttl: u32) {
        // The error state, this query is complete...
        let query_state = mem::replace(self, QueryState::Error);

        match query_state {
            QueryState::Query(QueryFuture {
                message_future: _,
                query,
                cache,
                dnssec: _,
                client: _,
            }) => {
                mem::replace(
                    self,
                    QueryState::CnameChain(future, query, cname_ttl, cache),
                );
            }
            _ => panic!("bad state, expected Query"),
        }
    }

    fn cache(&mut self, rdatas: Records) {
        // The error state, this query is complete...
        let query_state = mem::replace(self, QueryState::Error);

        match query_state {
            QueryState::Query(QueryFuture {
                message_future: _,
                query,
                cache,
                dnssec: _,
                client: _,
            }) => {
                match rdatas {
                    // There are Cnames to lookup
                    Records::CnameChain(..) => {
                        panic!("CnameChain should have been polled in poll() of QueryState");
                    }
                    rdatas @ _ => {
                        mem::replace(
                            self,
                            QueryState::InsertCache(InsertCache {
                                rdatas,
                                query,
                                cache,
                            }),
                        );
                    }
                }
            }
            QueryState::CnameChain(_, query, _, cache) => {
                match rdatas {
                    // There are Cnames to lookup
                    Records::CnameChain(..) => {
                        panic!("CnameChain should have been polled in poll() of QueryState");
                    }
                    rdatas @ _ => {
                        mem::replace(
                            self,
                            QueryState::InsertCache(InsertCache {
                                rdatas,
                                query,
                                cache,
                            }),
                        );
                    }
                }
            }
            _ => panic!("bad state, expected Query"),
        }
    }
}

impl<C: DnsHandle<Error = ResolveError> + 'static> Future for QueryState<C> {
    type Item = Lookup;
    type Error = ResolveError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // first transition any polling that is needed (mutable refs...)
        let records: Option<Records>;
        match *self {
            QueryState::FromCache(ref mut from_cache, ..) => {
                match from_cache.poll() {
                    // need to query since it wasn't in the cache
                    Ok(Async::Ready(None)) => (), // handled below
                    Ok(Async::Ready(Some(ips))) => return Ok(Async::Ready(ips)),
                    Ok(Async::NotReady) => return Ok(Async::NotReady),
                    Err(error) => return Err(error),
                };

                records = None;
            }
            QueryState::Query(ref mut query, ..) => {
                let poll = query.poll().map_err(|e| e.into());
                match poll {
                    Ok(Async::NotReady) => {
                        return Ok(Async::NotReady);
                    }
                    Ok(Async::Ready(rdatas)) => records = Some(rdatas), // handled in next match
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            QueryState::CnameChain(ref mut future, _, ttl, _) => {
                let poll = future.poll();
                match poll {
                    Ok(Async::NotReady) => {
                        return Ok(Async::NotReady);
                    }
                    Ok(Async::Ready(lookup)) => {
                        records = Some(Records::Chained(lookup, ttl));
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            QueryState::InsertCache(ref mut insert_cache) => {
                return insert_cache.poll();
            }
            QueryState::Error => panic!("invalid error state"),
        }

        // getting here means there are Aync::Ready available.
        match *self {
            QueryState::FromCache(..) => self.query_after_cache(),
            QueryState::Query(..) => match records {
                Some(Records::CnameChain(future, ttl)) => self.cname(future, ttl),
                Some(records) => {
                    self.cache(records);
                }
                None => panic!("should have returned earlier"),
            },
            QueryState::CnameChain(..) => match records {
                Some(records) => self.cache(records),
                None => panic!("should have returned earlier"),
            },
            QueryState::InsertCache(..) | QueryState::Error => {
                panic!("should have returned earlier")
            }
        }

        task::current().notify(); // yield
        return Ok(Async::NotReady);
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

    #[test]
    fn test_empty_cache() {
        let cache = Arc::new(Mutex::new(DnsLru::new(1)));
        let mut client = mock(vec![empty()]);

        assert_eq!(
            QueryState::lookup(Query::new(), &mut client, cache)
                .wait()
                .unwrap_err()
                .kind(),
            &ResolveErrorKind::NoRecordsFound(Query::new())
        );
    }

    #[test]
    fn test_from_cache() {
        let cache = Arc::new(Mutex::new(DnsLru::new(1)));
        cache.lock().unwrap().insert(
            Query::new(),
            vec![(RData::A(Ipv4Addr::new(127, 0, 0, 1)), u32::max_value())],
            Instant::now(),
        );

        let mut client = mock(vec![empty()]);

        let ips = QueryState::lookup(Query::new(), &mut client, cache)
            .wait()
            .unwrap();

        assert_eq!(
            ips.iter().cloned().collect::<Vec<_>>(),
            vec![RData::A(Ipv4Addr::new(127, 0, 0, 1))]
        );
    }

    #[test]
    fn test_no_cache_insert() {
        let cache = Arc::new(Mutex::new(DnsLru::new(1)));
        // first should come from client...
        let mut client = mock(vec![v4_message()]);

        let ips = QueryState::lookup(Query::new(), &mut client, cache.clone())
            .wait()
            .unwrap();

        assert_eq!(
            ips.iter().cloned().collect::<Vec<_>>(),
            vec![RData::A(Ipv4Addr::new(127, 0, 0, 1))]
        );

        // next should come from cache...
        let mut client = mock(vec![empty()]);

        let ips = QueryState::lookup(Query::new(), &mut client, cache)
            .wait()
            .unwrap();

        assert_eq!(
            ips.iter().cloned().collect::<Vec<_>>(),
            vec![RData::A(Ipv4Addr::new(127, 0, 0, 1))]
        );
    }
}
