// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Caching related functionality for the Resolver.

use std::io;
use std::mem;
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant};

use futures::{Async, Future, Poll, task};

use trust_dns::client::ClientHandle;
use trust_dns::error::ClientError;
use trust_dns::op::{Query, Message};
use trust_dns::rr::RData;

use lookup::Lookup;
use lru_cache::LruCache;

/// Maximum TTL as defined in https://tools.ietf.org/html/rfc2181
const MAX_TTL: u32 = 2147483647_u32;

#[derive(Debug)]
struct LruValue {
    lookup: Lookup,
    ttl_until: Instant,
}

impl LruValue {
    /// Returns true if this set of ips is still valid
    fn is_current(&self, now: Instant) -> bool {
        now <= self.ttl_until
    }
}

// TODO: need to consider this storage type as it compares to Authority in server...
//       should it just be an variation on Authority?
#[derive(Clone, Debug)]
pub(crate) struct DnsLru<C: ClientHandle> {
    lru: Arc<Mutex<LruCache<Query, LruValue>>>,
    client: C,
}

impl<C: ClientHandle + 'static> DnsLru<C> {
    pub(crate) fn new(max_size: usize, client: C) -> Self {
        DnsLru {
            lru: Arc::new(Mutex::new(LruCache::new(max_size))),
            client,
        }
    }

    pub fn lookup(&mut self, query: Query) -> Box<Future<Item = Lookup, Error = io::Error>> {
        Box::new(QueryState::lookup(
            query,
            &mut self.client,
            self.lru.clone(),
        ))
    }
}

// TODO: need to consider NXDomain storage...
fn insert(
    lru: &mut LruCache<Query, LruValue>,
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
    lru.insert(
        query,
        LruValue {
            lookup: lookup.clone(),
            ttl_until,
        },
    );

    lookup
}

/// This needs to be mut b/c it's an LRU, meaning the ordering of elements will potentially change on retrieval...
fn get(lru: &mut LruCache<Query, LruValue>, query: &Query, now: Instant) -> Option<Lookup> {
    let lookup = lru.get_mut(query).and_then(
        |value| if value.is_current(now) {
            Some(value.lookup.clone())
        } else {
            None
        },
    );

    // in this case, we can preemtively remove out of data elements
    // this assumes time is always moving forward, this would only not be true in contrived situations where now
    //  is not current time, like tests...
    if lookup.is_none() {
        lru.remove(query);
    }

    lookup
}

struct FromCache {
    query: Query,
    cache: Arc<Mutex<LruCache<Query, LruValue>>>,
}

impl Future for FromCache {
    type Item = Option<Lookup>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // first transition any polling that is needed (mutable refs...)
        match self.cache.try_lock() {
            Err(TryLockError::WouldBlock) => {
                task::current().notify(); // yield
                return Ok(Async::NotReady);
            }
            // TODO: need to figure out a way to recover from this.
            // It requires unwrapping the poisoned error and recreating the Mutex at a higher layer...
            Err(TryLockError::Poisoned(poison)) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("poisoned: {}", poison),
            )),
            Ok(mut lru) => {
                return Ok(Async::Ready(get(&mut lru, &self.query, Instant::now())));
            }
        }
    }
}

/// This is the Future responsible for performing an actual query.
struct QueryFuture {
    message_future: Box<Future<Item = Message, Error = ClientError>>,
    query: Query,
    cache: Arc<Mutex<LruCache<Query, LruValue>>>,
}

impl Future for QueryFuture {
    type Item = Vec<(RData, u32)>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.message_future.poll() {
            Ok(Async::Ready(mut message)) => {
                let records = message
                // TODO: consider taking other responses?
                    .take_answers()
                    .into_iter()
                    .filter_map(|r| {
                        let ttl = r.ttl();
                        // TODO: validate names in response?
                        // restrict to the RData type requested
                        if self.query.query_type() == r.rr_type() {
                            Some((r.unwrap_rdata(), ttl))
                        } else {
                            None
                        }
                    })
                    .collect();

                Ok(Async::Ready(records))
            }
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(err) => Err(err.into()),
        }
    }
}

struct InsertCache {
    rdatas: Vec<(RData, u32)>,
    query: Query,
    cache: Arc<Mutex<LruCache<Query, LruValue>>>,
}

impl Future for InsertCache {
    type Item = Lookup;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // first transition any polling that is needed (mutable refs...)
        match self.cache.try_lock() {
            Err(TryLockError::WouldBlock) => {
                task::current().notify(); // yield
                return Ok(Async::NotReady);
            }
            // TODO: need to figure out a way to recover from this.
            // It requires unwrapping the poisoned error and recreating the Mutex at a higher layer...
            Err(TryLockError::Poisoned(poison)) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("poisoned: {}", poison),
            )),
            Ok(mut lru) => {
                // this will put this object into an inconsistent state, but no one should call poll again...
                let query = mem::replace(&mut self.query, Query::new());
                let rdata = mem::replace(&mut self.rdatas, vec![]);

                return Ok(Async::Ready(
                    insert(&mut *lru, query, rdata, Instant::now()),
                ));
            }
        }
    }
}

enum QueryState<C: ClientHandle + 'static> {
    /// In the FromCache state we evaluate cache entries for any results
    FromCache(FromCache, C),
    /// In the query state there is an active query that's been started, see Self::lookup()
    Query(QueryFuture),
    /// State of adding the item to the cache
    InsertCache(InsertCache),
    /// A state which should not occur
    Error,
}

impl<C: ClientHandle + 'static> QueryState<C> {
    pub(crate) fn lookup(
        query: Query,
        client: &mut C,
        cache: Arc<Mutex<LruCache<Query, LruValue>>>,
    ) -> QueryState<C> {
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
                let query = from_cache.query;
                let message_future = client.lookup(query.clone());
                mem::replace(
                    self,
                    QueryState::Query(QueryFuture {
                        message_future,
                        query,
                        cache: from_cache.cache,
                    }),
                );
            }
            _ => panic!("bad state, expected FromCache"),
        }
    }

    fn cache(&mut self, rdatas: Vec<(RData, u32)>) {
        // The error state, this query is complete...
        let query_state = mem::replace(self, QueryState::Error);

        match query_state {
            QueryState::Query(QueryFuture {
                                  message_future: _,
                                  query,
                                  cache,
                              }) => {
                mem::replace(
                    self,
                    QueryState::InsertCache(InsertCache {
                        rdatas,
                        query,
                        cache,
                    }),
                );
            }
            _ => panic!("bad state, expected Query"),
        }
    }
}

impl<C: ClientHandle + 'static> Future for QueryState<C> {
    type Item = Lookup;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // first transition any polling that is needed (mutable refs...)
        let poll;
        match *self {
            QueryState::FromCache(ref mut from_cache, ..) => {
                match from_cache.poll() {
                    // need to query since it wasn't in the cache
                    Ok(Async::Ready(None)) => (), // handled below
                    Ok(Async::Ready(Some(ips))) => return Ok(Async::Ready(ips)),
                    Ok(Async::NotReady) => return Ok(Async::NotReady),
                    Err(error) => return Err(error),
                };

                poll = Ok(Async::NotReady);
            }
            QueryState::Query(ref mut query, ..) => {
                poll = query.poll().map_err(|e| e.into());
                match poll {
                    Ok(Async::NotReady) => {
                        return Ok(Async::NotReady);
                    }
                    Ok(Async::Ready(_)) => (), // handled in next match
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            QueryState::InsertCache(ref mut insert_cache) => {
                return insert_cache.poll();
                // match insert_cache.poll() {
                //     // need to query since it wasn't in the cache
                //     Ok(Async::Ready(ips)) => return Ok(Async::Ready(ips)),
                //     Ok(Async::NotReady) => return Ok(Async::NotReady),
                //     Err(error) => return Err(error),
                // }
            }
            QueryState::Error => panic!("invalid error state"),
        }

        // getting here means there are Aync::Ready available.
        match *self {
            QueryState::FromCache(..) => self.query_after_cache(),
            QueryState::Query(..) => {
                match poll {
                    Ok(Async::Ready(rdatas)) => {
                        self.cache(rdatas);
                    }
                    _ => panic!("should have returned earlier"),
                }
            }
            _ => panic!("should have returned earlier"),            
        }

        task::current().notify(); // yield
        return Ok(Async::NotReady);
    }
}

#[cfg(test)]
mod tests {
    use std::net::*;
    use std::str::FromStr;
    use std::time::*;

    use lru_cache::LruCache;
    use trust_dns::op::Query;
    use trust_dns::rr::{Name, RecordType};

    use super::*;
    use lookup_ip::tests::*;

    #[test]
    fn test_is_current() {
        let now = Instant::now();
        let not_the_future = now + Duration::from_secs(4);
        let future = now + Duration::from_secs(5);
        let past_the_future = now + Duration::from_secs(6);

        let value = LruValue {
            lookup: Lookup::new(Arc::new(vec![])),
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
        let mut lru = LruCache::new(1);

        let rc_ips = insert(&mut lru, name.clone(), ips_ttl, now);
        assert_eq!(*rc_ips.iter().next().unwrap(), ips[0]);

        let rc_ips = get(&mut lru, &name, now).unwrap();
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
        let mut lru = LruCache::new(1);

        insert(&mut lru, name.clone(), ips_ttl, now);

        // still valid
        let rc_ips = get(&mut lru, &name, now + Duration::from_secs(1)).unwrap();
        assert_eq!(*rc_ips.iter().next().unwrap(), ips[0]);

        // 2 should be one too far
        let rc_ips = get(&mut lru, &name, now + Duration::from_secs(2));
        assert!(rc_ips.is_none());
    }

    #[test]
    fn test_empty_cache() {
        let cache = Arc::new(Mutex::new(LruCache::new(1)));
        let mut client = mock(vec![empty()]);

        let ips = QueryState::lookup(Query::new(), &mut client, cache)
            .wait()
            .unwrap();

        assert!(ips.iter().next().is_none());
    }

    #[test]
    fn test_from_cache() {
        let cache = Arc::new(Mutex::new(LruCache::new(1)));
        insert(
            &mut cache.lock().unwrap(),
            Query::new(),
            vec![
                (RData::A(Ipv4Addr::new(127, 0, 0, 1)), u32::max_value()),
            ],
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
        let cache = Arc::new(Mutex::new(LruCache::new(1)));
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