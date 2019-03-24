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
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::Instant;

use futures::{future, task, Async, Future, Poll};

use proto::op::{Message, Query, ResponseCode};
use proto::rr::domain::usage::{
    ResolverUsage, DEFAULT, INVALID, IN_ADDR_ARPA_127, IP6_ARPA_1, LOCAL,
    LOCALHOST as LOCALHOST_usage,
};
use proto::rr::{DNSClass, Name, RData, Record, RecordType};
use proto::xfer::{DnsHandle, DnsRequestOptions, DnsResponse};

use dns_lru;
use dns_lru::DnsLru;
use error::*;
use lookup::Lookup;

const MAX_QUERY_DEPTH: u8 = 7; // arbitrarily chosen number...

task_local! {
    static QUERY_DEPTH: RefCell<u8> = RefCell::new(0)
}

lazy_static! {
    static ref LOCALHOST: RData = RData::PTR(Name::from_ascii("localhost.").unwrap());
    static ref LOCALHOST_V4: RData = RData::A(Ipv4Addr::new(127, 0, 0, 1));
    static ref LOCALHOST_V6: RData = RData::AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
}

// TODO: need to consider this storage type as it compares to Authority in server...
//       should it just be an variation on Authority?
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct CachingClient<C: DnsHandle> {
    // TODO: switch to FuturesMutex (Mutex will have some undesireable locking)
    lru: Arc<Mutex<DnsLru>>,
    client: C,
}

impl<C: DnsHandle + 'static> CachingClient<C> {
    #[doc(hidden)]
    pub fn new(max_size: usize, client: C) -> Self {
        Self::with_cache(
            Arc::new(Mutex::new(DnsLru::new(max_size, Default::default()))),
            client,
        )
    }

    pub(crate) fn with_cache(lru: Arc<Mutex<DnsLru>>, client: C) -> Self {
        CachingClient { lru, client }
    }

    /// Perform a lookup against this caching client, looking first in the cache for a result
    pub fn lookup(
        &mut self,
        query: Query,
        options: DnsRequestOptions,
    ) -> Box<Future<Item = Lookup, Error = ResolveError> + Send> {
        // see https://tools.ietf.org/html/rfc6761
        //
        // ```text
        // Name resolution APIs and libraries SHOULD recognize localhost
        // names as special and SHOULD always return the IP loopback address
        // for address queries and negative responses for all other query
        // types.  Name resolution APIs SHOULD NOT send queries for
        // localhost names to their configured caching DNS server(s).
        // ```
        //
        // special use rules only apply to the IN Class
        if query.query_class() == DNSClass::IN {
            let usage = match query.name() {
                n if LOCALHOST_usage.zone_of(n) => &*LOCALHOST_usage,
                n if IN_ADDR_ARPA_127.zone_of(n) => &*LOCALHOST_usage,
                n if IP6_ARPA_1.zone_of(n) => &*LOCALHOST_usage,
                n if INVALID.zone_of(n) => &*INVALID,
                n if LOCAL.zone_of(n) => &*LOCAL,
                _ => &*DEFAULT,
            };

            match usage.resolver() {
                ResolverUsage::Loopback => match query.query_type() {
                    // TODO: look in hosts for these ips/names first...
                    RecordType::A => {
                        return Box::new(future::ok(Lookup::from_rdata(query, LOCALHOST_V4.clone())))
                    }
                    RecordType::AAAA => {
                        return Box::new(future::ok(Lookup::from_rdata(query, LOCALHOST_V6.clone())))
                    }
                    RecordType::PTR => {
                        return Box::new(future::ok(Lookup::from_rdata(query, LOCALHOST.clone())))
                    }
                    _ => return Box::new(future::err(DnsLru::nx_error(query, None))), // Are there any other types we can use?
                },
                // when mdns is enabled we will follow a standard query path
                #[cfg(feature = "mdns")]
                ResolverUsage::LinkLocal => (),
                // TODO: this requires additional config, as Kubernetes and other systems misuse the .local. zone.
                // when mdns is not enabled we will return errors on LinkLocal ("*.local.") names
                #[cfg(not(feature = "mdns"))]
                ResolverUsage::LinkLocal => (),
                ResolverUsage::NxDomain => {
                    return Box::new(future::err(DnsLru::nx_error(query, None)))
                }
                ResolverUsage::Normal => (),
            }
        }

        Box::new(QueryState::lookup(
            query,
            options,
            &mut self.client,
            self.lru.clone(),
        ))
    }
}

struct FromCache {
    query: Query,
    options: DnsRequestOptions,
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
                Ok(Async::NotReady)
            }
            // TODO: need to figure out a way to recover from this.
            // It requires unwrapping the poisoned error and recreating the Mutex at a higher layer...
            Err(TryLockError::Poisoned(poison)) => {
                Err(ResolveErrorKind::Msg(format!("poisoned: {}", poison)).into())
            }
            Ok(mut lru) => Ok(Async::Ready(lru.get(&self.query, Instant::now()))),
        }
    }
}

/// This is the Future responsible for performing an actual query.
struct QueryFuture<C: DnsHandle + 'static> {
    message_future: <C as DnsHandle>::Response,
    query: Query,
    cache: Arc<Mutex<DnsLru>>,
    /// is this a DNSSec validating client?
    dnssec: bool, // TODO: move to DnsRequestOptions?
    options: DnsRequestOptions,
    client: CachingClient<C>,
}

enum Records {
    /// The records exists, a vec of rdata with ttl
    Exists(Vec<(Record, u32)>),
    /// Records do not exist, ttl for negative caching
    NoData { ttl: Option<u32> },
    /// Future lookup for recursive cname records
    CnameChain {
        next: Box<Future<Item = Lookup, Error = ResolveError> + Send>,
        min_ttl: u32,
    },
    /// Already cached, chained queries
    Chained { cached: Lookup, min_ttl: u32 },
}

impl<C: DnsHandle + 'static> QueryFuture<C> {
    fn next_query(&mut self, query: Query, cname_ttl: u32, message: DnsResponse) -> Records {
        if QUERY_DEPTH.with(|c| *c.borrow() >= MAX_QUERY_DEPTH) {
            // TODO: This should return an error
            self.handle_nxdomain(message, true)
        } else {
            // tracking the depth of our queries, to prevent infinite CNAME recursion
            QUERY_DEPTH.with(|c| *c.borrow_mut() += 1);

            Records::CnameChain {
                next: self.client.lookup(query, self.options.clone()),
                min_ttl: cname_ttl,
            }
        }
    }

    fn handle_noerror(&mut self, mut response: DnsResponse) -> Poll<Records, ResolveError> {
        // initial ttl is what CNAMES for min usage
        const INITIAL_TTL: u32 = dns_lru::MAX_TTL;

        // seek out CNAMES, this is only performed if the query is not a CNAME, ANY, or SRV
        let (search_name, cname_ttl, was_cname) = {
            // this will only search for CNAMEs if the request was not meant to be for one of the triggers for recursion
            let (search_name, cname_ttl, was_cname) =
                if self.query.query_type().is_any() || self.query.query_type().is_cname() {
                    (Cow::Borrowed(self.query.name()), INITIAL_TTL, false)
                } else {
                    // Folds any cnames from the answers section, into the final cname in the answers section
                    //   this works by folding the last CNAME found into the final folded result.
                    //   it assumes that the CNAMEs are in chained order in the DnsResponse Message...
                    // For SRV, the name added for the search becomes the target name.
                    //
                    // TODO: should this include the additionals?
                    response.messages().flat_map(Message::answers).fold(
                        (Cow::Borrowed(self.query.name()), INITIAL_TTL, false),
                        |(search_name, cname_ttl, was_cname), r| {
                            match *r.rdata() {
                                RData::CNAME(ref cname) => {
                                    // take the minimum TTL of the cname_ttl and the next record in the chain
                                    let ttl = cname_ttl.min(r.ttl());
                                    debug_assert_eq!(r.rr_type(), RecordType::CNAME);
                                    if search_name.as_ref() == r.name() {
                                        return (Cow::Owned(cname.clone()), ttl, true);
                                    }
                                }
                                RData::SRV(ref srv) => {
                                    // take the minimum TTL of the cname_ttl and the next record in the chain
                                    let ttl = cname_ttl.min(r.ttl());
                                    debug_assert_eq!(r.rr_type(), RecordType::SRV);

                                    // the search name becomes the srv.target
                                    return (Cow::Owned(srv.target().clone()), ttl, true);
                                }
                                _ => (),
                            }

                            (search_name, cname_ttl, was_cname)
                        },
                    )
                };

            // take all answers. // TODO: following CNAMES?
            let answers: Vec<Record> = response
                .messages_mut()
                .flat_map(Message::take_answers)
                .collect();
            let additionals: Vec<Record> = response
                .messages_mut()
                .flat_map(Message::take_additionals)
                .collect();

            // After following all the CNAMES to the last one, try and lookup the final name
            let records = answers
                .into_iter()
                // Chained records will generally exist in the additionals section
                .chain(additionals.into_iter())
                .filter_map(|r| {
                    // because this resolved potentially recursively, we want the min TTL from the chain
                    let ttl = cname_ttl.min(r.ttl());

                    // TODO: disable name validation with ResolverOpts? glibc feature...
                    // restrict to the RData type requested
                    if self.query.query_class() == r.dns_class() {
                        // standard evaluation, it's an any type or it's the requested type and the search_name matches
                        // - or -
                        // srv evaluation, it's an srv lookup and the srv_search_name/target matches this name
                        //    and it's an IP
                        if ((self.query.query_type().is_any() || self.query.query_type() == r.rr_type()) &&
                            (search_name.as_ref() == r.name() || self.query.name() == r.name())) || 
                            (self.query.query_type().is_srv() && r.rr_type().is_ip_addr() && search_name.as_ref() == r.name()) {
                            Some((r, ttl))
                        } else {
                            None
                        }
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

        // TODO: for SRV records we *could* do an implicit lookup, but, this requires knowing the type of IP desired
        //    for now, we'll make the API require the user to perform a follow up to the lookups.
        // It was a CNAME, but not included in the request...
        if was_cname {
            let next_query = Query::query(search_name, self.query.query_type());
            Ok(Async::Ready(
                self.next_query(next_query, cname_ttl, response),
            ))
        } else {
            // TODO: review See https://tools.ietf.org/html/rfc2308 for NoData section
            // Note on DNSSec, in secure_client_handle, if verify_nsec fails then the request fails.
            //   this will mean that no unverified negative caches will make it to this point and be stored
            Ok(Async::Ready(self.handle_nxdomain(response, true)))
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
    fn handle_nxdomain(&self, mut message: DnsResponse, valid_nsec: bool) -> Records {
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

            Records::NoData { ttl }
        } else {
            Records::NoData { ttl: None }
        }
    }
}

impl<C: DnsHandle + 'static> Future for QueryFuture<C> {
    type Item = Records;
    type Error = ResolveError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.message_future.poll() {
            Ok(Async::Ready(message)) => {
                // TODO: take all records and cache them?
                //  if it's DNSSec they must be signed, otherwise?

                match message.response_code() {
                    ResponseCode::NXDomain => Ok(Async::Ready(self.handle_nxdomain(
                        message, false, /* false b/c DNSSec should not cache NXDomain */
                    ))),
                    ResponseCode::NoError => self.handle_noerror(message),
                    r => Err(ResolveErrorKind::Msg(format!("DNS Error: {}", r)).into()),
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
                Ok(Async::NotReady)
            }
            // TODO: need to figure out a way to recover from this.
            // It requires unwrapping the poisoned error and recreating the Mutex at a higher layer...
            Err(TryLockError::Poisoned(poison)) => {
                Err(ResolveErrorKind::Msg(format!("poisoned: {}", poison)).into())
            }
            Ok(mut lru) => {
                // this will put this object into an inconsistent state, but no one should call poll again...
                let query = mem::replace(&mut self.query, Query::new());
                let rdata = mem::replace(&mut self.rdatas, Records::NoData { ttl: None });

                match rdata {
                    Records::Exists(rdata) => {
                        Ok(Async::Ready(lru.insert(query, rdata, Instant::now())))
                    }
                    Records::Chained {
                        cached: lookup,
                        min_ttl: ttl,
                    } => Ok(Async::Ready(lru.duplicate(
                        query,
                        lookup,
                        ttl,
                        Instant::now(),
                    ))),
                    Records::NoData { ttl: Some(ttl) } => {
                        Err(lru.negative(query, ttl, Instant::now()))
                    }
                    Records::NoData { ttl: None } | Records::CnameChain { .. } => {
                        Err(DnsLru::nx_error(query, None))
                    }
                }
            }
        }
    }
}

enum QueryState<C: DnsHandle + 'static> {
    /// In the FromCache state we evaluate cache entries for any results
    FromCache(FromCache, C),
    /// In the query state there is an active query that's been started, see Self::lookup()
    Query(QueryFuture<C>),
    /// CNAME lookup (internally it is making cached queries
    CnameChain(
        Box<Future<Item = Lookup, Error = ResolveError> + Send>,
        Query,
        u32,
        Arc<Mutex<DnsLru>>,
    ),
    /// State of adding the item to the cache
    InsertCache(InsertCache),
    /// A state which should not occur
    Error,
}

impl<C: DnsHandle + 'static> QueryState<C> {
    pub(crate) fn lookup(
        query: Query,
        options: DnsRequestOptions,
        client: &mut C,
        cache: Arc<Mutex<DnsLru>>,
    ) -> QueryState<C> {
        QueryState::FromCache(
            FromCache {
                query,
                options,
                cache,
            },
            client.clone(),
        )
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
                let options = from_cache.options;
                let message_future = client.lookup(query.clone(), options.clone());
                mem::replace(
                    self,
                    QueryState::Query(QueryFuture {
                        message_future,
                        query,
                        cache: cache.clone(),
                        dnssec: client.is_verifying_dnssec(),
                        options,
                        client: CachingClient::with_cache(cache, client),
                    }),
                );
            }
            _ => panic!("bad state, expected FromCache"),
        }
    }

    fn cname(
        &mut self,
        future: Box<Future<Item = Lookup, Error = ResolveError> + Send>,
        cname_ttl: u32,
    ) {
        // The error state, this query is complete...
        let query_state = mem::replace(self, QueryState::Error);

        match query_state {
            QueryState::Query(QueryFuture {
                message_future: _m,
                query,
                cache,
                dnssec: _d,
                options: _o,
                client: _c,
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
                message_future: _m,
                query,
                cache,
                dnssec: _d,
                options: _o,
                client: _c,
            }) => {
                match rdatas {
                    // There are Cnames to lookup
                    Records::CnameChain { .. } => {
                        panic!("CnameChain should have been polled in poll() of QueryState");
                    }
                    rdatas => {
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
                    Records::CnameChain { .. } => {
                        panic!("CnameChain should have been polled in poll() of QueryState");
                    }
                    rdatas => {
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

impl<C: DnsHandle + 'static> Future for QueryState<C> {
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
                let poll = query.poll();
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
                        records = Some(Records::Chained {
                            cached: lookup,
                            min_ttl: ttl,
                        });
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
                Some(Records::CnameChain {
                    next: future,
                    min_ttl: ttl,
                }) => self.cname(future, ttl),
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
        Ok(Async::NotReady)
    }
}

// see also the lookup_tests.rs in integration-tests crate
#[cfg(test)]
mod tests {
    use std::net::*;
    use std::str::FromStr;
    use std::time::*;

    use futures::future;

    use proto::error::{ProtoError, ProtoResult};
    use proto::op::{Message, Query};
    use proto::rr::rdata::SRV;
    use proto::rr::{Name, Record};

    use super::*;
    use lookup_ip::tests::*;

    #[test]
    fn test_empty_cache() {
        let cache = Arc::new(Mutex::new(DnsLru::new(1, dns_lru::TtlConfig::default())));
        let mut client = mock(vec![empty()]);

        assert_eq!(
            *QueryState::lookup(Query::new(), Default::default(), &mut client, cache)
                .wait()
                .unwrap_err()
                .kind(),
            ResolveErrorKind::NoRecordsFound {
                query: Query::new(),
                valid_until: None,
            }
        );
    }

    #[test]
    fn test_from_cache() {
        let cache = Arc::new(Mutex::new(DnsLru::new(1, dns_lru::TtlConfig::default())));
        let query = Query::new();
        cache.lock().unwrap().insert(
            query.clone(),
            vec![
                (Record::from_rdata(query.name().clone(), u32::max_value(), RData::A(Ipv4Addr::new(127, 0, 0, 1))), u32::max_value())
            ],
            Instant::now(),
        );

        let mut client = mock(vec![empty()]);

        let ips = QueryState::lookup(Query::new(), Default::default(), &mut client, cache)
            .wait()
            .unwrap();

        assert_eq!(
            ips.iter().cloned().collect::<Vec<_>>(),
            vec![RData::A(Ipv4Addr::new(127, 0, 0, 1))]
        );
    }

    #[test]
    fn test_no_cache_insert() {
        let cache = Arc::new(Mutex::new(DnsLru::new(1, dns_lru::TtlConfig::default())));
        // first should come from client...
        let mut client = mock(vec![v4_message()]);

        let ips = QueryState::lookup(Query::new(), Default::default(), &mut client, cache.clone())
            .wait()
            .unwrap();

        assert_eq!(
            ips.iter().cloned().collect::<Vec<_>>(),
            vec![RData::A(Ipv4Addr::new(127, 0, 0, 1))]
        );

        // next should come from cache...
        let mut client = mock(vec![empty()]);

        let ips = QueryState::lookup(Query::new(), Default::default(), &mut client, cache)
            .wait()
            .unwrap();

        assert_eq!(
            ips.iter().cloned().collect::<Vec<_>>(),
            vec![RData::A(Ipv4Addr::new(127, 0, 0, 1))]
        );
    }

    pub fn cname_message() -> ProtoResult<DnsResponse> {
        let mut message = Message::new();
        message.insert_answers(vec![Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            86400,
            RData::CNAME(Name::from_str("actual.example.com.").unwrap()),
        )]);
        Ok(message.into())
    }

    pub fn srv_message() -> ProtoResult<DnsResponse> {
        let mut message = Message::new();
        message.insert_answers(vec![Record::from_rdata(
            Name::from_str("_443._tcp.www.example.com.").unwrap(),
            86400,
            RData::SRV(SRV::new(
                1,
                2,
                443,
                Name::from_str("www.example.com.").unwrap(),
            )),
        )]);
        Ok(message.into())
    }

    fn no_recursion_on_query_test(query_type: RecordType) {
        let cache = Arc::new(Mutex::new(DnsLru::new(1, dns_lru::TtlConfig::default())));

        // the cname should succeed, we shouldn't query again after that, which would cause an error...
        let mut client = mock(vec![error(), cname_message()]);

        let ips = QueryState::lookup(
            Query::query(Name::from_str("www.example.com.").unwrap(), query_type),
            Default::default(),
            &mut client,
            cache.clone(),
        ).wait()
        .expect("lookup failed");

        assert_eq!(
            ips.iter().cloned().collect::<Vec<_>>(),
            vec![RData::CNAME(Name::from_str("actual.example.com.").unwrap())]
        );
    }

    #[test]
    fn test_no_recursion_on_cname_query() {
        no_recursion_on_query_test(RecordType::CNAME);
    }

    #[test]
    fn test_no_recursion_on_all_query() {
        no_recursion_on_query_test(RecordType::ANY);
    }

    #[test]
    fn test_non_recursive_srv_query() {
        let cache = Arc::new(Mutex::new(DnsLru::new(1, dns_lru::TtlConfig::default())));

        // the cname should succeed, we shouldn't query again after that, which would cause an error...
        let mut client = mock(vec![error(), srv_message()]);

        let ips = QueryState::lookup(
            Query::query(
                Name::from_str("_443._tcp.www.example.com.").unwrap(),
                RecordType::SRV,
            ),
            Default::default(),
            &mut client,
            cache.clone(),
        ).wait()
        .expect("lookup failed");

        assert_eq!(
            ips.iter().cloned().collect::<Vec<_>>(),
            vec![RData::SRV(SRV::new(
                1,
                2,
                443,
                Name::from_str("www.example.com.").unwrap(),
            ))]
        );
    }

    #[test]
    fn test_single_srv_query_response() {
        let cache = Arc::new(Mutex::new(DnsLru::new(1, dns_lru::TtlConfig::default())));

        let mut message = srv_message().unwrap();
        message.add_answer(Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            86400,
            RData::CNAME(Name::from_str("actual.example.com.").unwrap()),
        ));
        message.insert_additionals(vec![
            Record::from_rdata(
                Name::from_str("actual.example.com.").unwrap(),
                86400,
                RData::A(Ipv4Addr::new(127, 0, 0, 1)),
            ),
            Record::from_rdata(
                Name::from_str("actual.example.com.").unwrap(),
                86400,
                RData::AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ),
        ]);

        let mut client = mock(vec![error(), Ok(message)]);

        let ips = QueryState::lookup(
            Query::query(
                Name::from_str("_443._tcp.www.example.com.").unwrap(),
                RecordType::SRV,
            ),
            Default::default(),
            &mut client,
            cache.clone(),
        ).wait()
        .expect("lookup failed");

        assert_eq!(
            ips.iter().cloned().collect::<Vec<_>>(),
            vec![
                RData::SRV(SRV::new(
                    1,
                    2,
                    443,
                    Name::from_str("www.example.com.").unwrap(),
                )),
                RData::A(Ipv4Addr::new(127, 0, 0, 1)),
                RData::AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ]
        );
    }

    // TODO: if we ever enable recursive lookups for SRV, here are the tests...
    // #[test]
    // fn test_recursive_srv_query() {
    //     let cache = Arc::new(Mutex::new(DnsLru::new(1)));

    //     let mut message = Message::new();
    //     message.add_answer(Record::from_rdata(
    //         Name::from_str("www.example.com.").unwrap(),
    //         86400,
    //         RecordType::CNAME,
    //         RData::CNAME(Name::from_str("actual.example.com.").unwrap()),
    //     ));
    //     message.insert_additionals(vec![
    //         Record::from_rdata(
    //             Name::from_str("actual.example.com.").unwrap(),
    //             86400,
    //             RecordType::A,
    //             RData::A(Ipv4Addr::new(127, 0, 0, 1)),
    //         ),
    //     ]);

    //     let mut client = mock(vec![error(), Ok(message.into()), srv_message()]);

    //     let ips = QueryState::lookup(
    //         Query::query(
    //             Name::from_str("_443._tcp.www.example.com.").unwrap(),
    //             RecordType::SRV,
    //         ),
    //         Default::default(),
    //         &mut client,
    //         cache.clone(),
    //     ).wait()
    //         .expect("lookup failed");

    //     assert_eq!(
    //         ips.iter().cloned().collect::<Vec<_>>(),
    //         vec![
    //             RData::SRV(SRV::new(
    //                 1,
    //                 2,
    //                 443,
    //                 Name::from_str("www.example.com.").unwrap(),
    //             )),
    //             RData::A(Ipv4Addr::new(127, 0, 0, 1)),
    //             //RData::AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
    //         ]
    //     );
    // }

    fn cname_ttl_test(first: u32, second: u32) {
        let lru = Arc::new(Mutex::new(DnsLru::new(1, dns_lru::TtlConfig::default())));
        // expecting no queries to be performed
        let client = CachingClient::with_cache(Arc::clone(&lru), mock(vec![error()]));

        let mut query_future = QueryFuture {
            message_future: Box::new(future::err(ProtoError::from("no message_future in test")))
                as Box<Future<Item = DnsResponse, Error = ProtoError> + Send>,
            query: Query::query(Name::from_str("ttl.example.com.").unwrap(), RecordType::A),
            cache: lru,
            dnssec: false,
            options: Default::default(),
            client,
        };

        let mut message = Message::new();
        message.insert_answers(vec![Record::from_rdata(
            Name::from_str("ttl.example.com.").unwrap(),
            first,
            RData::CNAME(Name::from_str("actual.example.com.").unwrap()),
        )]);
        message.insert_additionals(vec![Record::from_rdata(
            Name::from_str("actual.example.com.").unwrap(),
            second,
            RData::A(Ipv4Addr::new(127, 0, 0, 1)),
        )]);

        let poll: Async<Records> = query_future
            .handle_noerror(message.into())
            .expect("handle_noerror failed");

        assert!(poll.is_ready());
        if let Async::Ready(records) = poll {
            if let Records::Exists(records) = records {
                assert!(records.iter().all(|&(_, ttl)| ttl == 1));
            } else {
                panic!("records don't exist");
            }
        } else {
            panic!("poll not ready");
        }
    }

    #[test]
    fn test_cname_ttl() {
        cname_ttl_test(1, 2);
        cname_ttl_test(2, 1);
    }

    #[test]
    fn test_early_return_localhost() {
        let cache = Arc::new(Mutex::new(DnsLru::new(0, dns_lru::TtlConfig::default())));
        let client = mock(vec![empty()]);
        let mut client = CachingClient { lru: cache, client };

        {
            let query = Query::query(Name::from_ascii("localhost.").unwrap(), RecordType::A);
            let lookup = client
                .lookup(query.clone(), Default::default())
                .wait()
                .expect("should have returned localhost");
            assert_eq!(lookup.query(), &query);
            assert_eq!(lookup.iter().cloned().collect::<Vec<_>>(), vec![LOCALHOST_V4.clone()]);
        }

        {
            let query = Query::query(Name::from_ascii("localhost.").unwrap(), RecordType::AAAA);
            let lookup = client
                .lookup(query.clone(), Default::default())
                .wait()
                .expect("should have returned localhost");
            assert_eq!(lookup.query(), &query);
            assert_eq!(lookup.iter().cloned().collect::<Vec<_>>(), vec![LOCALHOST_V6.clone()]);
        }

        {
            let query = Query::query(Name::from(Ipv4Addr::new(127, 0, 0, 1)), RecordType::PTR);
            let lookup = client
                .lookup(query.clone(), Default::default())
                .wait()
                .expect("should have returned localhost");
            assert_eq!(lookup.query(), &query);
            assert_eq!(lookup.iter().cloned().collect::<Vec<_>>(), vec![LOCALHOST.clone()]);
        }

        {
            let query = Query::query(
                Name::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                RecordType::PTR,
            );
            let lookup = client
                .lookup(query.clone(), Default::default())
                .wait()
                .expect("should have returned localhost");
            assert_eq!(lookup.query(), &query);
            assert_eq!(lookup.iter().cloned().collect::<Vec<_>>(), vec![LOCALHOST.clone()]);
        }

        assert!(
            client
                .lookup(
                    Query::query(Name::from_ascii("localhost.").unwrap(), RecordType::MX),
                    Default::default()
                ).wait()
                .is_err()
        );

        assert!(
            client
                .lookup(
                    Query::query(Name::from(Ipv4Addr::new(127, 0, 0, 1)), RecordType::MX),
                    Default::default()
                ).wait()
                .is_err()
        );

        assert!(
            client
                .lookup(
                    Query::query(
                        Name::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                        RecordType::MX
                    ),
                    Default::default()
                ).wait()
                .is_err()
        );
    }

    #[test]
    fn test_early_return_invalid() {
        let cache = Arc::new(Mutex::new(DnsLru::new(0, dns_lru::TtlConfig::default())));
        let client = mock(vec![empty()]);
        let mut client = CachingClient { lru: cache, client };

        assert!(
            client
                .lookup(
                    Query::query(
                        Name::from_ascii("horrible.invalid.").unwrap(),
                        RecordType::A,
                    ),
                    Default::default()
                ).wait()
                .is_err()
        );
    }

    #[test]
    fn test_no_error_on_dot_local_no_mdns() {
        let cache = Arc::new(Mutex::new(DnsLru::new(1, dns_lru::TtlConfig::default())));

        let mut message = srv_message().unwrap();
        message.add_answer(Record::from_rdata(
            Name::from_str("www.example.local.").unwrap(),
            86400,
            RData::A(Ipv4Addr::new(127, 0, 0, 1)),
        ));

        let client = mock(vec![error(), Ok(message)]);
        let mut client = CachingClient { lru: cache, client };

        assert!(
            client
                .lookup(
                    Query::query(
                        Name::from_ascii("www.example.local.").unwrap(),
                        RecordType::A,
                    ),
                    Default::default()
                ).wait()
                .is_ok()
        );
    }
}
