// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Caching related functionality for the Resolver.

use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Instant;

use futures::lock::Mutex;
use futures::{future, Future, FutureExt};

use proto::op::{Message, Query, ResponseCode};
use proto::rr::domain::usage::{
    ResolverUsage, DEFAULT, INVALID, IN_ADDR_ARPA_127, IP6_ARPA_1, LOCAL,
    LOCALHOST as LOCALHOST_usage,
};
use proto::rr::{DNSClass, Name, RData, Record, RecordType};
use proto::xfer::{DnsHandle, DnsRequestOptions, DnsResponse};

use crate::dns_lru;
use crate::dns_lru::DnsLru;
use crate::error::*;
use crate::lookup::Lookup;

const MAX_QUERY_DEPTH: u8 = 8; // arbitrarily chosen number...

lazy_static! {
    static ref LOCALHOST: RData = RData::PTR(Name::from_ascii("localhost.").unwrap());
    static ref LOCALHOST_V4: RData = RData::A(Ipv4Addr::new(127, 0, 0, 1));
    static ref LOCALHOST_V6: RData = RData::AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
}

struct DepthTracker {
    query_depth: Arc<AtomicU8>
}

impl DepthTracker {
    fn track(query_depth: Arc<AtomicU8>) -> Self {
        dbg!(query_depth.fetch_add(1, Ordering::Release));
        Self{ query_depth }
    }
}

impl Drop for DepthTracker {
    fn drop(&mut self) {
        dbg!(self.query_depth.fetch_sub(1, Ordering::Release));
    }
}

// TODO: need to consider this storage type as it compares to Authority in server...
//       should it just be an variation on Authority?
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct CachingClient<C: DnsHandle> {
    lru: Arc<Mutex<DnsLru>>,
    client: C,
    query_depth: Arc<AtomicU8>,
}

impl<C: DnsHandle + Send + 'static> CachingClient<C> {
    #[doc(hidden)]
    pub fn new(max_size: usize, client: C) -> Self {
        Self::with_cache(
            Arc::new(Mutex::new(DnsLru::new(max_size, Default::default()))),
            client,
        )
    }

    pub(crate) fn with_cache(lru: Arc<Mutex<DnsLru>>, client: C) -> Self {
        let query_depth = Arc::new(AtomicU8::new(0));
        CachingClient {
            lru,
            client,
            query_depth,
        }
    }

    /// Perform a lookup against this caching client, looking first in the cache for a result
    pub fn lookup(
        &mut self,
        query: Query,
        options: DnsRequestOptions,
    ) -> Pin<Box<dyn Future<Output = Result<Lookup, ResolveError>> + Send>> {
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
                        return future::ok(Lookup::from_rdata(query, LOCALHOST_V4.clone())).boxed()
                    }
                    RecordType::AAAA => {
                        return future::ok(Lookup::from_rdata(query, LOCALHOST_V6.clone())).boxed()
                    }
                    RecordType::PTR => {
                        return future::ok(Lookup::from_rdata(query, LOCALHOST.clone())).boxed()
                    }
                    _ => return future::err(DnsLru::nx_error(query, None)).boxed(), // Are there any other types we can use?
                },
                // when mdns is enabled we will follow a standard query path
                #[cfg(feature = "mdns")]
                ResolverUsage::LinkLocal => (),
                // TODO: this requires additional config, as Kubernetes and other systems misuse the .local. zone.
                // when mdns is not enabled we will return errors on LinkLocal ("*.local.") names
                #[cfg(not(feature = "mdns"))]
                ResolverUsage::LinkLocal => (),
                ResolverUsage::NxDomain => {
                    return future::err(DnsLru::nx_error(query, None)).boxed()
                }
                ResolverUsage::Normal => (),
            }
        }

        Box::pin(Self::inner_lookup(query, options, self.clone()))
    }

    async fn inner_lookup(
        query: Query,
        options: DnsRequestOptions,
        mut client: Self,
    ) -> Result<Lookup, ResolveError> {
        let _tracker = DepthTracker::track(client.query_depth.clone());
        let is_dnssec = client.client.is_verifying_dnssec();

        // first transition any polling that is needed (mutable refs...)
        if let Some(cached_lookup) = Self::from_cache(&query, &client.lru).await {
            return Ok(cached_lookup);
        };

        let response_message = client.client.lookup(query.clone(), options.clone()).await?;

        // TODO: take all records and cache them?
        //  if it's DNSSec they must be signed, otherwise?
        let records = match response_message.response_code() {
            ResponseCode::NXDomain => Ok(Self::handle_nxdomain(
                is_dnssec,
                response_message,
                false, /* false b/c DNSSec should not cache NXDomain */
            )),
            ResponseCode::NoError => {
                Self::handle_noerror(&mut client, options, is_dnssec, &query, response_message)
            }
            r => Err(ResolveErrorKind::Msg(format!("DNS Error: {}", r)).into()),
        }?;

        // after the request, evaluate if we have additional queries to perform
        match records {
            Records::CnameChain {
                next: future,
                min_ttl: ttl,
            } => Self::cname(query, future, &client.lru, ttl).await,
            records => Self::cache(query, records, &client.lru).await,
        }
    }

    /// Check if this query is already cached
    async fn from_cache(query: &Query, cache: &Mutex<DnsLru>) -> Option<Lookup> {
        let mut lru = cache.lock().await;
        lru.get(query, Instant::now())
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
    fn handle_nxdomain(is_dnssec: bool, mut message: DnsResponse, valid_nsec: bool) -> Records {
        if valid_nsec || !is_dnssec {
            //  if there were validated NSEC records
            let soa = message
                .take_name_servers()
                .into_iter()
                .find(|r| r.rr_type() == RecordType::SOA);

            let ttl = if let Some(RData::SOA(soa)) = soa.map(Record::unwrap_rdata) {
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

    /// Handle the case where there is no error returned
    fn handle_noerror(
        client: &mut Self,
        options: DnsRequestOptions,
        is_dnssec: bool,
        query: &Query,
        mut response: DnsResponse,
    ) -> Result<Records, ResolveError> {
        // initial ttl is what CNAMES for min usage
        const INITIAL_TTL: u32 = dns_lru::MAX_TTL;

        // seek out CNAMES, this is only performed if the query is not a CNAME, ANY, or SRV
        let (search_name, cname_ttl, was_cname) = {
            // this will only search for CNAMEs if the request was not meant to be for one of the triggers for recursion
            let (search_name, cname_ttl, was_cname) =
                if query.query_type().is_any() || query.query_type().is_cname() {
                    (Cow::Borrowed(query.name()), INITIAL_TTL, false)
                } else {
                    // Folds any cnames from the answers section, into the final cname in the answers section
                    //   this works by folding the last CNAME found into the final folded result.
                    //   it assumes that the CNAMEs are in chained order in the DnsResponse Message...
                    // For SRV, the name added for the search becomes the target name.
                    //
                    // TODO: should this include the additionals?
                    response.messages().flat_map(Message::answers).fold(
                        (Cow::Borrowed(query.name()), INITIAL_TTL, false),
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
                    if query.query_class() == r.dns_class() {
                        // standard evaluation, it's an any type or it's the requested type and the search_name matches
                        // - or -
                        // srv evaluation, it's an srv lookup and the srv_search_name/target matches this name
                        //    and it's an IP
                        if ((query.query_type().is_any() || query.query_type() == r.rr_type())
                            && (search_name.as_ref() == r.name() || query.name() == r.name()))
                            || (query.query_type().is_srv()
                                && r.rr_type().is_ip_addr()
                                && search_name.as_ref() == r.name())
                        {
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
                return Ok(Records::Exists(records));
            }

            (search_name.into_owned(), cname_ttl, was_cname)
        };

        // TODO: for SRV records we *could* do an implicit lookup, but, this requires knowing the type of IP desired
        //    for now, we'll make the API require the user to perform a follow up to the lookups.
        // It was a CNAME, but not included in the request...
        if was_cname {
            let next_query = Query::query(search_name, query.query_type());
            Ok(Self::next_query(
                client, options, is_dnssec, next_query, cname_ttl, response,
            ))
        } else {
            // TODO: review See https://tools.ietf.org/html/rfc2308 for NoData section
            // Note on DNSSec, in secure_client_handle, if verify_nsec fails then the request fails.
            //   this will mean that no unverified negative caches will make it to this point and be stored
            Ok(Self::handle_nxdomain(is_dnssec, response, true))
        }
    }

    // TODO: merge this with cname
    fn next_query(
        client: &mut Self,
        options: DnsRequestOptions,
        is_dnssec: bool,
        query: Query,
        cname_ttl: u32,
        message: DnsResponse,
    ) -> Records {
        // tracking the depth of our queries, to prevent infinite CNAME recursion
        if dbg!(client.query_depth.load(Ordering::Acquire)) >= MAX_QUERY_DEPTH {
            // TODO: This should return an error
            Self::handle_nxdomain(is_dnssec, message, true)
        } else {
            Records::CnameChain {
                next: client.lookup(query, options),
                min_ttl: cname_ttl,
            }
        }
    }

    async fn cname(
        query: Query,
        future: Pin<Box<dyn Future<Output = Result<Lookup, ResolveError>> + Send>>,
        cache: &Mutex<DnsLru>,
        cname_ttl: u32,
    ) -> Result<Lookup, ResolveError> {
        // The error state, this query is complete...

        let lookup = future.await?;
        let mut cache = cache.lock().await;

        Ok(cache.duplicate(query, lookup, cname_ttl, Instant::now()))
    }

    async fn cache(
        query: Query,
        records: Records,
        cache: &Mutex<DnsLru>,
    ) -> Result<Lookup, ResolveError> {
        // The error state, this query is complete...
        let mut lru = cache.lock().await;

        // this will put this object into an inconsistent state, but no one should call poll again...
        match records {
            Records::Exists(rdata) => Ok(lru.insert(query, rdata, Instant::now())),
            Records::NoData { ttl: Some(ttl) } => Err(lru.negative(query, ttl, Instant::now())),
            Records::NoData { ttl: None } | Records::CnameChain { .. } => {
                Err(DnsLru::nx_error(query, None))
            }
        }
    }
}

enum Records {
    /// The records exists, a vec of rdata with ttl
    Exists(Vec<(Record, u32)>),
    /// Records do not exist, ttl for negative caching
    NoData { ttl: Option<u32> },
    /// Future lookup for recursive cname records
    CnameChain {
        next: Pin<Box<dyn Future<Output = Result<Lookup, ResolveError>> + Send>>,
        min_ttl: u32,
    },
}

// see also the lookup_tests.rs in integration-tests crate
#[cfg(test)]
mod tests {
    use std::net::*;
    use std::str::FromStr;
    use std::time::*;

    use futures::executor::block_on;
    use proto::error::ProtoResult;
    use proto::op::{Message, Query};
    use proto::rr::rdata::SRV;
    use proto::rr::{Name, Record};

    use super::*;
    use crate::lookup_ip::tests::*;

    #[test]
    fn test_empty_cache() {
        let cache = Arc::new(Mutex::new(DnsLru::new(1, dns_lru::TtlConfig::default())));
        let client = mock(vec![empty()]);
        let client = CachingClient::with_cache(cache, client);

        assert_eq!(
            *block_on(CachingClient::inner_lookup(
                Query::new(),
                Default::default(),
                client,
            ))
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
        cache.try_lock().unwrap().insert(
            query.clone(),
            vec![(
                Record::from_rdata(
                    query.name().clone(),
                    u32::max_value(),
                    RData::A(Ipv4Addr::new(127, 0, 0, 1)),
                ),
                u32::max_value(),
            )],
            Instant::now(),
        );

        let client = mock(vec![empty()]);
        let client = CachingClient::with_cache(cache, client);

        let ips = block_on(CachingClient::inner_lookup(
            Query::new(),
            Default::default(),
            client,
        ))
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
        let client = mock(vec![v4_message()]);
        let client = CachingClient::with_cache(cache.clone(), client);

        let ips = block_on(CachingClient::inner_lookup(
            Query::new(),
            Default::default(),
            client,
        ))
        .unwrap();

        assert_eq!(
            ips.iter().cloned().collect::<Vec<_>>(),
            vec![RData::A(Ipv4Addr::new(127, 0, 0, 1))]
        );

        // next should come from cache...
        let client = mock(vec![empty()]);
        let client = CachingClient::with_cache(cache, client);

        let ips = block_on(CachingClient::inner_lookup(
            Query::new(),
            Default::default(),
            client,
        ))
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
        let client = mock(vec![error(), cname_message()]);
        let client = CachingClient::with_cache(cache, client);

        let ips = block_on(CachingClient::inner_lookup(
            Query::query(Name::from_str("www.example.com.").unwrap(), query_type),
            Default::default(),
            client,
        ))
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
        let client = mock(vec![error(), srv_message()]);
        let client = CachingClient::with_cache(cache, client);

        let ips = block_on(CachingClient::inner_lookup(
            Query::query(
                Name::from_str("_443._tcp.www.example.com.").unwrap(),
                RecordType::SRV,
            ),
            Default::default(),
            client,
        ))
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

        let client = mock(vec![error(), Ok(message)]);
        let client = CachingClient::with_cache(cache, client);

        let ips = block_on(CachingClient::inner_lookup(
            Query::query(
                Name::from_str("_443._tcp.www.example.com.").unwrap(),
                RecordType::SRV,
            ),
            Default::default(),
            client,
        ))
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
        let mut client = CachingClient::with_cache(Arc::clone(&lru), mock(vec![error()]));

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

        let records = CachingClient::handle_noerror(
            &mut client,
            Default::default(),
            false,
            &Query::query(Name::from_str("ttl.example.com.").unwrap(), RecordType::A),
            message.into(),
        );

        if let Ok(records) = records {
            if let Records::Exists(records) = records {
                assert!(records.iter().all(|&(_, ttl)| ttl == 1));
            } else {
                panic!("records don't exist");
            }
        } else {
            panic!("error getting records");
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
        let mut client = CachingClient::with_cache(cache, client);

        {
            let query = Query::query(Name::from_ascii("localhost.").unwrap(), RecordType::A);
            let lookup = block_on(client.lookup(query.clone(), Default::default()))
                .expect("should have returned localhost");
            assert_eq!(lookup.query(), &query);
            assert_eq!(
                lookup.iter().cloned().collect::<Vec<_>>(),
                vec![LOCALHOST_V4.clone()]
            );
        }

        {
            let query = Query::query(Name::from_ascii("localhost.").unwrap(), RecordType::AAAA);
            let lookup = block_on(client.lookup(query.clone(), Default::default()))
                .expect("should have returned localhost");
            assert_eq!(lookup.query(), &query);
            assert_eq!(
                lookup.iter().cloned().collect::<Vec<_>>(),
                vec![LOCALHOST_V6.clone()]
            );
        }

        {
            let query = Query::query(Name::from(Ipv4Addr::new(127, 0, 0, 1)), RecordType::PTR);
            let lookup = block_on(client.lookup(query.clone(), Default::default()))
                .expect("should have returned localhost");
            assert_eq!(lookup.query(), &query);
            assert_eq!(
                lookup.iter().cloned().collect::<Vec<_>>(),
                vec![LOCALHOST.clone()]
            );
        }

        {
            let query = Query::query(
                Name::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                RecordType::PTR,
            );
            let lookup = block_on(client.lookup(query.clone(), Default::default()))
                .expect("should have returned localhost");
            assert_eq!(lookup.query(), &query);
            assert_eq!(
                lookup.iter().cloned().collect::<Vec<_>>(),
                vec![LOCALHOST.clone()]
            );
        }

        assert!(block_on(client.lookup(
            Query::query(Name::from_ascii("localhost.").unwrap(), RecordType::MX),
            Default::default()
        ))
        .is_err());

        assert!(block_on(client.lookup(
            Query::query(Name::from(Ipv4Addr::new(127, 0, 0, 1)), RecordType::MX),
            Default::default()
        ))
        .is_err());

        assert!(block_on(client.lookup(
            Query::query(
                Name::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                RecordType::MX
            ),
            Default::default()
        ))
        .is_err());
    }

    #[test]
    fn test_early_return_invalid() {
        let cache = Arc::new(Mutex::new(DnsLru::new(0, dns_lru::TtlConfig::default())));
        let client = mock(vec![empty()]);
        let mut client = CachingClient::with_cache(cache, client);

        assert!(block_on(client.lookup(
            Query::query(
                Name::from_ascii("horrible.invalid.").unwrap(),
                RecordType::A,
            ),
            Default::default()
        ))
        .is_err());
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
        let mut client = CachingClient::with_cache(cache, client);

        assert!(block_on(client.lookup(
            Query::query(
                Name::from_ascii("www.example.local.").unwrap(),
                RecordType::A,
            ),
            Default::default()
        ))
        .is_ok());
    }
}
