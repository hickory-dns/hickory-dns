// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Caching related functionality for the Resolver.

use std::borrow::Cow;
use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Instant;

use futures_util::future::Future;

use proto::error::ProtoError;
use proto::op::{Query, ResponseCode};
use proto::rr::domain::usage::{
    ResolverUsage, DEFAULT, INVALID, IN_ADDR_ARPA_127, IP6_ARPA_1, LOCAL,
    LOCALHOST as LOCALHOST_usage, ONION,
};
use proto::rr::rdata::SOA;
use proto::rr::{DNSClass, Name, RData, Record, RecordType};
use proto::xfer::{DnsHandle, DnsRequestOptions, DnsResponse, FirstAnswer};

use crate::dns_lru::DnsLru;
use crate::dns_lru::{self, TtlConfig};
use crate::error::*;
use crate::lookup::Lookup;

const MAX_QUERY_DEPTH: u8 = 8; // arbitrarily chosen number...

lazy_static! {
    static ref LOCALHOST: RData = RData::PTR(Name::from_ascii("localhost.").unwrap());
    static ref LOCALHOST_V4: RData = RData::A(Ipv4Addr::new(127, 0, 0, 1));
    static ref LOCALHOST_V6: RData = RData::AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
}

struct DepthTracker {
    query_depth: Arc<AtomicU8>,
}

impl DepthTracker {
    fn track(query_depth: Arc<AtomicU8>) -> Self {
        query_depth.fetch_add(1, Ordering::Release);
        Self { query_depth }
    }
}

impl Drop for DepthTracker {
    fn drop(&mut self) {
        self.query_depth.fetch_sub(1, Ordering::Release);
    }
}

// TODO: need to consider this storage type as it compares to Authority in server...
//       should it just be an variation on Authority?
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct CachingClient<C, E>
where
    C: DnsHandle<Error = E>,
    E: Into<ResolveError> + From<ProtoError> + Error + Clone + Send + Unpin + 'static,
{
    lru: DnsLru,
    client: C,
    query_depth: Arc<AtomicU8>,
    preserve_intermediates: bool,
}

impl<C, E> CachingClient<C, E>
where
    C: DnsHandle<Error = E> + Send + 'static,
    E: Into<ResolveError> + From<ProtoError> + Error + Clone + Send + Unpin + 'static,
{
    #[doc(hidden)]
    pub fn new(max_size: usize, client: C, preserve_intermediates: bool) -> Self {
        Self::with_cache(
            DnsLru::new(max_size, TtlConfig::default()),
            client,
            preserve_intermediates,
        )
    }

    pub(crate) fn with_cache(lru: DnsLru, client: C, preserve_intermediates: bool) -> Self {
        let query_depth = Arc::new(AtomicU8::new(0));
        Self {
            lru,
            client,
            query_depth,
            preserve_intermediates,
        }
    }

    /// Perform a lookup against this caching client, looking first in the cache for a result
    pub fn lookup(
        &mut self,
        query: Query,
        options: DnsRequestOptions,
    ) -> Pin<Box<dyn Future<Output = Result<Lookup, ResolveError>> + Send>> {
        Box::pin(Self::inner_lookup(query, options, self.clone(), vec![]))
    }

    async fn inner_lookup(
        query: Query,
        options: DnsRequestOptions,
        mut client: Self,
        preserved_records: Vec<(Record, u32)>,
    ) -> Result<Lookup, ResolveError> {
        // see https://tools.ietf.org/html/rfc6761
        //
        // ```text
        // Name resolution APIs and libraries SHOULD recognize localhost
        // names as special and SHOULD always return the IP loopback address
        // for address queries and negative responses for all other query
        // types.  Name resolution APIs SHOULD NOT send queries for
        // localhost names to their configured caching DNS server(s).
        // ```
        // special use rules only apply to the IN Class
        if query.query_class() == DNSClass::IN {
            let usage = match query.name() {
                n if LOCALHOST_usage.zone_of(n) => &*LOCALHOST_usage,
                n if IN_ADDR_ARPA_127.zone_of(n) => &*LOCALHOST_usage,
                n if IP6_ARPA_1.zone_of(n) => &*LOCALHOST_usage,
                n if INVALID.zone_of(n) => &*INVALID,
                n if LOCAL.zone_of(n) => &*LOCAL,
                n if ONION.zone_of(n) => &*ONION,
                _ => &*DEFAULT,
            };

            match usage.resolver() {
                ResolverUsage::Loopback => match query.query_type() {
                    // TODO: look in hosts for these ips/names first...
                    RecordType::A => return Ok(Lookup::from_rdata(query, LOCALHOST_V4.clone())),
                    RecordType::AAAA => return Ok(Lookup::from_rdata(query, LOCALHOST_V6.clone())),
                    RecordType::PTR => return Ok(Lookup::from_rdata(query, LOCALHOST.clone())),
                    _ => {
                        return Err(ResolveError::nx_error(
                            query,
                            None,
                            None,
                            ResponseCode::NoError,
                            false,
                        ))
                    } // Are there any other types we can use?
                },
                // when mdns is enabled we will follow a standard query path
                #[cfg(feature = "mdns")]
                ResolverUsage::LinkLocal => (),
                // TODO: this requires additional config, as Kubernetes and other systems misuse the .local. zone.
                // when mdns is not enabled we will return errors on LinkLocal ("*.local.") names
                #[cfg(not(feature = "mdns"))]
                ResolverUsage::LinkLocal => (),
                ResolverUsage::NxDomain => {
                    return Err(ResolveError::nx_error(
                        query,
                        None,
                        None,
                        ResponseCode::NXDomain,
                        false,
                    ))
                }
                ResolverUsage::Normal => (),
            }
        }

        let _tracker = DepthTracker::track(client.query_depth.clone());
        let is_dnssec = client.client.is_verifying_dnssec();

        // first transition any polling that is needed (mutable refs...)
        if let Some(cached_lookup) = client.from_cache(&query) {
            return cached_lookup;
        };

        let response_message = client
            .client
            .lookup(query.clone(), options)
            .first_answer()
            .await
            .map_err(E::into);

        // TODO: technically this might be duplicating work, as name_server already performs this evaluation.
        //  we may want to create a new type, if evaluated... but this is most generic to support any impl in LookupState...
        let response_message = if let Ok(response) = response_message {
            ResolveError::from_response(response, false)
        } else {
            response_message
        };

        // TODO: take all records and cache them?
        //  if it's DNSSec they must be signed, otherwise?
        let records: Result<Records, ResolveError> = match response_message {
            // this is the only cacheable form
            Err(ResolveError {
                kind:
                    ResolveErrorKind::NoRecordsFound {
                        query,
                        soa,
                        negative_ttl,
                        response_code,
                        trusted,
                    },
                ..
            }) => {
                Err(Self::handle_nxdomain(
                    is_dnssec,
                    false, /*tbd*/
                    *query,
                    soa.map(|v| *v),
                    negative_ttl,
                    response_code,
                    trusted,
                ))
            }
            Err(e) => return Err(e),
            Ok(response_message) => {
                // allow the handle_noerror function to deal with any error codes
                let records = Self::handle_noerror(
                    &mut client,
                    options,
                    is_dnssec,
                    &query,
                    response_message,
                    preserved_records,
                )?;

                Ok(records)
            }
        };

        // after the request, evaluate if we have additional queries to perform
        match records {
            Ok(Records::CnameChain {
                next: future,
                min_ttl: ttl,
            }) => client.cname(future.await?, query, ttl),
            Ok(Records::Exists(rdata)) => client.cache(query, Ok(rdata)),
            Err(e) => client.cache(query, Err(e)),
        }
    }

    /// Check if this query is already cached
    fn from_cache(&self, query: &Query) -> Option<Result<Lookup, ResolveError>> {
        self.lru.get(query, Instant::now())
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
    /// TODO: should this should be expanded to do a forward lookup? Today, this will fail even if there are
    ///   forwarding options.
    ///
    /// # Arguments
    ///
    /// * `message` - message to extract SOA, etc, from for caching failed requests
    /// * `valid_nsec` - species that in DNSSec mode, this request is safe to cache
    /// * `negative_ttl` - this should be the SOA minimum for negative ttl
    fn handle_nxdomain(
        is_dnssec: bool,
        valid_nsec: bool,
        query: Query,
        soa: Option<SOA>,
        negative_ttl: Option<u32>,
        response_code: ResponseCode,
        trusted: bool,
    ) -> ResolveError {
        if valid_nsec || !is_dnssec {
            // only trust if there were validated NSEC records
            ResolveErrorKind::NoRecordsFound {
                query: Box::new(query),
                soa: soa.map(Box::new),
                negative_ttl,
                response_code,
                trusted: true,
            }
            .into()
        } else {
            // not cacheable, no ttl...
            ResolveErrorKind::NoRecordsFound {
                query: Box::new(query),
                soa: soa.map(Box::new),
                negative_ttl: None,
                response_code,
                trusted,
            }
            .into()
        }
    }

    /// Handle the case where there is no error returned
    fn handle_noerror(
        client: &mut Self,
        options: DnsRequestOptions,
        is_dnssec: bool,
        query: &Query,
        mut response: DnsResponse,
        mut preserved_records: Vec<(Record, u32)>,
    ) -> Result<Records, ResolveError> {
        // initial ttl is what CNAMES for min usage
        const INITIAL_TTL: u32 = dns_lru::MAX_TTL;

        // need to capture these before the subsequent and destructive record processing
        let soa = response.soa();
        let negative_ttl = response.negative_ttl();
        let response_code = response.response_code();

        // seek out CNAMES, this is only performed if the query is not a CNAME, ANY, or SRV
        // FIXME: for SRV this evaluation is inadequate. CNAME is a single chain to a single record
        //   for SRV, there could be many different targets. The search_name needs to be enhanced to
        //   be a list of names found for SRV records.
        let (search_name, cname_ttl, was_cname, preserved_records) = {
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
                    response.answers().iter().fold(
                        (Cow::Borrowed(query.name()), INITIAL_TTL, false),
                        |(search_name, cname_ttl, was_cname), r| {
                            match r.data() {
                                Some(RData::CNAME(ref cname)) => {
                                    // take the minimum TTL of the cname_ttl and the next record in the chain
                                    let ttl = cname_ttl.min(r.ttl());
                                    debug_assert_eq!(r.rr_type(), RecordType::CNAME);
                                    if search_name.as_ref() == r.name() {
                                        return (Cow::Owned(cname.clone()), ttl, true);
                                    }
                                }
                                Some(RData::SRV(ref srv)) => {
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
            let answers = response.take_answers();
            let additionals = response.take_additionals();
            let name_servers = response.take_name_servers();

            // set of names that still require resolution
            // TODO: this needs to be enhanced for SRV
            let mut found_name = false;

            // After following all the CNAMES to the last one, try and lookup the final name
            let records = answers
                .into_iter()
                // Chained records will generally exist in the additionals section
                .chain(additionals.into_iter())
                .chain(name_servers.into_iter())
                .filter_map(|r| {
                    // because this resolved potentially recursively, we want the min TTL from the chain
                    let ttl = cname_ttl.min(r.ttl());
                    // TODO: disable name validation with ResolverOpts? glibc feature...
                    // restrict to the RData type requested
                    if query.query_class() == r.dns_class() {
                        // standard evaluation, it's an any type or it's the requested type and the search_name matches
                        #[allow(clippy::suspicious_operation_groupings)]
                        if (query.query_type().is_any() || query.query_type() == r.rr_type())
                            && (search_name.as_ref() == r.name() || query.name() == r.name())
                        {
                            found_name = true;
                            return Some((r, ttl));
                        }
                        // CNAME evaluation, it's an A/AAAA lookup and the record is from the CNAME lookup chain.
                        if client.preserve_intermediates
                            && r.rr_type() == RecordType::CNAME
                            && (query.query_type() == RecordType::A
                                || query.query_type() == RecordType::AAAA)
                        {
                            return Some((r, ttl));
                        }
                        // srv evaluation, it's an srv lookup and the srv_search_name/target matches this name
                        //    and it's an IP
                        if query.query_type().is_srv()
                            && r.rr_type().is_ip_addr()
                            && search_name.as_ref() == r.name()
                        {
                            found_name = true;
                            Some((r, ttl))
                        } else if query.query_type().is_ns() && r.rr_type().is_ip_addr() {
                            Some((r, ttl))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();

            // adding the newly collected records to the preserved records
            preserved_records.extend(records);
            if !preserved_records.is_empty() && found_name {
                return Ok(Records::Exists(preserved_records));
            }

            (
                search_name.into_owned(),
                cname_ttl,
                was_cname,
                preserved_records,
            )
        };

        // TODO: for SRV records we *could* do an implicit lookup, but, this requires knowing the type of IP desired
        //    for now, we'll make the API require the user to perform a follow up to the lookups.
        // It was a CNAME, but not included in the request...
        if was_cname && client.query_depth.load(Ordering::Acquire) < MAX_QUERY_DEPTH {
            let next_query = Query::query(search_name, query.query_type());
            Ok(Records::CnameChain {
                next: Box::pin(Self::inner_lookup(
                    next_query,
                    options,
                    client.clone(),
                    preserved_records,
                )),
                min_ttl: cname_ttl,
            })
        } else {
            // TODO: review See https://tools.ietf.org/html/rfc2308 for NoData section
            // Note on DNSSec, in secure_client_handle, if verify_nsec fails then the request fails.
            //   this will mean that no unverified negative caches will make it to this point and be stored
            Err(Self::handle_nxdomain(
                is_dnssec,
                true,
                query.clone(),
                soa,
                negative_ttl,
                response_code,
                false,
            ))
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    fn cname(&self, lookup: Lookup, query: Query, cname_ttl: u32) -> Result<Lookup, ResolveError> {
        // this duplicates the cache entry under the original query
        Ok(self.lru.duplicate(query, lookup, cname_ttl, Instant::now()))
    }

    fn cache(
        &self,
        query: Query,
        records: Result<Vec<(Record, u32)>, ResolveError>,
    ) -> Result<Lookup, ResolveError> {
        // this will put this object into an inconsistent state, but no one should call poll again...
        match records {
            Ok(rdata) => Ok(self.lru.insert(query, rdata, Instant::now())),
            Err(err) => Err(self.lru.negative(query, err, Instant::now())),
        }
    }

    /// Flushes/Removes all entries from the cache
    pub fn clear_cache(&mut self) {
        self.lru.clear();
    }
}

enum Records {
    /// The records exists, a vec of rdata with ttl
    Exists(Vec<(Record, u32)>),
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

    use futures_executor::block_on;
    use proto::op::{Message, Query};
    use proto::rr::rdata::SRV;
    use proto::rr::{Name, Record};

    use super::*;
    use crate::lookup_ip::tests::*;

    #[test]
    fn test_empty_cache() {
        let cache = DnsLru::new(1, dns_lru::TtlConfig::default());
        let client = mock(vec![empty()]);
        let client = CachingClient::with_cache(cache, client, false);

        if let ResolveErrorKind::NoRecordsFound {
            query,
            negative_ttl,
            ..
        } = block_on(CachingClient::inner_lookup(
            Query::new(),
            DnsRequestOptions::default(),
            client,
            vec![],
        ))
        .unwrap_err()
        .kind()
        {
            assert_eq!(**query, Query::new());
            assert_eq!(*negative_ttl, None);
        } else {
            panic!("wrong error received")
        }
    }

    #[test]
    fn test_from_cache() {
        let cache = DnsLru::new(1, dns_lru::TtlConfig::default());
        let query = Query::new();
        cache.insert(
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
        let client = CachingClient::with_cache(cache, client, false);

        let ips = block_on(CachingClient::inner_lookup(
            Query::new(),
            DnsRequestOptions::default(),
            client,
            vec![],
        ))
        .unwrap();

        assert_eq!(
            ips.iter().cloned().collect::<Vec<_>>(),
            vec![RData::A(Ipv4Addr::new(127, 0, 0, 1))]
        );
    }

    #[test]
    fn test_no_cache_insert() {
        let cache = DnsLru::new(1, dns_lru::TtlConfig::default());
        // first should come from client...
        let client = mock(vec![v4_message()]);
        let client = CachingClient::with_cache(cache.clone(), client, false);

        let ips = block_on(CachingClient::inner_lookup(
            Query::new(),
            DnsRequestOptions::default(),
            client,
            vec![],
        ))
        .unwrap();

        assert_eq!(
            ips.iter().cloned().collect::<Vec<_>>(),
            vec![RData::A(Ipv4Addr::new(127, 0, 0, 1))]
        );

        // next should come from cache...
        let client = mock(vec![empty()]);
        let client = CachingClient::with_cache(cache, client, false);

        let ips = block_on(CachingClient::inner_lookup(
            Query::new(),
            DnsRequestOptions::default(),
            client,
            vec![],
        ))
        .unwrap();

        assert_eq!(
            ips.iter().cloned().collect::<Vec<_>>(),
            vec![RData::A(Ipv4Addr::new(127, 0, 0, 1))]
        );
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn cname_message() -> Result<DnsResponse, ResolveError> {
        let mut message = Message::new();
        message.add_query(Query::query(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::A,
        ));
        message.insert_answers(vec![Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            86400,
            RData::CNAME(Name::from_str("actual.example.com.").unwrap()),
        )]);
        Ok(message.into())
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn srv_message() -> Result<DnsResponse, ResolveError> {
        let mut message = Message::new();
        message.add_query(Query::query(
            Name::from_str("_443._tcp.www.example.com.").unwrap(),
            RecordType::SRV,
        ));
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

    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn ns_message() -> Result<DnsResponse, ResolveError> {
        let mut message = Message::new();
        message.add_query(Query::query(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::NS,
        ));
        message.insert_answers(vec![Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            86400,
            RData::NS(Name::from_str("www.example.com.").unwrap()),
        )]);
        Ok(message.into())
    }

    fn no_recursion_on_query_test(query_type: RecordType) {
        let cache = DnsLru::new(1, dns_lru::TtlConfig::default());

        // the cname should succeed, we shouldn't query again after that, which would cause an error...
        let client = mock(vec![error(), cname_message()]);
        let client = CachingClient::with_cache(cache, client, false);

        let ips = block_on(CachingClient::inner_lookup(
            Query::query(Name::from_str("www.example.com.").unwrap(), query_type),
            DnsRequestOptions::default(),
            client,
            vec![],
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
        let cache = DnsLru::new(1, dns_lru::TtlConfig::default());

        // the cname should succeed, we shouldn't query again after that, which would cause an error...
        let client = mock(vec![error(), srv_message()]);
        let client = CachingClient::with_cache(cache, client, false);

        let ips = block_on(CachingClient::inner_lookup(
            Query::query(
                Name::from_str("_443._tcp.www.example.com.").unwrap(),
                RecordType::SRV,
            ),
            DnsRequestOptions::default(),
            client,
            vec![],
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
        let cache = DnsLru::new(1, dns_lru::TtlConfig::default());

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
        let client = CachingClient::with_cache(cache, client, false);

        let ips = block_on(CachingClient::inner_lookup(
            Query::query(
                Name::from_str("_443._tcp.www.example.com.").unwrap(),
                RecordType::SRV,
            ),
            DnsRequestOptions::default(),
            client,
            vec![],
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

    #[test]
    fn test_single_ns_query_response() {
        let cache = DnsLru::new(1, dns_lru::TtlConfig::default());

        let mut message = ns_message().unwrap();
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
        let client = CachingClient::with_cache(cache, client, false);

        let ips = block_on(CachingClient::inner_lookup(
            Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::NS),
            DnsRequestOptions::default(),
            client,
            vec![],
        ))
        .expect("lookup failed");

        assert_eq!(
            ips.iter().cloned().collect::<Vec<_>>(),
            vec![
                RData::NS(Name::from_str("www.example.com.").unwrap()),
                RData::A(Ipv4Addr::new(127, 0, 0, 1)),
                RData::AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ]
        );
    }

    fn cname_ttl_test(first: u32, second: u32) {
        let lru = DnsLru::new(1, dns_lru::TtlConfig::default());
        // expecting no queries to be performed
        let mut client = CachingClient::with_cache(lru, mock(vec![error()]), false);

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
            DnsRequestOptions::default(),
            false,
            &Query::query(Name::from_str("ttl.example.com.").unwrap(), RecordType::A),
            message.into(),
            vec![],
        );

        if let Ok(records) = records {
            if let Records::Exists(records) = records {
                for (record, ttl) in records.iter() {
                    if record.record_type() == RecordType::CNAME {
                        continue;
                    }
                    assert_eq!(ttl, &1);
                }
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
        let cache = DnsLru::new(0, dns_lru::TtlConfig::default());
        let client = mock(vec![empty()]);
        let mut client = CachingClient::with_cache(cache, client, false);

        {
            let query = Query::query(Name::from_ascii("localhost.").unwrap(), RecordType::A);
            let lookup = block_on(client.lookup(query.clone(), DnsRequestOptions::default()))
                .expect("should have returned localhost");
            assert_eq!(lookup.query(), &query);
            assert_eq!(
                lookup.iter().cloned().collect::<Vec<_>>(),
                vec![LOCALHOST_V4.clone()]
            );
        }

        {
            let query = Query::query(Name::from_ascii("localhost.").unwrap(), RecordType::AAAA);
            let lookup = block_on(client.lookup(query.clone(), DnsRequestOptions::default()))
                .expect("should have returned localhost");
            assert_eq!(lookup.query(), &query);
            assert_eq!(
                lookup.iter().cloned().collect::<Vec<_>>(),
                vec![LOCALHOST_V6.clone()]
            );
        }

        {
            let query = Query::query(Name::from(Ipv4Addr::new(127, 0, 0, 1)), RecordType::PTR);
            let lookup = block_on(client.lookup(query.clone(), DnsRequestOptions::default()))
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
            let lookup = block_on(client.lookup(query.clone(), DnsRequestOptions::default()))
                .expect("should have returned localhost");
            assert_eq!(lookup.query(), &query);
            assert_eq!(
                lookup.iter().cloned().collect::<Vec<_>>(),
                vec![LOCALHOST.clone()]
            );
        }

        assert!(block_on(client.lookup(
            Query::query(Name::from_ascii("localhost.").unwrap(), RecordType::MX),
            DnsRequestOptions::default()
        ))
        .is_err());

        assert!(block_on(client.lookup(
            Query::query(Name::from(Ipv4Addr::new(127, 0, 0, 1)), RecordType::MX),
            DnsRequestOptions::default()
        ))
        .is_err());

        assert!(block_on(client.lookup(
            Query::query(
                Name::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                RecordType::MX
            ),
            DnsRequestOptions::default()
        ))
        .is_err());
    }

    #[test]
    fn test_early_return_invalid() {
        let cache = DnsLru::new(0, dns_lru::TtlConfig::default());
        let client = mock(vec![empty()]);
        let mut client = CachingClient::with_cache(cache, client, false);

        assert!(block_on(client.lookup(
            Query::query(
                Name::from_ascii("horrible.invalid.").unwrap(),
                RecordType::A,
            ),
            DnsRequestOptions::default()
        ))
        .is_err());
    }

    #[test]
    fn test_no_error_on_dot_local_no_mdns() {
        let cache = DnsLru::new(1, dns_lru::TtlConfig::default());

        let mut message = srv_message().unwrap();
        message.add_query(Query::query(
            Name::from_ascii("www.example.local.").unwrap(),
            RecordType::A,
        ));
        message.add_answer(Record::from_rdata(
            Name::from_str("www.example.local.").unwrap(),
            86400,
            RData::A(Ipv4Addr::new(127, 0, 0, 1)),
        ));

        let client = mock(vec![error(), Ok(message)]);
        let mut client = CachingClient::with_cache(cache, client, false);

        assert!(block_on(client.lookup(
            Query::query(
                Name::from_ascii("www.example.local.").unwrap(),
                RecordType::A,
            ),
            DnsRequestOptions::default()
        ))
        .is_ok());
    }
}
