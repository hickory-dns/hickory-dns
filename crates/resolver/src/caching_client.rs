// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Caching related functionality for the Resolver.

use std::{
    borrow::Cow,
    future::Future,
    time::{Duration, Instant},
};

use once_cell::sync::Lazy;

use crate::{
    cache::{MAX_TTL, ResponseCache, TtlConfig},
    lookup::Lookup,
    net::{
        DnsError, NetError, NoRecords,
        xfer::{DnsHandle, FirstAnswer},
    },
    proto::{
        op::{DnsRequestOptions, DnsResponse, Message, OpCode, Query, ResponseCode},
        rr::{
            DNSClass, Name, RData, Record, RecordType,
            domain::usage::{
                DEFAULT, IN_ADDR_ARPA_127, INVALID, IP6_ARPA_1, LOCAL,
                LOCALHOST as LOCALHOST_usage, ONION, ResolverUsage,
            },
            rdata::{A, AAAA, CNAME, PTR},
            resource::RecordRef,
        },
    },
};

static LOCALHOST: Lazy<RData> =
    Lazy::new(|| RData::PTR(PTR(Name::from_ascii("localhost.").unwrap())));
static LOCALHOST_V4: Lazy<RData> = Lazy::new(|| RData::A(A::new(127, 0, 0, 1)));
static LOCALHOST_V6: Lazy<RData> = Lazy::new(|| RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1)));

/// Counts the depth of CNAME query resolutions.
#[derive(Default, Clone, Copy)]
struct DepthTracker {
    query_depth: u8,
}

impl DepthTracker {
    fn nest(self) -> Self {
        Self {
            query_depth: self.query_depth + 1,
        }
    }

    fn is_exhausted(self) -> bool {
        self.query_depth + 1 >= Self::MAX_QUERY_DEPTH
    }

    const MAX_QUERY_DEPTH: u8 = 8; // arbitrarily chosen number...
}

#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct CachingClient<C>
where
    C: DnsHandle,
{
    cache: ResponseCache,
    client: C,
    preserve_intermediates: bool,
}

impl<C> CachingClient<C>
where
    C: DnsHandle + Send + 'static,
{
    #[doc(hidden)]
    pub fn new(max_size: u64, client: C, preserve_intermediates: bool) -> Self {
        Self::with_cache(
            ResponseCache::new(max_size, TtlConfig::default()),
            client,
            preserve_intermediates,
        )
    }

    pub(crate) fn with_cache(
        cache: ResponseCache,
        client: C,
        preserve_intermediates: bool,
    ) -> Self {
        Self {
            cache,
            client,
            preserve_intermediates,
        }
    }

    /// Perform a lookup against this caching client, looking first in the cache for a result
    pub fn lookup(
        &self,
        query: Query,
        options: DnsRequestOptions,
    ) -> impl Future<Output = Result<Lookup, NetError>> {
        Self::inner_lookup(
            query,
            options,
            self.clone(),
            vec![],
            DepthTracker::default(),
        )
    }

    async fn inner_lookup(
        query: Query,
        options: DnsRequestOptions,
        mut client: Self,
        preserved_records: Vec<Record>,
        depth: DepthTracker,
    ) -> Result<Lookup, NetError> {
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
                    // Are there any other types we can use?
                    _ => return Err(NoRecords::new(query, ResponseCode::NoError).into()),
                },
                // TODO: this requires additional config, as Kubernetes and other systems misuse the .local. zone.
                // when mdns is not enabled we will return errors on LinkLocal ("*.local.") names
                ResolverUsage::LinkLocal => (),
                ResolverUsage::NxDomain => {
                    return Err(NoRecords::new(query, ResponseCode::NXDomain).into());
                }
                ResolverUsage::Normal => (),
            }
        }

        let is_dnssec = client.client.is_verifying_dnssec();

        if let Some(cached_lookup) = client.lookup_from_cache(&query) {
            return cached_lookup;
        };

        let response_message = client
            .client
            .lookup(query.clone(), options)
            .first_answer()
            .await;

        // TODO: technically this might be duplicating work, as name_server already performs this evaluation.
        //  we may want to create a new type, if evaluated... but this is most generic to support any impl in LookupState...
        let response_message = if let Ok(response) = response_message {
            DnsError::from_response(response).map_err(NetError::from)
        } else {
            response_message
        };

        // TODO: take all records and cache them?
        //  if it's DNSSEC they must be signed, otherwise?
        let records = match response_message {
            Ok(response_message) => {
                // allow the handle_noerror function to deal with any error codes
                let records = Self::handle_noerror(
                    &mut client,
                    options,
                    &query,
                    response_message,
                    preserved_records,
                    depth,
                )?;

                Ok(records)
            }
            // this is the only cacheable form
            Err(NetError::Dns(DnsError::NoRecordsFound(mut no_records))) => {
                if is_dnssec {
                    no_records.negative_ttl = None;
                }
                Err(no_records.into())
            }
            Err(err) => return Err(err),
        };

        // after the request, evaluate if we have additional queries to perform
        match records {
            Ok(Records::CnameChain { next: future, .. }) => match future.await {
                Ok(lookup) => client.cname(lookup, query),
                Err(e) => client.cache(query, Err(e)),
            },
            Ok(Records::Exists { message, min_ttl }) => client.cache(query, Ok((message, min_ttl))),
            Err(e) => client.cache(query, Err(e)),
        }
    }

    /// Check if this query is already cached
    fn lookup_from_cache(&self, query: &Query) -> Option<Result<Lookup, NetError>> {
        let now = Instant::now();
        let message_res = self.cache.get(query, now)?;
        let message = match message_res {
            Ok(message) => message,
            Err(err) => return Some(Err(err)),
        };

        let valid_until = now
            + Duration::from_secs(
                message
                    .answers()
                    .iter()
                    .map(Record::ttl)
                    .min()
                    .unwrap_or(MAX_TTL)
                    .into(),
            );

        Some(Ok(Lookup::new(message, valid_until)))
    }

    /// Handle the case where there is no error returned
    fn handle_noerror(
        client: &mut Self,
        options: DnsRequestOptions,
        query: &Query,
        response: DnsResponse,
        mut preserved_records: Vec<Record>,
        depth: DepthTracker,
    ) -> Result<Records<impl Future<Output = Result<Lookup, NetError>>>, NetError> {
        // TODO: there should be a ResolverOpts config to disable the
        // name validation in this function to more closely match the
        // behaviour of glibc if that's what the user expects.

        // initial ttl is what CNAMES use for min usage
        const INITIAL_TTL: u32 = MAX_TTL;

        // need to capture these before the subsequent and destructive record processing
        let soa = response.soa().as_ref().map(RecordRef::to_owned);
        let negative_ttl = response.negative_ttl();
        let response_code = response.response_code();

        // seek out CNAMES, this is only performed if the query is not a CNAME, ANY, or SRV
        // FIXME: for SRV this evaluation is inadequate. CNAME is a single chain to a single record
        //   for SRV, there could be many different targets. The search_name needs to be enhanced to
        //   be a list of names found for SRV records.
        let (search_name, was_cname, preserved_records) = {
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
                                RData::CNAME(CNAME(cname)) => {
                                    // take the minimum TTL of the cname_ttl and the next record in the chain
                                    let ttl = cname_ttl.min(r.ttl());
                                    debug_assert_eq!(r.record_type(), RecordType::CNAME);
                                    if search_name.as_ref() == r.name() {
                                        return (Cow::Owned(cname.clone()), ttl, true);
                                    }
                                }
                                RData::SRV(srv) => {
                                    // take the minimum TTL of the cname_ttl and the next record in the chain
                                    let ttl = cname_ttl.min(r.ttl());
                                    debug_assert_eq!(r.record_type(), RecordType::SRV);

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
            let mut message = response.into_message();

            // set of names that still require resolution
            // TODO: this needs to be enhanced for SRV
            let mut found_name = false;
            let mut found_cname_target = false;
            let mut min_ttl = cname_ttl;

            // Scan through all sections to determine what we found and calculate minimum TTL
            // We need this first pass to decide our strategy: return complete message vs filter
            for r in message.all_sections() {
                // because this resolved potentially recursively, we want the min TTL from the chain
                min_ttl = min_ttl.min(r.ttl());

                // restrict to the RData type requested
                if query.query_class() != r.dns_class() {
                    continue;
                }

                // standard evaluation, it's an any type, or it's the requested type and the
                // search_name matches
                let type_matches =
                    query.query_type().is_any() || query.query_type() == r.record_type();
                let name_matches = search_name.as_ref() == r.name() || query.name() == r.name();
                if type_matches && name_matches {
                    found_name = true;
                    // Track if we found the CNAME target (not just the original name)
                    if was_cname && search_name.as_ref() == r.name() {
                        found_cname_target = true;
                    }
                }
            }

            // After following all the CNAMES to the last one, try and lookup the final name
            if found_name && (!was_cname || preserved_records.is_empty()) {
                // Decide strategy: do we need to filter, or return the message as-is?
                // - If we have accumulated records from previous CNAME hops → must filter and merge
                // - If we found the CNAME target in this response → filter out intermediate CNAMEs
                //   (unless preserve_intermediates)
                // - Otherwise → return complete message to preserve all sections exactly as DNS server
                //   sent them
                let needs_filtering = !preserved_records.is_empty()
                    || (found_cname_target && !client.preserve_intermediates);

                if needs_filtering {
                    // Filter records that belong in ANSWER section only
                    // Don't include records from ADDITIONAL/AUTHORITY here - they're preserved as-is below
                    preserved_records.extend(message.all_sections().filter_map(|r| {
                        // because this resolved potentially recursively, we want the min TTL from the chain
                        let ttl = cname_ttl.min(r.ttl());
                        let mut r = r.clone();
                        r.set_ttl(ttl);

                        // restrict to the RData type requested
                        if query.query_class() != r.dns_class() {
                            return None;
                        }

                        // standard evaluation, it's an any type, or it's the requested type
                        // and the search_name matches
                        let query_type = query.query_type();
                        let record_type = r.record_type();
                        let type_matches = query_type.is_any() || query_type == record_type;
                        let name_matches =
                            search_name.as_ref() == r.name() || query.name() == r.name();
                        if type_matches && name_matches {
                            return Some(r);
                        }

                        // CNAME evaluation, the record is from the CNAME lookup chain.
                        if client.preserve_intermediates && record_type == RecordType::CNAME {
                            return Some(r);
                        }

                        // Note: NS glue and SRV target IPs are NOT included here
                        // They belong in ADDITIONAL section and are preserved below via insert_additionals
                        None
                    }));

                    // Replace ANSWER section with filtered records, preserve AUTHORITY and ADDITIONAL sections
                    *message.answers_mut() = preserved_records;
                }

                // Strip DNSSEC records if DO bit is not set.
                message = message.maybe_strip_dnssec_records(options.edns_set_dnssec_ok);

                return Ok(Records::Exists { message, min_ttl });
            }

            // We didn't find the answer - need to continue following CNAME chain
            // Only accumulate ANSWER-section records (CNAMEs) for next hop
            // AUTHORITY and ADDITIONAL records stay with their original message and are not carried forward
            preserved_records.extend(message.take_all_sections().filter_map(|mut r| {
                // because this resolved potentially recursively, we want the min TTL from the chain
                let ttl = cname_ttl.min(r.ttl());
                r.set_ttl(ttl);

                // restrict to the RData type requested
                if query.query_class() != r.dns_class() {
                    return None;
                }

                // CNAME evaluation, the record is from the CNAME lookup chain.
                if client.preserve_intermediates && r.record_type() == RecordType::CNAME {
                    return Some(r);
                }

                // Note: NS glue and SRV target IPs are NOT accumulated across hops
                // They belong in ADDITIONAL section of their original response, not in ANSWER
                None
            }));

            (search_name.into_owned(), was_cname, preserved_records)
        };

        // TODO: for SRV records we *could* do an implicit lookup, but, this requires knowing the type of IP desired
        //    for now, we'll make the API require the user to perform a follow up to the lookups.
        // It was a CNAME, but not included in the request...
        if was_cname && !depth.is_exhausted() {
            let next_query = Query::query(search_name, query.query_type());
            Ok(Records::CnameChain {
                next: Box::pin(Self::inner_lookup(
                    next_query,
                    options,
                    client.clone(),
                    #[cfg(test)]
                    preserved_records.clone(),
                    #[cfg(not(test))]
                    preserved_records,
                    depth.nest(),
                )),
                #[cfg(test)]
                preserved_records,
            })
        } else {
            // TODO: review See https://tools.ietf.org/html/rfc2308 for NoData section
            // Note on DNSSEC, in secure_client_handle, if verify_nsec fails then the request fails.
            //   this will mean that no unverified negative caches will make it to this point and be stored
            let mut new = NoRecords::new(query.clone(), response_code);
            new.soa = soa.map(Box::new);
            new.negative_ttl = negative_ttl;
            Err(new.into())
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    fn cname(&self, lookup: Lookup, query: Query) -> Result<Lookup, NetError> {
        let mut message = Message::response(0, OpCode::Query);
        message.add_query(query.clone());
        message.add_answers(lookup.answers().iter().cloned());
        message.add_authorities(lookup.authorities().iter().cloned());
        message.add_additionals(lookup.additionals().iter().cloned());
        self.cache.insert(query, Ok(message), Instant::now());
        Ok(lookup)
    }

    fn cache(
        &self,
        query: Query,
        result: Result<(Message, u32), NetError>,
    ) -> Result<Lookup, NetError> {
        let now = Instant::now();
        match result {
            Ok((message, min_ttl)) => {
                let valid_until = now + Duration::from_secs(min_ttl.into());
                let lookup = Lookup::new(message.clone(), valid_until);
                self.cache.insert(query, Ok(message), now);
                Ok(lookup)
            }
            Err(err) => {
                self.cache.insert(query, Err(err.clone()), now);
                Err(err)
            }
        }
    }

    /// Flushes/Removes all entries from the cache
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Flushes/Removes the entry from the cache that is associated with this query
    pub fn clear_cache_query(&self, query: &Query) {
        self.cache.clear_query(query);
    }
}

enum Records<F> {
    /// The records exist, stored as a complete DNS Message
    Exists { message: Message, min_ttl: u32 },
    /// Future lookup for recursive cname records
    CnameChain {
        next: F,
        #[cfg(test)]
        preserved_records: Vec<Record>,
    },
}

// see also the lookup_tests.rs in integration-tests crate
#[cfg(test)]
mod tests {
    use std::net::*;
    use std::str::FromStr;
    use std::time::*;

    use futures_executor::block_on;
    use test_support::subscribe;

    use super::*;
    use crate::cache::TtlConfig;
    use crate::lookup_ip::tests::*;
    use crate::proto::op::{Message, Query};
    use crate::proto::rr::rdata::{NS, SRV};
    use crate::proto::rr::{Name, Record};

    #[test]
    fn test_empty_cache() {
        subscribe();
        let cache = ResponseCache::new(1, TtlConfig::default());
        let client = mock(vec![empty()]);
        let client = CachingClient::with_cache(cache, client, false);

        let error = block_on(CachingClient::inner_lookup(
            Query::new(),
            DnsRequestOptions::default(),
            client,
            vec![],
            DepthTracker::default(),
        ))
        .unwrap_err();

        let NetError::Dns(DnsError::NoRecordsFound(no_records)) = error else {
            panic!("wrong error received")
        };

        assert_eq!(no_records.query, Box::new(Query::new()));
        assert_eq!(no_records.negative_ttl, None);
    }

    #[test]
    fn test_from_cache() {
        subscribe();
        let cache = ResponseCache::new(1, TtlConfig::default());
        let query = Query::new();
        let mut message = Message::response(0, OpCode::Query);
        message.add_query(query.clone());
        message.add_answer(Record::from_rdata(
            query.name().clone(),
            u32::MAX,
            RData::A(A::new(127, 0, 0, 1)),
        ));
        cache.insert(query.clone(), Ok(message), Instant::now());

        let client = mock(vec![empty()]);
        let client = CachingClient::with_cache(cache, client, false);

        let ips = block_on(CachingClient::inner_lookup(
            Query::new(),
            DnsRequestOptions::default(),
            client,
            vec![],
            DepthTracker::default(),
        ))
        .unwrap();

        assert_eq!(
            ips.answers(),
            &[Record::from_rdata(
                query.name().clone(),
                u32::MAX,
                RData::A(A::new(127, 0, 0, 1))
            )]
        );
    }

    #[test]
    fn test_no_cache_insert() {
        subscribe();
        let cache = ResponseCache::new(1, TtlConfig::default());
        // first should come from client...
        let client = mock(vec![v4_message()]);
        let client = CachingClient::with_cache(cache.clone(), client, false);

        let ips = block_on(CachingClient::inner_lookup(
            Query::query(Name::root(), RecordType::A),
            DnsRequestOptions::default(),
            client,
            vec![],
            DepthTracker::default(),
        ))
        .unwrap();

        assert_eq!(
            ips.answers(),
            &[Record::from_rdata(
                Name::root(),
                86400,
                RData::A(A::new(127, 0, 0, 1))
            )]
        );

        // next should come from cache...
        let client = mock(vec![empty()]);
        let client = CachingClient::with_cache(cache, client, false);

        let ips = block_on(CachingClient::inner_lookup(
            Query::query(Name::root(), RecordType::A),
            DnsRequestOptions::default(),
            client,
            vec![],
            DepthTracker::default(),
        ))
        .unwrap();

        assert_eq!(
            ips.answers(),
            &[Record::from_rdata(
                Name::root(),
                86400,
                RData::A(A::new(127, 0, 0, 1))
            )]
        );
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn cname_message() -> Result<DnsResponse, NetError> {
        let mut message = Message::query();
        message.add_query(Query::query(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::A,
        ));
        message.insert_answers(vec![Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            86400,
            RData::CNAME(CNAME(Name::from_str("actual.example.com.").unwrap())),
        )]);
        Ok(DnsResponse::from_message(message).unwrap())
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn srv_message() -> Result<DnsResponse, NetError> {
        let mut message = Message::query();
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
        Ok(DnsResponse::from_message(message).unwrap())
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn ns_message() -> Result<DnsResponse, NetError> {
        let mut message = Message::query();
        message.add_query(Query::query(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::NS,
        ));
        message.insert_answers(vec![Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            86400,
            RData::NS(NS(Name::from_str("www.example.com.").unwrap())),
        )]);
        Ok(DnsResponse::from_message(message).unwrap())
    }

    fn no_recursion_on_query_test(query_type: RecordType) {
        let cache = ResponseCache::new(1, TtlConfig::default());

        // the cname should succeed, we shouldn't query again after that, which would cause an error...
        let client = mock(vec![error(), cname_message()]);
        let client = CachingClient::with_cache(cache, client, false);

        let ips = block_on(CachingClient::inner_lookup(
            Query::query(Name::from_str("www.example.com.").unwrap(), query_type),
            DnsRequestOptions::default(),
            client,
            vec![],
            DepthTracker::default(),
        ))
        .expect("lookup failed");

        assert_eq!(
            ips.answers(),
            &[Record::from_rdata(
                Name::from_str("www.example.com.").unwrap(),
                86400,
                RData::CNAME(CNAME(Name::from_str("actual.example.com.").unwrap()))
            )]
        );
    }

    #[test]
    fn test_no_recursion_on_cname_query() {
        subscribe();
        no_recursion_on_query_test(RecordType::CNAME);
    }

    #[test]
    fn test_no_recursion_on_all_query() {
        subscribe();
        no_recursion_on_query_test(RecordType::ANY);
    }

    #[test]
    fn test_non_recursive_srv_query() {
        subscribe();

        let cache = ResponseCache::new(1, TtlConfig::default());

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
            DepthTracker::default(),
        ))
        .expect("lookup failed");

        assert_eq!(
            ips.answers(),
            &[Record::from_rdata(
                Name::from_str("_443._tcp.www.example.com.").unwrap(),
                86400,
                RData::SRV(SRV::new(
                    1,
                    2,
                    443,
                    Name::from_str("www.example.com.").unwrap(),
                ))
            )]
        );
    }

    #[test]
    fn test_single_srv_query_response() {
        subscribe();

        let cache = ResponseCache::new(1, TtlConfig::default());

        let mut message = srv_message().unwrap().into_message();
        message.add_answer(Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            86400,
            RData::CNAME(CNAME(Name::from_str("actual.example.com.").unwrap())),
        ));
        message.insert_additionals(vec![
            Record::from_rdata(
                Name::from_str("actual.example.com.").unwrap(),
                86400,
                RData::A(A::new(127, 0, 0, 1)),
            ),
            Record::from_rdata(
                Name::from_str("actual.example.com.").unwrap(),
                86400,
                RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ),
        ]);

        let client = mock(vec![
            error(),
            Ok(DnsResponse::from_message(message).unwrap()),
        ]);
        let client = CachingClient::with_cache(cache, client, false);

        let ips = block_on(CachingClient::inner_lookup(
            Query::query(
                Name::from_str("_443._tcp.www.example.com.").unwrap(),
                RecordType::SRV,
            ),
            DnsRequestOptions::default(),
            client,
            vec![],
            DepthTracker::default(),
        ))
        .expect("lookup failed");

        // Answers section should have SRV + CNAME
        let answers = ips
            .answers()
            .iter()
            .map(|r| r.data().clone())
            .collect::<Vec<_>>();
        assert!(answers.contains(&RData::SRV(SRV::new(
            1,
            2,
            443,
            Name::from_str("www.example.com.").unwrap(),
        ))));
        assert!(answers.contains(&RData::CNAME(CNAME(
            Name::from_str("actual.example.com.").unwrap()
        ))));

        // Additionals section should have A + AAAA records
        let additionals = ips
            .additionals()
            .iter()
            .map(|r| r.data().clone())
            .collect::<Vec<_>>();
        assert!(additionals.contains(&RData::A(A::new(127, 0, 0, 1))));
        assert!(additionals.contains(&RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1))));
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
    //             RData::A(Ipv4Addr::LOCALHOST),
    //         ),
    //     ]);

    //     let mut client = mock(vec![error(), Ok(DnsResponse::from_message(message).unwrap()), srv_message()]);

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
    //             RData::A(Ipv4Addr::LOCALHOST),
    //             //RData::AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
    //         ]
    //     );
    // }

    #[test]
    fn test_single_ns_query_response() {
        subscribe();

        let cache = ResponseCache::new(1, TtlConfig::default());

        let mut message = ns_message().unwrap().into_message();
        message.add_answer(Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            86400,
            RData::CNAME(CNAME(Name::from_str("actual.example.com.").unwrap())),
        ));
        message.insert_additionals(vec![
            Record::from_rdata(
                Name::from_str("actual.example.com.").unwrap(),
                86400,
                RData::A(A::new(127, 0, 0, 1)),
            ),
            Record::from_rdata(
                Name::from_str("actual.example.com.").unwrap(),
                86400,
                RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ),
        ]);

        let client = mock(vec![
            error(),
            Ok(DnsResponse::from_message(message).unwrap()),
        ]);
        let client = CachingClient::with_cache(cache, client, false);

        let ips = block_on(CachingClient::inner_lookup(
            Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::NS),
            DnsRequestOptions::default(),
            client,
            vec![],
            DepthTracker::default(),
        ))
        .expect("lookup failed");

        // Answers section should have NS + CNAME
        let answers = ips
            .answers()
            .iter()
            .map(|r| r.data().clone())
            .collect::<Vec<_>>();
        assert!(answers.contains(&RData::NS(NS(Name::from_str("www.example.com.").unwrap()))));
        assert!(answers.contains(&RData::CNAME(CNAME(
            Name::from_str("actual.example.com.").unwrap()
        ))));

        // Additionals section should have A + AAAA records
        let additionals = ips
            .additionals()
            .iter()
            .map(|r| r.data().clone())
            .collect::<Vec<_>>();
        assert!(additionals.contains(&RData::A(A::new(127, 0, 0, 1))));
        assert!(additionals.contains(&RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1))));
    }

    /// Purpose: Verify glue records stay in ADDITIONAL section
    ///
    /// This test ensures that when querying for NS records, the glue A records for those
    /// nameservers stay in the ADDITIONAL section and do NOT leak into the ANSWER section.
    #[test]
    fn test_ns_query_glue_in_additional_section() {
        subscribe();

        let cache = ResponseCache::new(1, TtlConfig::default());

        // Create NS query response for example.com with glue in ADDITIONAL section
        let mut message = Message::response(0, OpCode::Query);
        message.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::NS,
        ));

        // ANSWER section: NS records
        message.insert_answers(vec![
            Record::from_rdata(
                Name::from_str("example.com.").unwrap(),
                3600,
                RData::NS(NS(Name::from_str("ns1.example.com.").unwrap())),
            ),
            Record::from_rdata(
                Name::from_str("example.com.").unwrap(),
                3600,
                RData::NS(NS(Name::from_str("ns2.example.com.").unwrap())),
            ),
        ]);

        // ADDITIONAL section: Glue A records for the nameservers
        message.insert_additionals(vec![
            Record::from_rdata(
                Name::from_str("ns1.example.com.").unwrap(),
                3600,
                RData::A(A::new(192, 0, 2, 1)),
            ),
            Record::from_rdata(
                Name::from_str("ns2.example.com.").unwrap(),
                3600,
                RData::A(A::new(192, 0, 2, 2)),
            ),
        ]);

        let client = mock(vec![
            error(),
            Ok(DnsResponse::from_message(message).unwrap()),
        ]);
        let client = CachingClient::with_cache(cache, client, false);

        let lookup = block_on(CachingClient::inner_lookup(
            Query::query(Name::from_str("example.com.").unwrap(), RecordType::NS),
            DnsRequestOptions::default(),
            client,
            vec![],
            DepthTracker::default(),
        ))
        .expect("lookup failed");

        // Verify: NS records in ANSWER section only
        let answers = lookup.answers().iter().collect::<Vec<_>>();
        assert_eq!(
            answers.len(),
            2,
            "Should have exactly 2 NS records in ANSWER"
        );

        // Verify all answer records are NS type
        for answer in &answers {
            assert_eq!(
                answer.record_type(),
                RecordType::NS,
                "All ANSWER section records should be NS type"
            );
        }

        // Verify: Glue A records in ADDITIONAL section only
        let additionals = lookup.additionals().iter().collect::<Vec<_>>();
        assert_eq!(
            additionals.len(),
            2,
            "Should have exactly 2 glue A records in ADDITIONAL"
        );

        // Verify all additional records are A type
        for additional in &additionals {
            assert_eq!(
                additional.record_type(),
                RecordType::A,
                "All ADDITIONAL section records should be A type (glue records)"
            );
        }

        // Verify glue records do NOT appear in ANSWER section
        for answer in &answers {
            assert_ne!(
                answer.record_type(),
                RecordType::A,
                "A records (glue) should NEVER appear in ANSWER for NS query - this was the original bug!"
            );
        }

        // Verify AUTHORITY section is empty
        assert_eq!(
            lookup.authorities().len(),
            0,
            "AUTHORITY section should be empty"
        );
    }

    /// Purpose: Verify sections preserved when CNAME and target in same response
    ///
    /// This test verifies that when a CNAME and its target appear in the same DNS response,
    /// the AUTHORITY and ADDITIONAL sections are preserved correctly, and filtering only
    /// affects the ANSWER section when preserve_intermediates=false.
    #[test]
    fn test_single_hop_cname_preserves_sections() {
        subscribe();

        let cache = ResponseCache::new(1, TtlConfig::default());

        // Create a response with CNAME + A in ANSWER, plus AUTHORITY and ADDITIONAL sections
        let mut message = Message::response(0, OpCode::Query);
        message.add_query(Query::query(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::A,
        ));

        // ANSWER section: CNAME + A record
        message.insert_answers(vec![
            Record::from_rdata(
                Name::from_str("www.example.com.").unwrap(),
                300,
                RData::CNAME(CNAME(Name::from_str("v4.example.com.").unwrap())),
            ),
            Record::from_rdata(
                Name::from_str("v4.example.com.").unwrap(),
                300,
                RData::A(A::new(192, 0, 2, 1)),
            ),
        ]);

        // AUTHORITY section: NS record
        message.insert_authorities(vec![Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            3600,
            RData::NS(NS(Name::from_str("ns1.example.com.").unwrap())),
        )]);

        // ADDITIONAL section: Glue for NS
        message.insert_additionals(vec![Record::from_rdata(
            Name::from_str("ns1.example.com.").unwrap(),
            3600,
            RData::A(A::new(192, 0, 2, 10)),
        )]);

        let client = mock(vec![
            error(),
            Ok(DnsResponse::from_message(message).unwrap()),
        ]);
        let client = CachingClient::with_cache(cache, client, false); // preserve_intermediates=false

        let lookup = block_on(CachingClient::inner_lookup(
            Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A),
            DnsRequestOptions::default(),
            client,
            vec![],
            DepthTracker::default(),
        ))
        .expect("lookup failed");

        // Verify ANSWER: Only A record (CNAME filtered out because target was found)
        let answers = lookup.answers().iter().collect::<Vec<_>>();
        assert_eq!(
            answers.len(),
            1,
            "ANSWER should have 1 record (CNAME filtered)"
        );
        assert_eq!(
            answers[0].record_type(),
            RecordType::A,
            "ANSWER should contain only the A record"
        );
        match answers[0].data() {
            RData::A(a) => assert_eq!(a, &A::new(192, 0, 2, 1), "A record should have correct IP"),
            _ => panic!("wrong rdata type"),
        }

        // Verify AUTHORITY: NS record preserved
        let authorities = lookup.authorities().iter().collect::<Vec<_>>();
        assert_eq!(
            authorities.len(),
            1,
            "AUTHORITY section should be preserved"
        );
        assert_eq!(
            authorities[0].record_type(),
            RecordType::NS,
            "AUTHORITY should contain NS record"
        );

        // Verify ADDITIONAL: Glue preserved
        let additionals = lookup.additionals().iter().collect::<Vec<_>>();
        assert_eq!(
            additionals.len(),
            1,
            "ADDITIONAL section should be preserved"
        );
        assert_eq!(
            additionals[0].record_type(),
            RecordType::A,
            "ADDITIONAL should contain glue A record"
        );
        match additionals[0].data() {
            RData::A(a) => assert_eq!(
                a,
                &A::new(192, 0, 2, 10),
                "Glue record should have correct IP"
            ),
            _ => panic!("wrong rdata type"),
        }
    }

    /// test_single_hop_cname_with_preserve_intermediates
    ///
    /// Purpose: Verify CNAME is kept when preserve_intermediates=true
    ///
    /// Same setup as Test 2.1 but with preserve_intermediates=true, so the CNAME
    /// should be kept in the ANSWER section along with the A record.
    #[test]
    fn test_single_hop_cname_with_preserve_intermediates() {
        subscribe();

        let cache = ResponseCache::new(1, TtlConfig::default());

        // Same response as Test 2.1
        let mut message = Message::response(0, OpCode::Query);
        message.add_query(Query::query(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::A,
        ));

        message.insert_answers(vec![
            Record::from_rdata(
                Name::from_str("www.example.com.").unwrap(),
                300,
                RData::CNAME(CNAME(Name::from_str("v4.example.com.").unwrap())),
            ),
            Record::from_rdata(
                Name::from_str("v4.example.com.").unwrap(),
                300,
                RData::A(A::new(192, 0, 2, 1)),
            ),
        ]);

        message.insert_authorities(vec![Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            3600,
            RData::NS(NS(Name::from_str("ns1.example.com.").unwrap())),
        )]);

        message.insert_additionals(vec![Record::from_rdata(
            Name::from_str("ns1.example.com.").unwrap(),
            3600,
            RData::A(A::new(192, 0, 2, 10)),
        )]);

        let client = mock(vec![
            error(),
            Ok(DnsResponse::from_message(message).unwrap()),
        ]);
        let client = CachingClient::with_cache(cache, client, true); // preserve_intermediates=true

        let lookup = block_on(CachingClient::inner_lookup(
            Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A),
            DnsRequestOptions::default(),
            client,
            vec![],
            DepthTracker::default(),
        ))
        .expect("lookup failed");

        // Verify ANSWER: Both CNAME and A record
        let answers = lookup.answers().iter().collect::<Vec<_>>();
        assert_eq!(answers.len(), 2, "ANSWER should have 2 records (CNAME + A)");

        // Check for CNAME record
        let cname_records = answers
            .iter()
            .filter(|r| r.record_type() == RecordType::CNAME)
            .collect::<Vec<_>>();
        assert_eq!(cname_records.len(), 1, "Should have 1 CNAME record");

        // Check for A record
        let a_records = answers
            .iter()
            .filter(|r| r.record_type() == RecordType::A)
            .collect::<Vec<_>>();
        assert_eq!(a_records.len(), 1, "Should have 1 A record");

        // Verify AUTHORITY: NS records preserved (1 record)
        assert_eq!(
            lookup.authorities().len(),
            1,
            "AUTHORITY section should be preserved"
        );

        // Verify ADDITIONAL: Glue preserved (1 record)
        assert_eq!(
            lookup.additionals().len(),
            1,
            "ADDITIONAL section should be preserved"
        );
    }

    /// Purpose: Verify only final response sections are preserved in multi-hop CNAME chains
    ///
    /// This test verifies that in a multi-hop CNAME chain, only the AUTHORITY and ADDITIONAL
    /// sections from the FINAL response are preserved, not merged from intermediate responses.
    #[test]
    fn test_multi_hop_cname_preserves_final_sections() {
        subscribe();

        let cache = ResponseCache::new(1, TtlConfig::default());

        // Response 1 (first hop): CNAME only
        let mut message1 = Message::response(0, OpCode::Query);
        message1.add_query(Query::query(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::A,
        ));

        message1.insert_answers(vec![Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            300,
            RData::CNAME(CNAME(Name::from_str("v4.example.com.").unwrap())),
        )]);

        // AUTHORITY from first response (should NOT be in final result)
        message1.insert_authorities(vec![Record::from_rdata(
            Name::from_str("www-zone.example.com.").unwrap(),
            3600,
            RData::NS(NS(Name::from_str("ns-www.example.com.").unwrap())),
        )]);

        // ADDITIONAL from first response (should NOT be in final result)
        message1.insert_additionals(vec![Record::from_rdata(
            Name::from_str("ns-www.example.com.").unwrap(),
            3600,
            RData::A(A::new(192, 0, 2, 20)),
        )]);

        // Response 2 (second hop): Final A record
        let mut message2 = Message::response(0, OpCode::Query);
        message2.add_query(Query::query(
            Name::from_str("v4.example.com.").unwrap(),
            RecordType::A,
        ));

        message2.insert_answers(vec![Record::from_rdata(
            Name::from_str("v4.example.com.").unwrap(),
            300,
            RData::A(A::new(192, 0, 2, 1)),
        )]);

        // AUTHORITY from second response (SHOULD be in final result)
        message2.insert_authorities(vec![Record::from_rdata(
            Name::from_str("v4-zone.example.com.").unwrap(),
            3600,
            RData::NS(NS(Name::from_str("ns-v4.example.com.").unwrap())),
        )]);

        // ADDITIONAL from second response (SHOULD be in final result)
        message2.insert_additionals(vec![Record::from_rdata(
            Name::from_str("ns-v4.example.com.").unwrap(),
            3600,
            RData::A(A::new(192, 0, 2, 30)),
        )]);

        let mut client = CachingClient::with_cache(cache, mock(vec![]), false); // preserve_intermediates=false

        // First hop: Process CNAME response
        let result1 = CachingClient::handle_noerror(
            &mut client,
            DnsRequestOptions::default(),
            &Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A),
            DnsResponse::from_message(message1).unwrap(),
            vec![],
            DepthTracker::default(),
        );

        // Should return Records::CnameChain with empty preserved_records (preserve_intermediates=false)
        let preserved_records = match result1 {
            Ok(Records::CnameChain {
                preserved_records, ..
            }) => {
                // Verify preserved_records is empty when preserve_intermediates=false
                assert_eq!(
                    preserved_records.len(),
                    0,
                    "With preserve_intermediates=false, preserved_records should be empty"
                );
                preserved_records
            }
            Ok(Records::Exists { .. }) => {
                panic!("Expected Records::CnameChain from first hop, got Records::Exists")
            }
            Err(e) => panic!(
                "Expected Records::CnameChain from first hop, got error: {}",
                e
            ),
        };

        // Second hop: Process final A record response
        let result2 = CachingClient::handle_noerror(
            &mut client,
            DnsRequestOptions::default(),
            &Query::query(Name::from_str("v4.example.com.").unwrap(), RecordType::A),
            DnsResponse::from_message(message2).unwrap(),
            preserved_records,
            DepthTracker::default().nest(),
        );

        // Should return Records::Exists
        let lookup_message = match result2 {
            Ok(Records::Exists { message, .. }) => message,
            Ok(Records::CnameChain { .. }) => {
                panic!("Expected Records::Exists from second hop, got Records::CnameChain")
            }
            Err(e) => panic!("Expected Records::Exists from second hop, got error: {}", e),
        };

        // Create a Lookup from the final message
        let lookup = Lookup::new(lookup_message, Instant::now() + Duration::from_secs(300));

        // Verify ANSWER: Only final A record (CNAME from Response 1 filtered)
        let answers = lookup.answers().iter().collect::<Vec<_>>();
        assert_eq!(
            answers.len(),
            1,
            "ANSWER should have only the final A record"
        );
        assert_eq!(answers[0].record_type(), RecordType::A);
        match answers[0].data() {
            RData::A(a) => assert_eq!(a, &A::new(192, 0, 2, 1), "Should have IP from Response 2"),
            _ => panic!("wrong rdata type"),
        }
        match answers[0].data() {
            RData::A(a) => assert_eq!(a, &A::new(192, 0, 2, 1), "Should have IP from Response 2"),
            _ => panic!("wrong rdata type"),
        }

        // Verify AUTHORITY: From Response 2 only (not merged with Response 1)
        let authorities = lookup.authorities().iter().collect::<Vec<_>>();
        assert_eq!(
            authorities.len(),
            1,
            "AUTHORITY should have 1 record from final response only"
        );

        // Check it's the NS from Response 2, not Response 1
        match authorities[0].data() {
            RData::NS(ns_name) => assert_eq!(
                ns_name.0,
                Name::from_str("ns-v4.example.com.").unwrap(),
                "AUTHORITY should be from Response 2 (ns-v4), NOT Response 1 (ns-www)"
            ),
            _ => panic!("wrong rdata type"),
        }

        // Verify ADDITIONAL: From Response 2 only
        let additionals = lookup.additionals().iter().collect::<Vec<_>>();
        assert_eq!(
            additionals.len(),
            1,
            "ADDITIONAL should have 1 record from final response only"
        );

        // Check it's the IP from Response 2, not Response 1
        match additionals[0].data() {
            RData::A(a) => assert_eq!(
                a,
                &A::new(192, 0, 2, 30),
                "ADDITIONAL should have IP 192.0.2.30 from Response 2, NOT 192.0.2.20 from Response 1"
            ),
            _ => panic!("wrong rdata type"),
        }
    }

    /// test_multi_hop_cname_with_preserve_accumulates_cnames
    ///
    /// Purpose: Verify CNAMEs from multiple hops are accumulated when
    /// preserve_intermediates=true
    ///
    /// Same setup as test_multi_hop_cname_preserves_final_sections
    /// but with preserve_intermediates=true, so the CNAME from the
    /// first hop should be included in the final ANSWER section.
    ///
    /// Uses handle_noerror directly to test the two-hop CNAME chain
    /// with CNAME preservation.
    #[test]
    fn test_multi_hop_cname_with_preserve_accumulates_cnames() {
        subscribe();

        let cache = ResponseCache::new(1, TtlConfig::default());

        // Response 1 (first hop): CNAME only
        let mut message1 = Message::response(0, OpCode::Query);
        message1.add_query(Query::query(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::A,
        ));

        message1.insert_answers(vec![Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            300,
            RData::CNAME(CNAME(Name::from_str("v4.example.com.").unwrap())),
        )]);

        message1.insert_authorities(vec![Record::from_rdata(
            Name::from_str("www-zone.example.com.").unwrap(),
            3600,
            RData::NS(NS(Name::from_str("ns-www.example.com.").unwrap())),
        )]);

        message1.insert_additionals(vec![Record::from_rdata(
            Name::from_str("ns-www.example.com.").unwrap(),
            3600,
            RData::A(A::new(192, 0, 2, 20)),
        )]);

        // Response 2 (second hop): Final A record
        let mut message2 = Message::response(0, OpCode::Query);
        message2.add_query(Query::query(
            Name::from_str("v4.example.com.").unwrap(),
            RecordType::A,
        ));

        message2.insert_answers(vec![Record::from_rdata(
            Name::from_str("v4.example.com.").unwrap(),
            300,
            RData::A(A::new(192, 0, 2, 1)),
        )]);

        message2.insert_authorities(vec![Record::from_rdata(
            Name::from_str("v4-zone.example.com.").unwrap(),
            3600,
            RData::NS(NS(Name::from_str("ns-v4.example.com.").unwrap())),
        )]);

        message2.insert_additionals(vec![Record::from_rdata(
            Name::from_str("ns-v4.example.com.").unwrap(),
            3600,
            RData::A(A::new(192, 0, 2, 30)),
        )]);

        let client = mock(vec![]);
        let mut client = CachingClient::with_cache(cache, client, true); // preserve_intermediates=true

        // First hop: Process CNAME response
        let result1 = CachingClient::handle_noerror(
            &mut client,
            DnsRequestOptions::default(),
            &Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A),
            DnsResponse::from_message(message1.clone()).unwrap(),
            vec![],
            DepthTracker::default(),
        );

        // With preserve_intermediates=true, verify CNAME is preserved
        let preserved_records = match result1 {
            Ok(Records::CnameChain {
                preserved_records, ..
            }) => {
                // Verify preserved_records contains the CNAME when preserve_intermediates=true
                assert_eq!(
                    preserved_records.len(),
                    1,
                    "With preserve_intermediates=true, preserved_records should contain the CNAME"
                );
                assert_eq!(
                    preserved_records[0].record_type(),
                    RecordType::CNAME,
                    "Preserved record should be a CNAME"
                );
                preserved_records
            }
            _ => panic!("Expected CnameChain from first hop"),
        };

        // Second hop: Process final A record with preserved CNAME
        let result2 = CachingClient::handle_noerror(
            &mut client,
            DnsRequestOptions::default(),
            &Query::query(Name::from_str("v4.example.com.").unwrap(), RecordType::A),
            DnsResponse::from_message(message2).unwrap(),
            preserved_records,
            DepthTracker::default().nest(),
        );

        let lookup_message = match result2 {
            Ok(Records::Exists { message, .. }) => message,
            Ok(Records::CnameChain { .. }) => {
                panic!("Expected Records::Exists from second hop, got Records::CnameChain")
            }
            Err(e) => panic!("Expected Records::Exists from second hop, got error: {}", e),
        };

        // Create a Lookup from the final message
        let lookup = Lookup::new(lookup_message, Instant::now() + Duration::from_secs(300));

        // Verify ANSWER: CNAME from Response 1 + A from Response 2
        let answers = lookup.answers().iter().collect::<Vec<_>>();
        assert_eq!(
            answers.len(),
            2,
            "ANSWER should have CNAME + A (both preserved)"
        );

        // Check for CNAME record (from Response 1)
        let cname_records = answers
            .iter()
            .filter(|r| r.record_type() == RecordType::CNAME)
            .collect::<Vec<_>>();
        assert_eq!(
            cname_records.len(),
            1,
            "Should have 1 CNAME from Response 1"
        );

        match cname_records[0].data() {
            RData::CNAME(cname_target) => assert_eq!(
                cname_target.0,
                Name::from_str("v4.example.com.").unwrap(),
                "CNAME should point to v4.example.com"
            ),
            _ => panic!("wrong rdata type"),
        }

        // Check for A record (from Response 2)
        let a_records = answers
            .iter()
            .filter(|r| r.record_type() == RecordType::A)
            .collect::<Vec<_>>();
        assert_eq!(a_records.len(), 1, "Should have 1 A record");
        match a_records[0].data() {
            RData::A(a) => assert_eq!(
                a,
                &A::new(192, 0, 2, 1),
                "A record should have IP from Response 2"
            ),
            _ => panic!("wrong rdata type"),
        };

        // Verify AUTHORITY: From Response 2 only (1 record)
        assert_eq!(
            lookup.authorities().len(),
            1,
            "AUTHORITY should be from final response only"
        );

        // Verify ADDITIONAL: From Response 2 only (1 record)
        assert_eq!(
            lookup.additionals().len(),
            1,
            "ADDITIONAL should be from final response only"
        );
    }

    fn cname_ttl_test(first: u32, second: u32) {
        let lru = ResponseCache::new(1, TtlConfig::default());
        // expecting no queries to be performed
        let mut client = CachingClient::with_cache(lru, mock(vec![error()]), false);

        let mut message = Message::query();
        message.insert_answers(vec![Record::from_rdata(
            Name::from_str("ttl.example.com.").unwrap(),
            first,
            RData::CNAME(CNAME(Name::from_str("actual.example.com.").unwrap())),
        )]);
        message.insert_additionals(vec![Record::from_rdata(
            Name::from_str("actual.example.com.").unwrap(),
            second,
            RData::A(A::new(127, 0, 0, 1)),
        )]);

        let records = CachingClient::handle_noerror(
            &mut client,
            DnsRequestOptions::default(),
            &Query::query(Name::from_str("ttl.example.com.").unwrap(), RecordType::A),
            DnsResponse::from_message(message).unwrap(),
            vec![],
            DepthTracker::default(),
        );

        if let Ok(records) = records {
            if let Records::Exists { message, min_ttl } = records {
                assert_eq!(min_ttl, 1);
                assert!(!message.answers().is_empty());
            } else {
                panic!("records don't exist");
            }
        } else {
            panic!("error getting records");
        }
    }

    #[test]
    fn test_cname_ttl() {
        subscribe();
        cname_ttl_test(1, 2);
        cname_ttl_test(2, 1);
    }

    #[test]
    fn test_early_return_localhost() {
        subscribe();
        let cache = ResponseCache::new(0, TtlConfig::default());
        let client = mock(vec![empty()]);
        let client = CachingClient::with_cache(cache, client, false);

        {
            let query = Query::query(Name::from_ascii("localhost.").unwrap(), RecordType::A);
            let lookup = block_on(client.lookup(query.clone(), DnsRequestOptions::default()))
                .expect("should have returned localhost");
            assert_eq!(lookup.query(), &query);
            assert_eq!(
                lookup.answers(),
                &[Record::from_rdata(
                    query.name().clone(),
                    MAX_TTL,
                    LOCALHOST_V4.clone()
                )]
            );
        }

        {
            let query = Query::query(Name::from_ascii("localhost.").unwrap(), RecordType::AAAA);
            let lookup = block_on(client.lookup(query.clone(), DnsRequestOptions::default()))
                .expect("should have returned localhost");
            assert_eq!(lookup.query(), &query);
            assert_eq!(
                lookup.answers(),
                &[Record::from_rdata(
                    query.name().clone(),
                    MAX_TTL,
                    LOCALHOST_V6.clone()
                )]
            );
        }

        {
            let query = Query::query(Name::from(Ipv4Addr::LOCALHOST), RecordType::PTR);
            let lookup = block_on(client.lookup(query.clone(), DnsRequestOptions::default()))
                .expect("should have returned localhost");
            assert_eq!(lookup.query(), &query);
            assert_eq!(
                lookup.answers(),
                &[Record::from_rdata(
                    query.name().clone(),
                    MAX_TTL,
                    LOCALHOST.clone()
                )]
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
                lookup.answers(),
                &[Record::from_rdata(
                    query.name().clone(),
                    MAX_TTL,
                    LOCALHOST.clone()
                )]
            );
        }

        assert!(
            block_on(client.lookup(
                Query::query(Name::from_ascii("localhost.").unwrap(), RecordType::MX),
                DnsRequestOptions::default()
            ))
            .is_err()
        );

        assert!(
            block_on(client.lookup(
                Query::query(Name::from(Ipv4Addr::LOCALHOST), RecordType::MX),
                DnsRequestOptions::default()
            ))
            .is_err()
        );

        assert!(
            block_on(client.lookup(
                Query::query(
                    Name::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                    RecordType::MX
                ),
                DnsRequestOptions::default()
            ))
            .is_err()
        );
    }

    #[test]
    fn test_early_return_invalid() {
        subscribe();
        let cache = ResponseCache::new(0, TtlConfig::default());
        let client = mock(vec![empty()]);
        let client = CachingClient::with_cache(cache, client, false);

        assert!(
            block_on(client.lookup(
                Query::query(
                    Name::from_ascii("horrible.invalid.").unwrap(),
                    RecordType::A,
                ),
                DnsRequestOptions::default()
            ))
            .is_err()
        );
    }

    #[test]
    fn test_no_error_on_dot_local_no_mdns() {
        subscribe();

        let cache = ResponseCache::new(1, TtlConfig::default());

        let mut message = srv_message().unwrap().into_message();
        message.add_query(Query::query(
            Name::from_ascii("www.example.local.").unwrap(),
            RecordType::A,
        ));
        message.add_answer(Record::from_rdata(
            Name::from_str("www.example.local.").unwrap(),
            86400,
            RData::A(A::new(127, 0, 0, 1)),
        ));

        let client = mock(vec![
            error(),
            Ok(DnsResponse::from_message(message).unwrap()),
        ]);
        let client = CachingClient::with_cache(cache, client, false);

        assert!(
            block_on(client.lookup(
                Query::query(
                    Name::from_ascii("www.example.local.").unwrap(),
                    RecordType::A,
                ),
                DnsRequestOptions::default()
            ))
            .is_ok()
        );
    }
}
