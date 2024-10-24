// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// TODO, I've implemented this as a separate entity from the cache, but I wonder if the cache
//  should be the only "front-end" for lookups, where if that misses, then we go to the catalog
//  then, if requested, do a recursive lookup... i.e. the catalog would only point to files.
use std::{borrow::Borrow, collections::HashMap, io, sync::Arc};

use cfg_if::cfg_if;
use tracing::{debug, error, info, trace, warn};

#[cfg(feature = "dnssec")]
use crate::{
    authority::Nsec3QueryInfo,
    dnssec::NxProofKind,
    proto::rr::{
        dnssec::SupportedAlgorithms,
        rdata::opt::{EdnsCode, EdnsOption},
    },
};
use crate::{
    authority::{
        authority_object::DnssecSummary, AuthLookup, AuthorityObject, EmptyLookup,
        LookupControlFlow, LookupError, LookupObject, LookupOptions, LookupRecords,
        MessageResponse, MessageResponseBuilder, ZoneType,
    },
    proto::{
        op::{Edns, Header, LowerQuery, MessageType, OpCode, ResponseCode},
        rr::{LowerName, Record, RecordSet, RecordType},
    },
    server::{Request, RequestHandler, RequestInfo, ResponseHandler, ResponseInfo},
};

/// Set of authorities, zones, available to this server.
#[derive(Default)]
pub struct Catalog {
    authorities: HashMap<LowerName, Vec<Arc<dyn AuthorityObject>>>,
}

#[allow(unused_mut, unused_variables)]
async fn send_response<'a, R: ResponseHandler>(
    response_edns: Option<Edns>,
    mut response: MessageResponse<
        '_,
        'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
    >,
    mut response_handle: R,
) -> io::Result<ResponseInfo> {
    if let Some(mut resp_edns) = response_edns {
        #[cfg(feature = "dnssec")]
        {
            resp_edns.set_default_algorithms();
        }
        response.set_edns(resp_edns);
    }

    response_handle.send_response(response).await
}

#[async_trait::async_trait]
impl RequestHandler for Catalog {
    /// Determines what needs to happen given the type of request, i.e. Query or Update.
    ///
    /// # Arguments
    ///
    /// * `request` - the requested action to perform.
    /// * `response_handle` - sink for the response message to be sent
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        trace!("request: {:?}", request);

        let response_edns: Option<Edns>;

        // check if it's edns
        if let Some(req_edns) = request.edns() {
            let mut response = MessageResponseBuilder::new(Some(request.raw_query()));
            let mut response_header = Header::response_from_request(request.header());

            let mut resp_edns: Edns = Edns::new();

            // check our version against the request
            // TODO: what version are we?
            let our_version = 0;
            resp_edns.set_dnssec_ok(true);
            resp_edns.set_max_payload(req_edns.max_payload().max(512));
            resp_edns.set_version(our_version);

            if req_edns.version() > our_version {
                warn!(
                    "request edns version greater than {}: {}",
                    our_version,
                    req_edns.version()
                );
                response_header.set_response_code(ResponseCode::BADVERS);
                resp_edns.set_rcode_high(ResponseCode::BADVERS.high());
                response.edns(resp_edns);

                // TODO: should ResponseHandle consume self?
                let result = response_handle
                    .send_response(response.build_no_records(response_header))
                    .await;

                // couldn't handle the request
                return match result {
                    Err(e) => {
                        error!("request error: {}", e);
                        ResponseInfo::serve_failed()
                    }
                    Ok(info) => info,
                };
            }

            response_edns = Some(resp_edns);
        } else {
            response_edns = None;
        }

        let result = match request.message_type() {
            // TODO think about threading query lookups for multiple lookups, this could be a huge improvement
            //  especially for recursive lookups
            MessageType::Query => match request.op_code() {
                OpCode::Query => {
                    debug!("query received: {}", request.id());
                    let info = self.lookup(request, response_edns, response_handle).await;

                    Ok(info)
                }
                OpCode::Update => {
                    debug!("update received: {}", request.id());
                    self.update(request, response_edns, response_handle).await
                }
                c => {
                    warn!("unimplemented op_code: {:?}", c);
                    let response = MessageResponseBuilder::new(Some(request.raw_query()));

                    response_handle
                        .send_response(response.error_msg(request.header(), ResponseCode::NotImp))
                        .await
                }
            },
            MessageType::Response => {
                warn!("got a response as a request from id: {}", request.id());
                let response = MessageResponseBuilder::new(Some(request.raw_query()));

                response_handle
                    .send_response(response.error_msg(request.header(), ResponseCode::FormErr))
                    .await
            }
        };

        match result {
            Err(e) => {
                error!("request failed: {}", e);
                ResponseInfo::serve_failed()
            }
            Ok(info) => info,
        }
    }
}

impl Catalog {
    /// Constructs a new Catalog
    pub fn new() -> Self {
        Self {
            authorities: HashMap::new(),
        }
    }

    /// Insert or update a zone authority
    ///
    /// # Arguments
    ///
    /// * `name` - zone name, e.g. example.com.
    /// * `authority` - the zone data
    pub fn upsert(&mut self, name: LowerName, authorities: Vec<Arc<dyn AuthorityObject>>) {
        self.authorities.insert(name, authorities);
    }

    /// Remove a zone from the catalog
    pub fn remove(&mut self, name: &LowerName) -> Option<Vec<Arc<dyn AuthorityObject>>> {
        self.authorities.remove(name)
    }

    /// Update the zone given the Update request.
    ///
    /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    /// 3.1 - Process Zone Section
    ///
    ///   3.1.1. The Zone Section is checked to see that there is exactly one
    ///   RR therein and that the RR's ZTYPE is SOA, else signal FORMERR to the
    ///   requestor.  Next, the ZNAME and ZCLASS are checked to see if the zone
    ///   so named is one of this server's authority zones, else signal NOTAUTH
    ///   to the requestor.  If the server is a zone Secondary, the request will be
    ///   forwarded toward the Primary Zone Server.
    ///
    ///   3.1.2 - Pseudocode For Zone Section Processing
    ///
    ///      if (zcount != 1 || ztype != SOA)
    ///           return (FORMERR)
    ///      if (zone_type(zname, zclass) == SECONDARY)
    ///           return forward()
    ///      if (zone_type(zname, zclass) == PRIMARY)
    ///           return update()
    ///      return (NOTAUTH)
    ///
    ///   Sections 3.2 through 3.8 describe the primary's behaviour,
    ///   whereas Section 6 describes a forwarder's behaviour.
    ///
    /// 3.8 - Response
    ///
    ///   At the end of UPDATE processing, a response code will be known.  A
    ///   response message is generated by copying the ID and Opcode fields
    ///   from the request, and either copying the ZOCOUNT, PRCOUNT, UPCOUNT,
    ///   and ADCOUNT fields and associated sections, or placing zeros (0) in
    ///   the these "count" fields and not including any part of the original
    ///   update.  The QR bit is set to one (1), and the response is sent back
    ///   to the requestor.  If the requestor used UDP, then the response will
    ///   be sent to the requestor's source UDP port.  If the requestor used
    ///   TCP, then the response will be sent back on the requestor's open TCP
    ///   connection.
    /// ```
    ///
    /// The "request" should be an update formatted message.
    ///  The response will be in the alternate, all 0's format described in RFC 2136 section 3.8
    ///  as this is more efficient.
    ///
    /// # Arguments
    ///
    /// * `request` - an update message
    /// * `response_handle` - sink for the response message to be sent
    pub async fn update<R: ResponseHandler>(
        &self,
        update: &Request,
        response_edns: Option<Edns>,
        response_handle: R,
    ) -> io::Result<ResponseInfo> {
        let request_info = update.request_info();

        let verify_request = move || -> Result<RequestInfo<'_>, ResponseCode> {
            // 2.3 - Zone Section
            //
            //  All records to be updated must be in the same zone, and
            //  therefore the Zone Section is allowed to contain exactly one record.
            //  The ZNAME is the zone name, the ZTYPE must be SOA, and the ZCLASS is
            //  the zone's class.

            let ztype = request_info.query.query_type();

            if ztype != RecordType::SOA {
                warn!(
                    "invalid update request zone type must be SOA, ztype: {}",
                    ztype
                );
                return Err(ResponseCode::FormErr);
            }

            Ok(request_info)
        };

        let Ok(verify_request) = verify_request() else {
            return Ok(ResponseInfo::serve_failed());
        };

        // verify the zone type and number of zones in request, then find the zone to update
        if let Some(authorities) = self.find(verify_request.query.name()) {
            #[allow(clippy::never_loop)]
            for authority in authorities {
                #[allow(deprecated)]
                let response_code = match authority.zone_type() {
                    ZoneType::Secondary | ZoneType::Slave => {
                        error!("secondary forwarding for update not yet implemented");
                        ResponseCode::NotImp
                    }
                    ZoneType::Primary | ZoneType::Master => {
                        let update_result = authority.update(update).await;
                        match update_result {
                            // successful update
                            Ok(..) => ResponseCode::NoError,
                            Err(response_code) => response_code,
                        }
                    }
                    _ => ResponseCode::NotAuth,
                };

                let response = MessageResponseBuilder::new(Some(update.raw_query()));
                let mut response_header = Header::default();
                response_header.set_id(update.id());
                response_header.set_op_code(OpCode::Update);
                response_header.set_message_type(MessageType::Response);
                response_header.set_response_code(response_code);

                return send_response(
                    response_edns,
                    response.build_no_records(response_header),
                    response_handle,
                )
                .await;
            }
        };

        Ok(ResponseInfo::serve_failed())
    }

    /// Checks whether the `Catalog` contains DNS records for `name`
    ///
    /// Use this when you know the exact `LowerName` that was used when
    /// adding an authority and you don't care about the authority it
    /// contains. For public domain names, `LowerName` is usually the
    /// top level domain name like `example.com.`.
    ///
    /// If you do not know the exact domain name to use or you actually
    /// want to use the authority it contains, use `find` instead.
    pub fn contains(&self, name: &LowerName) -> bool {
        self.authorities.contains_key(name)
    }

    /// Given the requested query, lookup and return any matching results.
    ///
    /// # Arguments
    ///
    /// * `request` - the query message.
    /// * `response_handle` - sink for the response message to be sent
    pub async fn lookup<R: ResponseHandler>(
        &self,
        request: &Request,
        response_edns: Option<Edns>,
        response_handle: R,
    ) -> ResponseInfo {
        let request_info = request.request_info();
        let authorities = self.find(request_info.query.name());

        let Some(authorities) = authorities else {
            // There are no authorities registered that can handle the request
            let response = MessageResponseBuilder::new(Some(request.raw_query()));

            let result = send_response(
                response_edns,
                response.error_msg(request.header(), ResponseCode::Refused),
                response_handle,
            )
            .await;

            match result {
                Err(e) => {
                    error!("failed to send response: {e}");
                    return ResponseInfo::serve_failed();
                }
                Ok(r) => return r,
            }
        };

        let result = lookup(
            request_info.clone(),
            authorities,
            request,
            response_edns
                .as_ref()
                .map(|arc| Borrow::<Edns>::borrow(arc).clone()),
            response_handle.clone(),
        )
        .await;

        match result {
            Ok(lookup) => lookup,
            Err(_e) => ResponseInfo::serve_failed(),
        }
    }

    /// Recursively searches the catalog for a matching authority
    pub fn find(&self, name: &LowerName) -> Option<&Vec<Arc<(dyn AuthorityObject + 'static)>>> {
        debug!("searching authorities for: {name}");
        self.authorities.get(name).or_else(|| {
            if !name.is_root() {
                let name = name.base_name();
                self.find(&name)
            } else {
                None
            }
        })
    }
}

async fn lookup<'a, R: ResponseHandler + Unpin>(
    request_info: RequestInfo<'_>,
    authorities: &[Arc<dyn AuthorityObject>],
    request: &Request,
    response_edns: Option<Edns>,
    response_handle: R,
) -> Result<ResponseInfo, LookupError> {
    let edns = request.edns();
    let lookup_options = lookup_options_for_edns(edns);
    let request_id = request.id();

    // log algorithms being requested
    if lookup_options.dnssec_ok() {
        info!("request: {request_id} lookup_options: {lookup_options:?}");
    }

    let query = request_info.query;

    for (authority_index, authority) in authorities.iter().enumerate() {
        debug!(
            "performing {query} on authority {origin} with request id {request_id}",
            origin = authority.origin(),
        );

        // Wait so we can determine if we need to fire a request to the next authority in a chained
        // configuration if the current authority declines to answer.
        let mut result = authority.search(request_info.clone(), lookup_options).await;

        if let LookupControlFlow::Skip = result {
            trace!("catalog::lookup::authority did not handle request");
            continue;
        } else if result.is_continue() {
            trace!("catalog::lookup::authority did handle request with continue");

            // For LookupControlFlow::Continue results, we'll call consult on every
            // authority, except the authority that returned the Continue result.
            for (continue_index, consult_authority) in authorities.iter().enumerate() {
                if continue_index == authority_index {
                    trace!("skipping current authority consult (index {continue_index})");
                    continue;
                } else {
                    trace!("calling authority consult (index {continue_index})");
                }

                result = consult_authority
                    .consult(
                        request_info.query.name(),
                        request_info.query.query_type(),
                        lookup_options_for_edns(response_edns.as_ref()),
                        result,
                    )
                    .await;
            }
        } else {
            trace!("catalog::lookup::authority did handle request with break");
        }

        // We no longer need the context from LookupControlFlow, so decompose into a standard Result
        // to clean up the rest of the match conditions
        let Some(result) = result.map_result() else {
            error!("impossible skip detected after final lookup result");
            return Err(LookupError::ResponseCode(ResponseCode::ServFail));
        };

        let (response_header, sections) = build_response(
            result,
            &**authority,
            request_id,
            request.header(),
            query,
            edns,
        )
        .await;

        let message_response = MessageResponseBuilder::new(Some(request.raw_query())).build(
            response_header,
            sections.answers.iter(),
            sections.ns.iter(),
            sections.soa.iter(),
            sections.additionals.iter(),
        );

        let result = send_response(response_edns, message_response, response_handle).await;

        match result {
            Err(e) => {
                error!("error sending response: {e}");
                return Err(LookupError::Io(e));
            }
            Ok(l) => return Ok(l),
        }
    }

    error!("end of chained authority loop reached with all authorities not answering");
    Err(LookupError::ResponseCode(ResponseCode::ServFail))
}

#[allow(unused_variables)]
fn lookup_options_for_edns(edns: Option<&Edns>) -> LookupOptions {
    let edns = match edns {
        Some(edns) => edns,
        None => return LookupOptions::default(),
    };

    cfg_if! {
        if #[cfg(feature = "dnssec")] {
            let supported_algorithms = if let Some(&EdnsOption::DAU(algs)) = edns.option(EdnsCode::DAU)
            {
               algs
            } else {
               debug!("no DAU in request, used default SupportAlgorithms");
               SupportedAlgorithms::default()
            };

            LookupOptions::for_dnssec(edns.dnssec_ok(), supported_algorithms)
        } else {
            LookupOptions::default()
        }
    }
}

/// Build Header and LookupSections (answers) given a query response from an authority
async fn build_response(
    result: Result<Box<dyn LookupObject>, LookupError>,
    authority: &dyn AuthorityObject,
    request_id: u16,
    request_header: &Header,
    query: &LowerQuery,
    edns: Option<&Edns>,
) -> (Header, LookupSections) {
    let lookup_options = lookup_options_for_edns(edns);

    let mut response_header = Header::response_from_request(request_header);
    response_header.set_authoritative(authority.zone_type().is_authoritative());

    #[allow(deprecated)]
    let sections = match authority.zone_type() {
        ZoneType::Primary | ZoneType::Secondary | ZoneType::Master | ZoneType::Slave => {
            build_authoritative_response(
                result,
                authority,
                &mut response_header,
                lookup_options,
                request_id,
                query,
            )
            .await
        }
        ZoneType::Forward | ZoneType::Hint => {
            build_forwarded_response(
                result,
                request_header,
                &mut response_header,
                authority.can_validate_dnssec(),
                query,
                lookup_options,
            )
            .await
        }
    };

    (response_header, sections)
}

/// Prepare a response for an authoritative zone
async fn build_authoritative_response(
    response: Result<Box<dyn LookupObject>, LookupError>,
    authority: &dyn AuthorityObject,
    response_header: &mut Header,
    lookup_options: LookupOptions,
    _request_id: u16,
    query: &LowerQuery,
) -> LookupSections {
    // In this state we await the records, on success we transition to getting
    // NS records, which indicate an authoritative response.
    //
    // On Errors, the transition depends on the type of error.

    let answers = match response {
        Ok(records) => {
            response_header.set_response_code(ResponseCode::NoError);
            response_header.set_authoritative(true);
            Some(records)
        }
        // This request was refused
        // TODO: there are probably other error cases that should just drop through (FormErr, ServFail)
        Err(LookupError::ResponseCode(ResponseCode::Refused)) => {
            response_header.set_response_code(ResponseCode::Refused);
            return LookupSections {
                answers: Box::<AuthLookup>::default(),
                ns: Box::<AuthLookup>::default(),
                soa: Box::<AuthLookup>::default(),
                additionals: Box::<AuthLookup>::default(),
            };
        }
        Err(e) => {
            if e.is_nx_domain() {
                response_header.set_response_code(ResponseCode::NXDomain);
            } else if e.is_name_exists() {
                response_header.set_response_code(ResponseCode::NoError);
            };
            None
        }
    };

    let (ns, soa) = if answers.is_some() {
        // SOA queries should return the NS records as well.
        if query.query_type().is_soa() {
            // This was a successful authoritative lookup for SOA:
            //   get the NS records as well.

            match authority.ns(lookup_options).await.map_result() {
                Some(Ok(ns)) => (Some(ns), None),
                Some(Err(e)) => {
                    warn!("ns_lookup errored: {e}");
                    (None, None)
                }
                None => {
                    warn!("ns_lookup unexpected skip");
                    (None, None)
                }
            }
        } else {
            #[cfg(feature = "dnssec")]
            {
                if let Some(NxProofKind::Nsec3 {
                    algorithm,
                    salt,
                    iterations,
                }) = authority.nx_proof_kind()
                {
                    // This unwrap will not panic as we know that `answers` is `Some`.
                    let has_wildcard_match =
                        answers.as_ref().unwrap().iter().any(|rr| {
                            rr.record_type() == RecordType::RRSIG && rr.name().is_wildcard()
                        });

                    match authority
                        .get_nsec3_records(
                            Nsec3QueryInfo {
                                qname: query.name(),
                                qtype: query.query_type(),
                                has_wildcard_match,
                                algorithm: *algorithm,
                                salt,
                                iterations: *iterations,
                            },
                            lookup_options,
                        )
                        .await
                        .map_result()
                    {
                        // run the soa lookup
                        Some(Ok(nsecs)) => (Some(nsecs), None),
                        Some(Err(e)) => {
                            warn!("failed to lookup nsecs for request {_request_id}: {e}");
                            (None, None)
                        }
                        None => {
                            warn!("unexpected lookup skip for request {_request_id}");
                            (None, None)
                        }
                    }
                } else {
                    (None, None)
                }
            }
            #[cfg(not(feature = "dnssec"))]
            (None, None)
        }
    } else {
        let nsecs = if lookup_options.dnssec_ok() {
            #[cfg(feature = "dnssec")]
            {
                // in the dnssec case, nsec records should exist, we return NoError + NoData + NSec...
                debug!("request: {_request_id} non-existent adding nsecs");
                match authority.nx_proof_kind() {
                    Some(nx_proof_kind) => {
                        // run the nsec lookup future, and then transition to get soa
                        let future = match nx_proof_kind {
                            NxProofKind::Nsec => {
                                authority.get_nsec_records(query.name(), lookup_options)
                            }
                            NxProofKind::Nsec3 {
                                algorithm,
                                salt,
                                iterations,
                            } => authority.get_nsec3_records(
                                Nsec3QueryInfo {
                                    qname: query.name(),
                                    qtype: query.query_type(),
                                    has_wildcard_match: false,
                                    algorithm: *algorithm,
                                    salt,
                                    iterations: *iterations,
                                },
                                lookup_options,
                            ),
                        };

                        match future.await.map_result() {
                            // run the soa lookup
                            Some(Ok(nsecs)) => Some(nsecs),
                            Some(Err(e)) => {
                                warn!("failed to lookup nsecs for request {_request_id}: {e}");
                                None
                            }
                            None => {
                                warn!("unexpected lookup skip for request {_request_id}");
                                None
                            }
                        }
                    }
                    None => None,
                }
            }
            #[cfg(not(feature = "dnssec"))]
            None
        } else {
            None
        };

        match authority.soa_secure(lookup_options).await.map_result() {
            Some(Ok(soa)) => (nsecs, Some(soa)),
            Some(Err(e)) => {
                warn!("failed to lookup soa: {e}");
                (nsecs, None)
            }
            None => {
                warn!("unexpected lookup skip");
                (None, None)
            }
        }
    };

    // everything is done, return results.
    let (answers, additionals) = match answers {
        Some(mut answers) => match answers.take_additionals() {
            Some(additionals) => (answers, additionals),
            None => (
                answers,
                Box::<AuthLookup>::default() as Box<dyn LookupObject>,
            ),
        },
        None => (
            Box::<AuthLookup>::default() as Box<dyn LookupObject>,
            Box::<AuthLookup>::default() as Box<dyn LookupObject>,
        ),
    };

    LookupSections {
        answers,
        ns: ns.unwrap_or_else(|| Box::<AuthLookup>::default()),
        soa: soa.unwrap_or_else(|| Box::<AuthLookup>::default()),
        additionals,
    }
}

/// Prepare a response for a forwarded zone.
async fn build_forwarded_response(
    response: Result<Box<dyn LookupObject>, LookupError>,
    request_header: &Header,
    response_header: &mut Header,
    can_validate_dnssec: bool,
    query: &LowerQuery,
    lookup_options: LookupOptions,
) -> LookupSections {
    response_header.set_recursion_available(true);
    response_header.set_authoritative(false);

    enum Answer {
        Normal(Box<dyn LookupObject>),
        NoRecords(Box<AuthLookup>),
    }

    let (mut answers, authorities) = match response {
        Ok(_) | Err(_) if !request_header.recursion_desired() => {
            info!(
                "request disabled recursion, returning no records: {}",
                request_header.id()
            );

            (
                Answer::Normal(Box::new(EmptyLookup)),
                Box::<AuthLookup>::default(),
            )
        }
        Ok(l) => (Answer::Normal(l), Box::<AuthLookup>::default()),
        Err(e) if e.is_no_records_found() || e.is_nx_domain() => {
            debug!("error resolving: {e:?}");

            if e.is_nx_domain() {
                response_header.set_response_code(ResponseCode::NXDomain);
            }

            // Collect all of the authority records, except the SOA
            let authorities = if let Some(authorities) = e.authorities() {
                let authorities = authorities
                    .iter()
                    .filter_map(|x| {
                        // if we have another record (probably a dnssec record) that
                        // matches the query name, but wasn't included in the answers
                        // section, change the NXDomain response to NoError
                        if *x.name() == **query.name() {
                            debug!(
                                "changing response code from NXDomain to NoError for {} due to other record {x:?}",
                                query.name(),
                            );
                            response_header.set_response_code(ResponseCode::NoError);
                        }

                        match x.record_type() {
                            RecordType::SOA => None,
                            _ => Some(Arc::new(RecordSet::from(x.clone()))),
                        }
                    })
                    .collect();

                Box::new(AuthLookup::answers(
                    LookupRecords::many(LookupOptions::default(), authorities),
                    None,
                ))
            } else {
                Box::<AuthLookup>::default()
            };

            if let Some(soa) = e.into_soa() {
                let soa = soa.into_record_of_rdata();
                let record_set = Arc::new(RecordSet::from(soa));
                let records = LookupRecords::new(LookupOptions::default(), record_set);

                (
                    Answer::NoRecords(Box::new(AuthLookup::SOA(records))),
                    authorities,
                )
            } else {
                (Answer::Normal(Box::new(EmptyLookup)), authorities)
            }
        }
        Err(e) => {
            response_header.set_response_code(ResponseCode::ServFail);
            debug!("error resolving {e:?}");
            (
                Answer::Normal(Box::new(EmptyLookup)),
                Box::<AuthLookup>::default(),
            )
        }
    };

    if can_validate_dnssec {
        // section 3.2.2 ("the CD bit") of RFC4035 is a bit underspecified because it does not use
        // RFC2119 vocabulary ("MUST", "MAY", etc.) in some sentences that describe the resolver's
        // behavior.
        //
        // A. it is clear that if CD=1 in the query then data that fails DNSSEC validation SHOULD
        //   be returned
        //
        // B. it also clear that if CD=0 and DNSSEC validation fails then the status MUST be
        //   SERVFAIL
        //
        // C. it's less clear if DNSSEC validation can be skippped altogether when CD=1
        //
        // the logic here follows `unbound`'s interpretation of that section
        //
        // 0. the requirements A and B are implemented
        // 1. DNSSEC validation happens regardless of the state of the CD bit
        // 2. the AD bit gets set if DNSSEC validation succeeded regardless of the state of the
        //   CD bit
        //
        // this last point can result in responses that have both AD=1 and CD=1. RFC4035 is unclear
        // whether that's a valid state but that's what `unbound` does
        //
        // we may want to interpret (B) as allowed ("MAY be skipped") as a form of optimization in
        // the future to reduce the number of network transactions that a CD=1 query needs.
        match &mut answers {
            Answer::Normal(answers) => match answers.dnssec_summary() {
                DnssecSummary::Secure => {
                    trace!("setting ad header");
                    response_header.set_authentic_data(true);
                }
                DnssecSummary::Bogus if !request_header.checking_disabled() => {
                    response_header.set_response_code(ResponseCode::ServFail);
                    // do not return Bogus records when CD=0
                    *answers = Box::new(EmptyLookup);
                }
                _ => {}
            },
            Answer::NoRecords(soa) => match authorities.dnssec_summary() {
                DnssecSummary::Secure => {
                    trace!("setting ad header");
                    response_header.set_authentic_data(true);
                }
                DnssecSummary::Bogus if !request_header.checking_disabled() => {
                    response_header.set_response_code(ResponseCode::ServFail);
                    // do not return Bogus records when CD=0
                    *soa = Box::<AuthLookup>::default();
                    trace!("clearing SOA record from response");
                }
                _ => {}
            },
        }
    }

    // Strip out DNSSEC records unless the DO bit is set.
    let authorities = if !lookup_options.dnssec_ok() {
        let auth = authorities
            .into_iter()
            .filter_map(|rrset| {
                let record_type = rrset.record_type();
                if record_type == query.query_type() || !record_type.is_dnssec() {
                    Some(Arc::new(RecordSet::from(rrset.clone())))
                } else {
                    None
                }
            })
            .collect();

        Box::new(AuthLookup::answers(
            LookupRecords::many(LookupOptions::default(), auth),
            None,
        ))
    } else {
        authorities
    };

    match answers {
        Answer::Normal(answers) => LookupSections {
            answers,
            ns: authorities,
            soa: Box::<AuthLookup>::default(),
            additionals: Box::<AuthLookup>::default(),
        },
        Answer::NoRecords(soa) => LookupSections {
            answers: Box::new(EmptyLookup),
            ns: authorities,
            soa,
            additionals: Box::<AuthLookup>::default(),
        },
    }
}

struct LookupSections {
    answers: Box<dyn LookupObject>,
    ns: Box<dyn LookupObject>,
    soa: Box<dyn LookupObject>,
    additionals: Box<dyn LookupObject>,
}
