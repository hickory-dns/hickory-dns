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

use tracing::{debug, error, info, trace, warn};

#[cfg(feature = "metrics")]
use crate::authority::metrics::CatalogMetrics;
#[cfg(feature = "__dnssec")]
use crate::{authority::Nsec3QueryInfo, dnssec::NxProofKind, proto::dnssec::DnssecSummary};
use crate::{
    authority::{
        AuthLookup, Authority, LookupControlFlow, LookupError, LookupOptions, LookupRecords,
        MessageResponseBuilder, ZoneType,
    },
    proto::{
        op::{Edns, Header, LowerQuery, MessageType, OpCode, ResponseCode},
        rr::{
            LowerName, RecordSet, RecordType,
            rdata::opt::{EdnsCode, EdnsOption, NSIDPayload},
        },
        serialize::binary::{BinEncoder, EncodeMode},
    },
    server::{Request, RequestHandler, RequestInfo, ResponseHandler, ResponseInfo},
};
#[cfg(all(feature = "__dnssec", feature = "recursor"))]
use crate::{
    proto::{ProtoError, ProtoErrorKind},
    recursor,
    recursor::ErrorKind,
};

/// Set of authorities, zones, available to this server.
#[derive(Default)]
pub struct Catalog {
    nsid_payload: Option<NSIDPayload>,
    authorities: HashMap<LowerName, Vec<Arc<dyn Authority>>>,
    #[cfg(feature = "metrics")]
    metrics: CatalogMetrics,
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
                let mut response_header = Header::response_from_request(request.header());
                response_header.set_response_code(ResponseCode::BADVERS);
                resp_edns.set_rcode_high(ResponseCode::BADVERS.high());
                let response = MessageResponseBuilder::new(request.raw_queries(), Some(resp_edns))
                    .build_no_records(response_header);

                // TODO: should ResponseHandle consume self?
                let result = response_handle.send_response(response).await;

                // couldn't handle the request
                return match result {
                    Err(error) => {
                        error!(%error, "request error");
                        ResponseInfo::serve_failed(request)
                    }
                    Ok(info) => info,
                };
            }

            // RFC 5001 "DNS Name Server Identifier (NSID) Option" handling.
            match (req_edns.option(EdnsCode::NSID), &self.nsid_payload) {
                // NSID was requested, and we have a payload to reply with. Add it to the
                // response EDNS.
                (Some(request_option), Some(payload)) => {
                    // "The name server MUST ignore any NSID payload data that might be
                    //  present in the query message."
                    if !request_option.is_empty() {
                        warn!("ignoring non-empty EDNS NSID request payload")
                    }
                    resp_edns
                        .options_mut()
                        .insert(EdnsOption::NSID(payload.clone()));
                }
                // NSID was requested, but we don't have a payload configured.
                (Some(_), None) => {
                    trace!("ignoring EDNS NSID request - no response payload configured")
                }
                // "A name server MUST NOT send an NSID option back to a resolver which
                // did not request it."
                (None, _) => {}
            };

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
                    let response =
                        MessageResponseBuilder::new(request.raw_queries(), response_edns)
                            .error_msg(request.header(), ResponseCode::NotImp);

                    response_handle.send_response(response).await
                }
            },
            MessageType::Response => {
                warn!("got a response as a request from id: {}", request.id());
                let response = MessageResponseBuilder::new(request.raw_queries(), response_edns)
                    .error_msg(request.header(), ResponseCode::FormErr);

                response_handle.send_response(response).await
            }
        };

        match result {
            Err(error) => {
                error!(%error, "request failed");
                ResponseInfo::serve_failed(request)
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
            nsid_payload: None,
            #[cfg(feature = "metrics")]
            metrics: CatalogMetrics::default(),
        }
    }

    /// Insert or update the provided zone authorities
    ///
    /// # Arguments
    ///
    /// * `name` - zone name, e.g. example.com.
    /// * `authorities` - a vec of authority objects
    pub fn upsert(&mut self, name: LowerName, authorities: Vec<Arc<dyn Authority>>) {
        #[cfg(feature = "metrics")]
        for authority in authorities.iter() {
            self.metrics.add_authority(authority.as_ref())
        }

        self.authorities.insert(name, authorities);
    }

    /// Remove a zone from the catalog
    pub fn remove(&mut self, name: &LowerName) -> Option<Vec<Arc<dyn Authority>>> {
        // NOTE: metrics are not removed to avoid dropping counters that are potentially still
        // being used by other authorities having the same labels
        self.authorities.remove(name)
    }

    /// Set a specified name server identifier (NSID) in responses
    ///
    /// The provided `NSIDPayload` will be included in responses to requests that
    /// specify the NSID option in EDNS. Set to `None` to disable NSID.
    ///
    /// By default, no NSID is sent.
    pub fn set_nsid(&mut self, payload: Option<NSIDPayload>) {
        self.nsid_payload = payload
    }

    /// Return the name server identifier (NSID) that is used for responses (if enabled)
    ///
    /// See `set_nsid()` for more information.
    pub fn nsid(&self) -> Option<&NSIDPayload> {
        self.nsid_payload.as_ref()
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
    /// * `response_edns` an optional `Edns` value for the response message
    /// * `response_handle` - sink for the response message to be sent
    pub async fn update<R: ResponseHandler>(
        &self,
        update: &Request,
        response_edns: Option<Edns>,
        mut response_handle: R,
    ) -> io::Result<ResponseInfo> {
        // 2.3 - Zone Section
        //
        //  All records to be updated must be in the same zone, and
        //  therefore the Zone Section is allowed to contain exactly one record.
        //  The ZNAME is the zone name, the ZTYPE must be SOA, and the ZCLASS is
        //  the zone's class.

        let request_info = update.request_info()?;
        let ztype = request_info.query.query_type();

        if ztype != RecordType::SOA {
            warn!("invalid update request zone type must be SOA, ztype: {ztype}");
            return Ok(ResponseInfo::serve_failed(update));
        }

        // verify the zone type and number of zones in request, then find the zone to update
        if let Some(authorities) = self.find(request_info.query.name()) {
            #[allow(clippy::never_loop)]
            for authority in authorities {
                let (response_code, signer) = match authority.zone_type() {
                    ZoneType::Secondary => {
                        error!("secondary forwarding for update not yet implemented");
                        (ResponseCode::NotImp, None)
                    }
                    ZoneType::Primary => {
                        let (update_result, signer) = authority.update(update).await;
                        match update_result {
                            // successful update
                            Ok(_) => (ResponseCode::NoError, signer),
                            Err(response_code) => (response_code, signer),
                        }
                    }
                    _ => (ResponseCode::NotAuth, None),
                };

                let response =
                    MessageResponseBuilder::new(update.raw_queries(), response_edns.clone());
                let mut response_header =
                    Header::new(update.id(), MessageType::Response, OpCode::Update);
                response_header.set_response_code(response_code);
                let mut response = response.build_no_records(response_header);

                if let Some(signer) = signer {
                    let mut tbs_response_buf = Vec::with_capacity(512);
                    let mut encoder =
                        BinEncoder::with_mode(&mut tbs_response_buf, EncodeMode::Normal);
                    let mut response_header =
                        Header::new(update.id(), MessageType::Response, OpCode::Update);
                    response_header.set_response_code(response_code);
                    let tbs_response =
                        MessageResponseBuilder::new(update.raw_queries(), response_edns)
                            .build_no_records(response_header);
                    tbs_response.destructive_emit(&mut encoder)?;
                    response.set_signature(signer.sign(&tbs_response_buf)?);
                }

                return response_handle.send_response(response).await;
            }
        };

        Ok(ResponseInfo::serve_failed(update))
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
    /// * `response_edns` an optional `Edns` value for the response message
    /// * `response_handle` - sink for the response message to be sent
    pub async fn lookup<R: ResponseHandler>(
        &self,
        request: &Request,
        response_edns: Option<Edns>,
        mut response_handle: R,
    ) -> ResponseInfo {
        let Ok(request_info) = request.request_info() else {
            // Wrong number of queries
            let response = MessageResponseBuilder::new(request.raw_queries(), response_edns)
                .error_msg(request.header(), ResponseCode::FormErr);
            match response_handle.send_response(response).await {
                Err(error) => {
                    error!(%error, "failed to send response");
                    return ResponseInfo::serve_failed(request);
                }
                Ok(r) => return r,
            }
        };
        let authorities = self.find(request_info.query.name());

        let Some(authorities) = authorities else {
            // There are no authorities registered that can handle the request
            let response = MessageResponseBuilder::new(request.raw_queries(), response_edns)
                .error_msg(request.header(), ResponseCode::Refused);
            match response_handle.send_response(response).await {
                Err(error) => {
                    error!(%error, "failed to send response");
                    return ResponseInfo::serve_failed(request);
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
            #[cfg(feature = "metrics")]
            &self.metrics,
        )
        .await;

        match result {
            Ok(lookup) => lookup,
            Err(_e) => ResponseInfo::serve_failed(request),
        }
    }

    /// Recursively searches the catalog for a matching authority
    pub fn find(&self, name: &LowerName) -> Option<&Vec<Arc<(dyn Authority + 'static)>>> {
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

async fn lookup<R: ResponseHandler + Unpin>(
    request_info: RequestInfo<'_>,
    authorities: &[Arc<dyn Authority>],
    request: &Request,
    response_edns: Option<Edns>,
    mut response_handle: R,
    #[cfg(feature = "metrics")] metrics: &CatalogMetrics,
) -> Result<ResponseInfo, LookupError> {
    let edns = request.edns();
    let lookup_options = LookupOptions::from_edns(edns);
    let request_id = request.id();

    if lookup_options.dnssec_ok {
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
        let (mut result, mut signer) = authority.search(request, lookup_options).await;
        #[cfg(feature = "metrics")]
        metrics.update_zone_lookup(authority.as_ref(), &result);

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

                let (new_result, new_signer) = consult_authority
                    .consult(
                        request_info.query.name(),
                        request_info.query.query_type(),
                        Some(&request_info),
                        LookupOptions::from_edns(response_edns.as_ref()),
                        result,
                    )
                    .await;
                if let Some(new_signer) = new_signer {
                    signer = Some(new_signer);
                }
                result = new_result;
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

        let mut message_response =
            MessageResponseBuilder::new(request.raw_queries(), response_edns.clone()).build(
                response_header,
                sections.answers.iter(),
                sections.ns.iter(),
                sections.soa.iter(),
                sections.additionals.iter(),
            );

        if let Some(signer) = signer {
            let mut tbs_response_buf = Vec::with_capacity(512);
            let mut encoder = BinEncoder::with_mode(&mut tbs_response_buf, EncodeMode::Normal);
            let tbs_response = MessageResponseBuilder::new(request.raw_queries(), response_edns)
                .build(
                    response_header,
                    sections.answers.iter(),
                    sections.ns.iter(),
                    sections.soa.iter(),
                    sections.additionals.iter(),
                );
            tbs_response.destructive_emit(&mut encoder)?;
            message_response.set_signature(signer.sign(&tbs_response_buf)?);
        }

        #[cfg(feature = "metrics")]
        metrics.update_request_response(query, sections.answers.iter());

        match response_handle.send_response(message_response).await {
            Err(error) => {
                error!(%error, "error sending response");
                return Err(LookupError::Io(error));
            }
            Ok(l) => return Ok(l),
        }
    }

    error!("end of chained authority loop reached with all authorities not answering");
    Err(LookupError::ResponseCode(ResponseCode::ServFail))
}

/// Build Header and LookupSections (answers) given a query response from an authority
async fn build_response(
    result: Result<AuthLookup, LookupError>,
    authority: &dyn Authority,
    request_id: u16,
    request_header: &Header,
    query: &LowerQuery,
    edns: Option<&Edns>,
) -> (Header, LookupSections) {
    let lookup_options = LookupOptions::from_edns(edns);

    let mut response_header = Header::response_from_request(request_header);
    let sections = match authority.zone_type() {
        ZoneType::Primary | ZoneType::Secondary => {
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
        ZoneType::External => {
            build_forwarded_response(
                result,
                request_header,
                &mut response_header,
                #[cfg(feature = "__dnssec")]
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
    response: Result<AuthLookup, LookupError>,
    authority: &dyn Authority,
    response_header: &mut Header,
    lookup_options: LookupOptions,
    _request_id: u16,
    query: &LowerQuery,
) -> LookupSections {
    response_header.set_authoritative(true);

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
            return LookupSections::default();
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

    #[cfg_attr(not(feature = "__dnssec"), allow(unused_variables))]
    let (ns, soa) = if let Some(answers) = &answers {
        // SOA queries should return the NS records as well.
        if query.query_type().is_soa() {
            // This was a successful authoritative lookup for SOA:
            //   get the NS records as well.

            match authority.ns(lookup_options).await.map_result() {
                Some(Ok(ns)) => (Some(ns), None),
                Some(Err(error)) => {
                    warn!(%error, "ns_lookup errored");
                    (None, None)
                }
                None => {
                    warn!("ns_lookup unexpected skip");
                    (None, None)
                }
            }
        } else {
            #[cfg(feature = "__dnssec")]
            {
                if let Some(NxProofKind::Nsec3 {
                    algorithm,
                    salt,
                    iterations,
                    opt_out: _,
                }) = authority.nx_proof_kind()
                {
                    let has_wildcard_match = answers
                        .iter()
                        .any(|rr| rr.record_type() == RecordType::RRSIG && rr.name().is_wildcard());

                    match authority
                        .nsec3_records(
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
                        Some(Err(error)) => {
                            warn!(%error, request_id = _request_id, "failed to lookup nsecs for request");
                            (None, None)
                        }
                        None => {
                            warn!(
                                request_id = _request_id,
                                "unexpected lookup skip for request"
                            );
                            (None, None)
                        }
                    }
                } else {
                    (None, None)
                }
            }
            #[cfg(not(feature = "__dnssec"))]
            (None, None)
        }
    } else {
        let nsecs = if lookup_options.dnssec_ok {
            #[cfg(feature = "__dnssec")]
            {
                // in the dnssec case, nsec records should exist, we return NoError + NoData + NSec...
                debug!("request: {_request_id} non-existent adding nsecs");
                match authority.nx_proof_kind() {
                    Some(nx_proof_kind) => {
                        // run the nsec lookup future, and then transition to get soa
                        let future = match nx_proof_kind {
                            NxProofKind::Nsec => {
                                authority.nsec_records(query.name(), lookup_options)
                            }
                            NxProofKind::Nsec3 {
                                algorithm,
                                salt,
                                iterations,
                                opt_out: _,
                            } => authority.nsec3_records(
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
                            Some(Err(error)) => {
                                warn!(%error, request_id = _request_id, "failed to lookup nsecs for request");
                                None
                            }
                            None => {
                                warn!(
                                    request_id = _request_id,
                                    "unexpected lookup skip for request"
                                );
                                None
                            }
                        }
                    }
                    None => None,
                }
            }
            #[cfg(not(feature = "__dnssec"))]
            None
        } else {
            None
        };

        match authority.soa_secure(lookup_options).await.map_result() {
            Some(Ok(soa)) => (nsecs, Some(soa)),
            Some(Err(error)) => {
                warn!(%error, "failed to lookup soa");
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
            Some(additionals) => (
                answers,
                AuthLookup::Records {
                    answers: additionals,
                    additionals: None,
                },
            ),
            None => (answers, AuthLookup::default()),
        },
        None => (AuthLookup::default(), AuthLookup::default()),
    };

    LookupSections {
        answers,
        ns: ns.unwrap_or_default(),
        soa: soa.unwrap_or_default(),
        additionals,
    }
}

/// Prepare a response for a forwarded zone.
async fn build_forwarded_response(
    response: Result<AuthLookup, LookupError>,
    request_header: &Header,
    response_header: &mut Header,
    #[cfg(feature = "__dnssec")] can_validate_dnssec: bool,
    query: &LowerQuery,
    lookup_options: LookupOptions,
) -> LookupSections {
    response_header.set_recursion_available(true);
    response_header.set_authoritative(false);
    if !request_header.recursion_desired() {
        info!(
            id = request_header.id(),
            "request disabled recursion, returning REFUSED"
        );

        response_header.set_response_code(ResponseCode::Refused);
        return LookupSections::default();
    }

    enum Answer {
        Normal(AuthLookup),
        NoRecords(AuthLookup),
    }

    #[cfg_attr(not(feature = "__dnssec"), allow(unused_mut))]
    let (mut answers, authorities) = match response {
        Ok(l) => (Answer::Normal(l), AuthLookup::default()),
        Err(e) if e.is_no_records_found() || e.is_nx_domain() => {
            debug!(error = ?e, "error resolving");

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
                                query_name = %query.name(),
                                record = ?x,
                                "changing response code from NXDomain to NoError due to other record",
                            );
                            response_header.set_response_code(ResponseCode::NoError);
                        }

                        match x.record_type() {
                            RecordType::SOA => None,
                            _ => Some(Arc::new(RecordSet::from(x.clone()))),
                        }
                    })
                    .collect();

                AuthLookup::answers(
                    LookupRecords::many(LookupOptions::default(), authorities),
                    None,
                )
            } else {
                AuthLookup::default()
            };

            if let Some(soa) = e.into_soa() {
                let soa = soa.into_record_of_rdata();
                let record_set = Arc::new(RecordSet::from(soa));
                let records = LookupRecords::new(LookupOptions::default(), record_set);

                (Answer::NoRecords(AuthLookup::SOA(records)), authorities)
            } else {
                (Answer::Normal(AuthLookup::default()), authorities)
            }
        }
        #[cfg(all(feature = "__dnssec", feature = "recursor"))]
        Err(LookupError::RecursiveError(recursor::Error {
            kind:
                ErrorKind::Proto(ProtoError {
                    kind:
                        ProtoErrorKind::Nsec {
                            response, proof, ..
                        },
                    ..
                }),
            ..
        })) if proof.is_insecure() => {
            response_header.set_response_code(response.response_code());

            if let Some(soa) = response.soa() {
                let soa = soa.to_owned().into_record_of_rdata();
                let record_set = Arc::new(RecordSet::from(soa));
                let records = LookupRecords::new(LookupOptions::default(), record_set);

                (
                    Answer::NoRecords(AuthLookup::SOA(records)),
                    AuthLookup::default(),
                )
            } else {
                (Answer::Normal(AuthLookup::default()), AuthLookup::default())
            }
        }
        Err(e) => {
            response_header.set_response_code(ResponseCode::ServFail);
            debug!(error = ?e, "error resolving");
            (Answer::Normal(AuthLookup::default()), AuthLookup::default())
        }
    };

    // If DNSSEC is disabled, we ignore the CD bit and do not set the AD bit.
    #[cfg(feature = "__dnssec")]
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
        // C. it's less clear if DNSSEC validation can be skipped altogether when CD=1
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
            Answer::Normal(answers) => match DnssecSummary::from_records(answers.iter()) {
                DnssecSummary::Secure => {
                    trace!("setting ad header");
                    response_header.set_authentic_data(true);
                }
                DnssecSummary::Bogus if !request_header.checking_disabled() => {
                    response_header.set_response_code(ResponseCode::ServFail);
                    // do not return Bogus records when CD=0
                    *answers = AuthLookup::default();
                }
                _ => {}
            },
            Answer::NoRecords(soa) => match DnssecSummary::from_records(authorities.iter()) {
                DnssecSummary::Secure => {
                    trace!("setting ad header");
                    response_header.set_authentic_data(true);
                }
                DnssecSummary::Bogus if !request_header.checking_disabled() => {
                    response_header.set_response_code(ResponseCode::ServFail);
                    // do not return Bogus records when CD=0
                    *soa = AuthLookup::default();
                    trace!("clearing SOA record from response");
                }
                _ => {}
            },
        }
    }

    // Strip out DNSSEC records unless the DO bit is set.
    let authorities = if !lookup_options.dnssec_ok {
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

        AuthLookup::answers(LookupRecords::many(LookupOptions::default(), auth), None)
    } else {
        authorities
    };

    match answers {
        Answer::Normal(answers) => LookupSections {
            answers,
            ns: authorities,
            ..LookupSections::default()
        },
        Answer::NoRecords(soa) => LookupSections {
            ns: authorities,
            soa,
            ..LookupSections::default()
        },
    }
}

#[derive(Default)]
struct LookupSections {
    answers: AuthLookup,
    ns: AuthLookup,
    soa: AuthLookup,
    additionals: AuthLookup,
}
