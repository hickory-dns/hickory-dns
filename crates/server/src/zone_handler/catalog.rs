// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// TODO, I've implemented this as a separate entity from the cache, but I wonder if the cache
//  should be the only "front-end" for lookups, where if that misses, then we go to the catalog
//  then, if requested, do a recursive lookup... i.e. the catalog would only point to files.
use std::{collections::HashMap, iter, sync::Arc};

use hickory_proto::runtime::Time;
use tracing::{debug, error, info, trace, warn};

#[cfg(feature = "metrics")]
use crate::zone_handler::metrics::CatalogMetrics;
#[cfg(feature = "__dnssec")]
use crate::{dnssec::NxProofKind, proto::dnssec::DnssecSummary, zone_handler::Nsec3QueryInfo};
#[cfg(all(feature = "__dnssec", feature = "recursor"))]
use crate::{
    proto::{DnsError, ProtoError, ProtoErrorKind},
    recursor,
    recursor::ErrorKind,
};
use crate::{
    proto::{
        op::{Edns, Header, LowerQuery, MessageType, OpCode, ResponseCode},
        rr::{
            LowerName, RecordSet, RecordType,
            rdata::opt::{EdnsCode, EdnsOption, NSIDPayload},
        },
        serialize::binary::{BinEncoder, EncodeMode},
    },
    server::{Request, RequestHandler, RequestInfo, ResponseHandler, ResponseInfo},
    zone_handler::{
        AuthLookup, LookupControlFlow, LookupError, LookupOptions, LookupRecords,
        MessageResponseBuilder, ZoneHandler, ZoneType,
    },
};

/// Set of zones and zone handlers available to this server.
#[derive(Default)]
pub struct Catalog {
    nsid_payload: Option<NSIDPayload>,
    handlers: HashMap<LowerName, Vec<Arc<dyn ZoneHandler>>>,
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
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        trace!("request: {:?}", request);

        let mut resp_edns: Edns;

        // check if it's edns
        let response_edns = if let Some(req_edns) = request.edns() {
            resp_edns = Edns::new();

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
                return send_error_response(
                    request,
                    ResponseCode::BADVERS,
                    Some(&resp_edns),
                    response_handle,
                )
                .await;
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

            Some(&resp_edns)
        } else {
            None
        };

        let now = T::current_time();
        match request.message_type() {
            // TODO think about threading query lookups for multiple lookups, this could be a huge improvement
            //  especially for recursive lookups
            MessageType::Query => match request.op_code() {
                OpCode::Query => {
                    debug!("query received: {}", request.id());
                    self.lookup(request, response_edns, now, response_handle)
                        .await
                }
                OpCode::Update => {
                    debug!("update received: {}", request.id());
                    self.update(request, response_edns, now, response_handle)
                        .await
                }
                c => {
                    warn!("unimplemented op_code: {:?}", c);
                    send_error_response(
                        request,
                        ResponseCode::NotImp,
                        response_edns,
                        response_handle,
                    )
                    .await
                }
            },
            MessageType::Response => {
                warn!("got a response as a request from id: {}", request.id());
                send_error_response(
                    request,
                    ResponseCode::FormErr,
                    response_edns,
                    response_handle,
                )
                .await
            }
        }
    }
}

impl Catalog {
    /// Constructs a new Catalog
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            nsid_payload: None,
            #[cfg(feature = "metrics")]
            metrics: CatalogMetrics::default(),
        }
    }

    /// Insert or update the provided zone handlers
    ///
    /// # Arguments
    ///
    /// * `name` - zone name, e.g. example.com.
    /// * `handlers` - a vec of zone handler objects
    pub fn upsert(&mut self, name: LowerName, handlers: Vec<Arc<dyn ZoneHandler>>) {
        #[cfg(feature = "metrics")]
        for handler in handlers.iter() {
            self.metrics.add_handler(handler.as_ref())
        }

        self.handlers.insert(name, handlers);
    }

    /// Remove a zone from the catalog
    pub fn remove(&mut self, name: &LowerName) -> Option<Vec<Arc<dyn ZoneHandler>>> {
        // NOTE: metrics are not removed to avoid dropping counters that are potentially still
        // being used by other zone handlers having the same labels
        self.handlers.remove(name)
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
        response_edns: Option<&Edns>,
        now: u64,
        mut response_handle: R,
    ) -> ResponseInfo {
        // 2.3 - Zone Section
        //
        //  All records to be updated must be in the same zone, and
        //  therefore the Zone Section is allowed to contain exactly one record.
        //  The ZNAME is the zone name, the ZTYPE must be SOA, and the ZCLASS is
        //  the zone's class.

        let Ok(request_info) = update.request_info() else {
            warn!("invalid update request, zone count must be one");
            return send_error_response(
                update,
                ResponseCode::FormErr,
                response_edns,
                response_handle,
            )
            .await;
        };
        let ztype = request_info.query.query_type();

        if ztype != RecordType::SOA {
            warn!("invalid update request zone type must be SOA, ztype: {ztype}");
            return send_error_response(
                update,
                ResponseCode::FormErr,
                response_edns,
                response_handle,
            )
            .await;
        }

        // verify the zone type and number of zones in request, then find the zone to update
        if let Some(handlers) = self.find(request_info.query.name()) {
            #[allow(clippy::never_loop)]
            for handler in handlers {
                let (response_code, signer) = match handler.zone_type() {
                    ZoneType::Secondary => {
                        error!("secondary forwarding for update not yet implemented");
                        (ResponseCode::NotImp, None)
                    }
                    ZoneType::Primary => {
                        let (update_result, signer) = handler.update(update, now).await;
                        match update_result {
                            // successful update
                            Ok(_) => (ResponseCode::NoError, signer),
                            Err(response_code) => (response_code, signer),
                        }
                    }
                    _ => (ResponseCode::NotAuth, None),
                };

                let response = MessageResponseBuilder::new(update.raw_queries(), response_edns);
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
                    if let Err(error) = tbs_response.destructive_emit(&mut encoder) {
                        error!(%error, "error encoding response");
                        return send_error_response(
                            update,
                            ResponseCode::ServFail,
                            response_edns,
                            response_handle,
                        )
                        .await;
                    }
                    match signer.sign(&tbs_response_buf) {
                        Ok(signature) => response.set_signature(signature),
                        Err(error) => {
                            error!(%error, "error signing response");
                            return send_error_response(
                                update,
                                ResponseCode::ServFail,
                                response_edns,
                                response_handle,
                            )
                            .await;
                        }
                    }
                }

                match response_handle.send_response(response).await {
                    Err(error) => {
                        error!(%error, "error sending message");
                        return ResponseInfo::serve_failed(update);
                    }
                    Ok(response_info) => return response_info,
                }
            }
        };

        send_error_response(
            update,
            ResponseCode::ServFail,
            response_edns,
            response_handle,
        )
        .await
    }

    /// Checks whether the `Catalog` contains DNS records for `name`
    ///
    /// Use this when you know the exact `LowerName` that was used when
    /// adding a zone handler and you don't care about the zone handler it
    /// contains. For public domain names, `LowerName` is usually the
    /// top level domain name like `example.com.`.
    ///
    /// If you do not know the exact domain name to use or you actually
    /// want to use the zone handler it contains, use `find` instead.
    pub fn contains(&self, name: &LowerName) -> bool {
        self.handlers.contains_key(name)
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
        response_edns: Option<&Edns>,
        now: u64,
        response_handle: R,
    ) -> ResponseInfo {
        let Ok(request_info) = request.request_info() else {
            // Wrong number of queries
            return send_error_response(
                request,
                ResponseCode::FormErr,
                response_edns,
                response_handle,
            )
            .await;
        };
        let handlers = self.find(request_info.query.name());

        let Some(handlers) = handlers else {
            // There are no zone handlers registered that can handle the request
            return send_error_response(
                request,
                ResponseCode::Refused,
                response_edns,
                response_handle,
            )
            .await;
        };

        if request_info.query.query_type() == RecordType::AXFR {
            zone_transfer(
                request_info,
                handlers,
                request,
                response_edns,
                now,
                response_handle.clone(),
            )
            .await
        } else {
            lookup(
                request_info,
                handlers,
                request,
                response_edns,
                response_handle.clone(),
                #[cfg(feature = "metrics")]
                &self.metrics,
            )
            .await
        }
    }

    /// Recursively searches the catalog for a matching zone handler
    pub fn find(&self, name: &LowerName) -> Option<&Vec<Arc<dyn ZoneHandler + 'static>>> {
        debug!("searching zone handlers for: {name}");
        self.handlers.get(name).or_else(|| {
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
    handlers: &[Arc<dyn ZoneHandler>],
    request: &Request,
    response_edns: Option<&Edns>,
    mut response_handle: R,
    #[cfg(feature = "metrics")] metrics: &CatalogMetrics,
) -> ResponseInfo {
    let edns = request.edns();
    let lookup_options = LookupOptions::from_edns(edns);
    let request_id = request.id();

    if lookup_options.dnssec_ok {
        info!("request: {request_id} lookup_options: {lookup_options:?}");
    }

    let query = request_info.query;

    for (index, handler) in handlers.iter().enumerate() {
        debug!(
            "performing {query} on zone handler {origin} with request id {request_id}",
            origin = handler.origin(),
        );

        // Wait so we can determine if we need to fire a request to the next zone handler in a
        // chained configuration if the current zone handler declines to answer.
        let (mut result, mut signer) = handler.search(request, lookup_options).await;
        #[cfg(feature = "metrics")]
        metrics.update_zone_lookup(handler.as_ref(), &result);

        if let LookupControlFlow::Skip = result {
            trace!("catalog::lookup: zone handler did not handle request");
            continue;
        } else if result.is_continue() {
            trace!("catalog::lookup: zone handler did handle request with continue");

            // For LookupControlFlow::Continue results, we'll call consult on every
            // zone handler, except the zone handler that returned the Continue result.
            for (continue_index, consult_handler) in handlers.iter().enumerate() {
                if continue_index == index {
                    trace!("skipping current zone handler consult (index {continue_index})");
                    continue;
                } else {
                    trace!("calling zone handler consult (index {continue_index})");
                }

                let (new_result, new_signer) = consult_handler
                    .consult(
                        request_info.query.name(),
                        request_info.query.query_type(),
                        Some(&request_info),
                        LookupOptions::from_edns(response_edns),
                        result,
                    )
                    .await;
                if let Some(new_signer) = new_signer {
                    signer = Some(new_signer);
                }
                result = new_result;
            }
        } else {
            trace!("catalog::lookup: zone handler did handle request with break");
        }

        // We no longer need the context from LookupControlFlow, so decompose into a standard Result
        // to clean up the rest of the match conditions
        let Some(result) = result.map_result() else {
            error!("impossible skip detected after final lookup result");
            return send_error_response(
                request,
                ResponseCode::ServFail,
                response_edns,
                response_handle,
            )
            .await;
        };

        let (response_header, sections) = build_response(
            result,
            &**handler,
            request_id,
            request.header(),
            query,
            edns,
        )
        .await;

        let mut message_response =
            MessageResponseBuilder::new(request.raw_queries(), response_edns).build(
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
            if let Err(error) = tbs_response.destructive_emit(&mut encoder) {
                error!(%error, "error encoding response");
                return send_error_response(
                    request,
                    ResponseCode::ServFail,
                    response_edns,
                    response_handle,
                )
                .await;
            }
            match signer.sign(&tbs_response_buf) {
                Ok(signature) => message_response.set_signature(signature),
                Err(error) => {
                    error!(%error, "error signing response");
                    return send_error_response(
                        request,
                        ResponseCode::ServFail,
                        response_edns,
                        response_handle,
                    )
                    .await;
                }
            }
        }

        #[cfg(feature = "metrics")]
        metrics.update_request_response(query, sections.answers.iter());

        match response_handle.send_response(message_response).await {
            Err(error) => {
                error!(%error, "error sending response");
                return ResponseInfo::serve_failed(request);
            }
            Ok(response_info) => return response_info,
        }
    }

    error!("end of chained zone handler loop reached with all zone handlers not answering");
    send_error_response(
        request,
        ResponseCode::ServFail,
        response_edns,
        response_handle,
    )
    .await
}

async fn zone_transfer(
    request_info: RequestInfo<'_>,
    handlers: &[Arc<dyn ZoneHandler>],
    request: &Request,
    response_edns: Option<&Edns>,
    now: u64,
    mut response_handle: impl ResponseHandler,
) -> ResponseInfo {
    let request_edns = request.edns();
    let lookup_options = LookupOptions::from_edns(request_edns);
    for handler in handlers.iter() {
        debug!(
            query = %request_info.query,
            origin = %handler.origin(),
            request_id = request.id(),
            "performing zone transfer"
        );
        let Some((result, signer)) = handler.zone_transfer(request, lookup_options, now).await
        else {
            continue;
        };

        let mut response_header = Header::response_from_request(request.header());
        let zone_transfer = match result {
            Ok(zone_transfer) => {
                response_header.set_response_code(ResponseCode::NoError);
                response_header.set_authoritative(true);
                Some(zone_transfer)
            }
            Err(e) => {
                match e {
                    LookupError::ResponseCode(
                        rcode @ ResponseCode::Refused | rcode @ ResponseCode::NotAuth,
                    ) => {
                        response_header.set_response_code(rcode);
                    }
                    _ => {
                        if e.is_nx_domain() {
                            response_header.set_response_code(ResponseCode::NXDomain);
                        }
                    }
                }
                None
            }
        };

        // TODO(issue #351): Send more than one message in response as needed.
        let mut message_response =
            MessageResponseBuilder::new(request.raw_queries(), response_edns).build(
                response_header,
                zone_transfer
                    .iter()
                    .flat_map(|zone_transfer| zone_transfer.iter()),
                iter::empty(),
                iter::empty(),
                iter::empty(),
            );

        if let Some(signer) = signer {
            let mut tbs_response_buf = Vec::with_capacity(512);
            let mut encoder = BinEncoder::with_mode(&mut tbs_response_buf, EncodeMode::Normal);
            let tbs_response = MessageResponseBuilder::new(request.raw_queries(), response_edns)
                .build(
                    response_header,
                    zone_transfer
                        .iter()
                        .flat_map(|zone_transfer| zone_transfer.iter()),
                    iter::empty(),
                    iter::empty(),
                    iter::empty(),
                );
            if let Err(error) = tbs_response.destructive_emit(&mut encoder) {
                error!(%error, "error encoding response");
                return send_error_response(
                    request,
                    ResponseCode::ServFail,
                    response_edns,
                    response_handle,
                )
                .await;
            }
            match signer.sign(&tbs_response_buf) {
                Ok(signature) => message_response.set_signature(signature),
                Err(error) => {
                    error!(%error, "error signing response");
                    return send_error_response(
                        request,
                        ResponseCode::ServFail,
                        response_edns,
                        response_handle,
                    )
                    .await;
                }
            }
        }

        match response_handle.send_response(message_response).await {
            Err(error) => {
                error!(%error, "error sending response");
                return ResponseInfo::serve_failed(request);
            }
            Ok(response_info) => return response_info,
        }
    }

    error!("end of chained zone handler loop with all zone handlers not answering");
    send_error_response(
        request,
        ResponseCode::ServFail,
        response_edns,
        response_handle,
    )
    .await
}

/// Helper function to construct a response message with an error response code, and send it via a
/// response handler.
async fn send_error_response(
    request: &Request,
    response_code: ResponseCode,
    mut response_edns: Option<&Edns>,
    mut response_handle: impl ResponseHandler,
) -> ResponseInfo {
    let mut new_edns: Edns;
    if response_code.high() != 0 {
        if let Some(edns) = response_edns {
            new_edns = edns.clone();
            new_edns.set_rcode_high(response_code.high());
            response_edns = Some(&new_edns);
        }
    }
    let response = MessageResponseBuilder::new(request.raw_queries(), response_edns)
        .error_msg(request.header(), response_code);
    match response_handle.send_response(response).await {
        Ok(r) => r,
        Err(error) => {
            error!(%error, "failed to send response");
            ResponseInfo::serve_failed(request)
        }
    }
}

/// Build Header and LookupSections (answers) given a query response from a zone handler
async fn build_response(
    result: Result<AuthLookup, LookupError>,
    handler: &dyn ZoneHandler,
    request_id: u16,
    request_header: &Header,
    query: &LowerQuery,
    edns: Option<&Edns>,
) -> (Header, LookupSections) {
    let lookup_options = LookupOptions::from_edns(edns);

    let mut response_header = Header::response_from_request(request_header);
    let sections = match handler.zone_type() {
        ZoneType::Primary | ZoneType::Secondary => {
            build_authoritative_response(
                result,
                handler,
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
                handler.can_validate_dnssec(),
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
    handler: &dyn ZoneHandler,
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
        // TODO: there are probably other error cases that should just drop through (FormErr, ServFail)
        Err(LookupError::ResponseCode(
            rcode @ ResponseCode::Refused | rcode @ ResponseCode::NotAuth,
        )) => {
            response_header.set_response_code(rcode);
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

            let future = handler.lookup(handler.origin(), RecordType::NS, None, lookup_options);
            match future.await.map_result() {
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
                let has_wildcard_match = answers.iter().any(|rr| {
                    let Some(dnssec) = rr.data().as_dnssec() else {
                        return false;
                    };
                    let Some(rrsig) = dnssec.as_rrsig() else {
                        return false;
                    };

                    rrsig.input().num_labels < rr.name().num_labels()
                });

                let res = match handler.nx_proof_kind() {
                    Some(NxProofKind::Nsec3 {
                        algorithm,
                        salt,
                        iterations,
                        opt_out: _,
                    }) => handler
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
                        .map_result(),
                    Some(NxProofKind::Nsec) if has_wildcard_match => handler
                        .nsec_records(query.name(), lookup_options)
                        .await
                        .map_result(),
                    _ => None,
                };

                match res {
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
                match handler.nx_proof_kind() {
                    Some(nx_proof_kind) => {
                        // run the nsec lookup future, and then transition to get soa
                        let future = match nx_proof_kind {
                            NxProofKind::Nsec => handler.nsec_records(query.name(), lookup_options),
                            NxProofKind::Nsec3 {
                                algorithm,
                                salt,
                                iterations,
                                opt_out: _,
                            } => handler.nsec3_records(
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

        let future = handler.lookup(handler.origin(), RecordType::SOA, None, lookup_options);
        match future.await.map_result() {
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
                    .filter_map(|record| {
                        // if we have another record (probably a dnssec record) that
                        // matches the query name, but wasn't included in the answers
                        // section, change the NXDomain response to NoError
                        if *record.name() == **query.name() {
                            debug!(
                                query_name = %query.name(),
                                ?record,
                                "changing response code from NXDomain to NoError due to other record",
                            );
                            response_header.set_response_code(ResponseCode::NoError);
                        }

                        match record.record_type() {
                            RecordType::SOA => None,
                            _ => Some(record.clone()),
                        }
                    })
                    .collect();

                AuthLookup::answers(LookupRecords::Section(authorities), None)
            } else {
                AuthLookup::default()
            };

            if let Some(soa) = e.into_soa() {
                let soa = soa.into_record_of_rdata();
                let record_set = Arc::new(RecordSet::from(soa));
                let records = LookupRecords::new(LookupOptions::default(), record_set);

                (
                    Answer::NoRecords(AuthLookup::answers(records, None)),
                    authorities,
                )
            } else {
                (Answer::Normal(AuthLookup::default()), authorities)
            }
        }
        #[cfg(all(feature = "__dnssec", feature = "recursor"))]
        Err(LookupError::RecursiveError(recursor::Error {
            kind:
                ErrorKind::Proto(ProtoError {
                    kind:
                        ProtoErrorKind::Dns(DnsError::Nsec {
                            response, proof, ..
                        }),
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
                    Answer::NoRecords(AuthLookup::answers(records, None)),
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
                    if request_header.authentic_data() || lookup_options.dnssec_ok {
                        trace!("setting ad header");
                        response_header.set_authentic_data(true);
                    }
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
                    if request_header.authentic_data() || lookup_options.dnssec_ok {
                        trace!("setting ad header");
                        response_header.set_authentic_data(true);
                    }
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
            .filter_map(|record| {
                let record_type = record.record_type();
                if record_type == query.query_type() || !record_type.is_dnssec() {
                    Some(record.clone())
                } else {
                    None
                }
            })
            .collect();

        AuthLookup::answers(LookupRecords::Section(auth), None)
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
