/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// TODO, I've implemented this as a separate entity from the cache, but I wonder if the cache
//  should be the only "front-end" for lookups, where if that misses, then we go to the catalog
//  then, if requested, do a recursive lookup... i.e. the catalog would only point to files.
use std::borrow::Borrow;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;

use log::{debug, error, info, trace, warn};

use crate::authority::{
    AuthLookup, MessageRequest, MessageResponse, MessageResponseBuilder, ZoneType,
};
use crate::authority::{
    AuthorityObject, BoxedLookupFuture, EmptyLookup, LookupError, LookupObject,
};
use crate::client::op::{Edns, Header, LowerQuery, MessageType, OpCode, ResponseCode};
use crate::client::rr::dnssec::{Algorithm, SupportedAlgorithms};
use crate::client::rr::rdata::opt::{EdnsCode, EdnsOption};
use crate::client::rr::{LowerName, RecordType};
use crate::server::{Request, RequestHandler, ResponseHandler};

/// Set of authorities, zones, available to this server.
#[derive(Default)]
pub struct Catalog {
    authorities: HashMap<LowerName, Box<dyn AuthorityObject>>,
}

fn send_response<R: ResponseHandler>(
    response_edns: Option<Edns>,
    mut response: MessageResponse,
    mut response_handle: R,
) -> io::Result<()> {
    if let Some(mut resp_edns) = response_edns {
        // set edns DAU and DHU
        // send along the algorithms which are supported by this authority
        let mut algorithms = SupportedAlgorithms::new();
        algorithms.set(Algorithm::RSASHA256);
        algorithms.set(Algorithm::ECDSAP256SHA256);
        algorithms.set(Algorithm::ECDSAP384SHA384);
        algorithms.set(Algorithm::ED25519);

        let dau = EdnsOption::DAU(algorithms);
        let dhu = EdnsOption::DHU(algorithms);

        resp_edns.set_option(dau);
        resp_edns.set_option(dhu);

        response.set_edns(resp_edns);
    }

    response_handle.send_response(response)
}

impl RequestHandler for Catalog {
    type ResponseFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

    /// Determines what needs to happen given the type of request, i.e. Query or Update.
    ///
    /// # Arguments
    ///
    /// * `request` - the requested action to perform.
    /// * `response_handle` - sink for the response message to be sent
    fn handle_request<R: ResponseHandler>(
        &self,
        request: Request,
        mut response_handle: R,
    ) -> Self::ResponseFuture {
        let request_message = request.message;
        trace!("request: {:?}", request_message);

        let response_edns: Option<Edns>;

        // check if it's edns
        if let Some(req_edns) = request_message.edns() {
            let mut response = MessageResponseBuilder::new(Some(request_message.raw_queries()));
            let mut response_header = Header::default();
            response_header.set_id(request_message.id());

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
                response.edns(resp_edns);

                // TODO: should ResponseHandle consume self?
                let result =
                    response_handle.send_response(response.build_no_records(response_header));
                if let Err(e) = result {
                    error!("request error: {}", e);
                }
                return Box::pin(async {});
            }

            response_edns = Some(resp_edns);
        } else {
            response_edns = None;
        }

        let result = match request_message.message_type() {
            // TODO think about threading query lookups for multiple lookups, this could be a huge improvement
            //  especially for recursive lookups
            MessageType::Query => match request_message.op_code() {
                OpCode::Query => {
                    debug!("query received: {}", request_message.id());
                    return Box::pin(self.lookup(request_message, response_edns, response_handle));
                }
                OpCode::Update => {
                    debug!("update received: {}", request_message.id());
                    // TODO: this should be a future
                    self.update(&request_message, response_edns, response_handle)
                }
                c => {
                    warn!("unimplemented op_code: {:?}", c);
                    let response = MessageResponseBuilder::new(Some(request_message.raw_queries()));
                    response_handle.send_response(response.error_msg(
                        request_message.id(),
                        request_message.op_code(),
                        ResponseCode::NotImp,
                    ))
                }
            },
            MessageType::Response => {
                warn!(
                    "got a response as a request from id: {}",
                    request_message.id()
                );
                let response = MessageResponseBuilder::new(Some(request_message.raw_queries()));
                response_handle.send_response(response.error_msg(
                    request_message.id(),
                    request_message.op_code(),
                    ResponseCode::FormErr,
                ))
            }
        };

        if let Err(e) = result {
            error!("request failed: {}", e);
        }
        Box::pin(async {})
    }
}

impl Catalog {
    /// Constructs a new Catalog
    pub fn new() -> Self {
        Catalog {
            authorities: HashMap::new(),
        }
    }

    /// Insert or update a zone authority
    ///
    /// # Arguments
    ///
    /// * `name` - zone name, e.g. example.com.
    /// * `authority` - the zone data
    pub fn upsert(&mut self, name: LowerName, authority: Box<dyn AuthorityObject>) {
        self.authorities.insert(name, authority);
    }

    /// Remove a zone from the catalog
    pub fn remove(&mut self, name: &LowerName) -> Option<Box<dyn AuthorityObject>> {
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
    pub fn update<'q, R: ResponseHandler + 'static>(
        &self,
        update: &'q MessageRequest,
        response_edns: Option<Edns>,
        response_handle: R,
    ) -> io::Result<()> {
        let zones: &[LowerQuery] = update.queries();

        // 2.3 - Zone Section
        //
        //  All records to be updated must be in the same zone, and
        //  therefore the Zone Section is allowed to contain exactly one record.
        //  The ZNAME is the zone name, the ZTYPE must be SOA, and the ZCLASS is
        //  the zone's class.
        let ztype = zones
            .first()
            .map(LowerQuery::query_type)
            .unwrap_or(RecordType::Unknown(0));

        let result = if zones.len() != 1 || ztype != RecordType::SOA {
            warn!(
                "invalid update request zones must be 1 and not SOA records, zones: {} ztype: {}",
                zones.len(),
                ztype
            );
            Err(ResponseCode::FormErr)
        } else {
            zones
                .first()
                .map(LowerQuery::name)
                .and_then(|name| self.find(name).map(|a| a.box_clone()))
                .ok_or(ResponseCode::Refused)
        };

        let response_code = match result {
            Ok(authority) => {
                // Ask for Master/Slave terms to be replaced
                #[allow(deprecated)]
                match authority.zone_type() {
                    ZoneType::Slave | ZoneType::Master => {
                        warn!("Consider replacing the usage of master/slave with primary/secondary, see Juneteenth.");
                    }
                    _ => (),
                }

                #[allow(deprecated)]
                match authority.zone_type() {
                    ZoneType::Secondary | ZoneType::Slave => {
                        error!("secondary forwarding for update not yet implemented");
                        ResponseCode::NotImp
                    }
                    ZoneType::Primary | ZoneType::Master => {
                        let update_result = authority.update(update);
                        match update_result {
                            // successful update
                            Ok(..) => ResponseCode::NoError,
                            Err(response_code) => response_code,
                        }
                    }
                    _ => ResponseCode::NotAuth,
                }
            }
            Err(response_code) => response_code,
        };

        let response = MessageResponseBuilder::new(None);
        let mut response_header = Header::default();
        response_header.set_id(update.id());
        response_header.set_op_code(OpCode::Update);
        response_header.set_message_type(MessageType::Response);
        response_header.set_response_code(response_code);

        send_response(
            response_edns,
            response.build_no_records(response_header),
            response_handle,
        )
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
    pub fn lookup<R: ResponseHandler>(
        &self,
        request: MessageRequest,
        response_edns: Option<Edns>,
        response_handle: R,
    ) -> impl Future<Output = ()> + 'static {
        let queries_and_authorities = request
            .queries()
            .iter()
            .enumerate()
            .filter_map(|(i, q)| {
                self.find(q.name())
                    .map(|authority| (i, authority.box_clone()))
            })
            .collect::<Vec<_>>();

        if queries_and_authorities.is_empty() {
            let response = MessageResponseBuilder::new(Some(request.raw_queries()));
            send_response(
                response_edns
                    .as_ref()
                    .map(|arc| Borrow::<Edns>::borrow(arc).clone()),
                response.error_msg(request.id(), request.op_code(), ResponseCode::NXDomain),
                response_handle.clone(),
            )
            .map_err(|e| error!("failed to send response: {}", e))
            .ok();
        }

        lookup(
            queries_and_authorities,
            request,
            response_edns,
            response_handle,
        )
    }

    /// Recursively searches the catalog for a matching authority
    pub fn find(&self, name: &LowerName) -> Option<&(dyn AuthorityObject + 'static)> {
        debug!("searching authorities for: {}", name);
        self.authorities
            .get(name)
            .map(|authority| &**authority)
            .or_else(|| {
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
    queries_and_authorities: Vec<(usize, Box<dyn AuthorityObject>)>,
    request: MessageRequest,
    response_edns: Option<Edns>,
    response_handle: R,
) {
    // TODO: the spec is very unclear on what to do with multiple queries
    //  we will search for each, in the future, maybe make this threaded to respond even faster.
    //  the current impl will return on the first query result
    for (query_idx, authority) in queries_and_authorities {
        let query = &request.queries()[query_idx];
        info!(
            "request: {} found authority: {}",
            request.id(),
            authority.origin()
        );

        let (response_header, sections) =
            build_response(&*authority, request.id(), query, request.edns()).await;

        let response = MessageResponseBuilder::new(Some(request.raw_queries())).build(
            response_header,
            sections.answers.iter(),
            sections.ns.iter(),
            sections.soa.iter(),
            sections.additionals.iter(),
        );

        let result = send_response(response_edns.clone(), response, response_handle.clone());
        if let Err(e) = result {
            error!("error sending response: {}", e);
        }
    }
}

async fn build_response(
    authority: &dyn AuthorityObject,
    request_id: u16,
    query: &LowerQuery,
    edns: Option<&Edns>,
) -> (Header, LookupSections) {
    let (is_dnssec, supported_algorithms) =
        edns.map_or((false, SupportedAlgorithms::new()), |edns| {
            let supported_algorithms =
                if let Some(&EdnsOption::DAU(algs)) = edns.option(EdnsCode::DAU) {
                    algs
                } else {
                    debug!("no DAU in request, used default SupportAlgorithms");
                    Default::default()
                };

            (edns.dnssec_ok(), supported_algorithms)
        });

    // log algorithms being requested
    if is_dnssec {
        info!(
            "request: {} supported_algs: {}",
            request_id, supported_algorithms
        );
    }

    let mut response_header = Header::new();
    response_header.set_id(request_id);
    response_header.set_op_code(OpCode::Query);
    response_header.set_message_type(MessageType::Response);
    response_header.set_authoritative(authority.zone_type().is_authoritative());

    debug!("performing {} on {}", query, authority.origin());
    let future = authority.search(query, is_dnssec, supported_algorithms);

    #[allow(deprecated)]
    let sections = match authority.zone_type() {
        ZoneType::Primary | ZoneType::Secondary | ZoneType::Master | ZoneType::Slave => {
            send_authoritative_response(
                future,
                authority,
                &mut response_header,
                is_dnssec,
                supported_algorithms,
                request_id,
                &query,
            )
            .await
        }
        ZoneType::Forward | ZoneType::Hint => {
            send_forwarded_response(future, &mut response_header).await
        }
    };

    (response_header, sections)
}

async fn send_authoritative_response(
    future: BoxedLookupFuture,
    authority: &dyn AuthorityObject,
    response_header: &mut Header,
    is_dnssec: bool,
    supported_algorithms: SupportedAlgorithms,
    request_id: u16,
    query: &LowerQuery,
) -> LookupSections {
    // In this state we await the records, on success we transition to getting
    // NS records, which indicate an authoritative response.
    //
    // On Errors, the transition depends on the type of error.
    let answers = match future.await {
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
                answers: Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
                ns: Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
                soa: Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
                additionals: Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
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
        // This was a successful authoritative lookup:
        //   get the NS records
        match authority.ns(is_dnssec, supported_algorithms).await {
            Ok(ns) => (Some(ns), None),
            Err(e) => {
                warn!("ns_lookup errored: {}", e);
                (None, None)
            }
        }
    } else {
        let nsecs = if is_dnssec {
            // in the dnssec case, nsec records should exist, we return NoError + NoData + NSec...
            debug!("request: {} non-existent adding nsecs", request_id);
            // run the nsec lookup future, and then transition to get soa
            let future = authority.get_nsec_records(query.name(), true, supported_algorithms);
            match future.await {
                // run the soa lookup
                Ok(nsecs) => Some(nsecs),
                Err(e) => {
                    warn!("failed to lookup nsecs: {}", e);
                    None
                }
            }
        } else {
            None
        };

        match authority.soa_secure(is_dnssec, supported_algorithms).await {
            Ok(soa) => (nsecs, Some(soa)),
            Err(e) => {
                warn!("failed to lookup soa: {}", e);
                (nsecs, None)
            }
        }
    };

    // everything is done, return results.
    let (answers, additionals) = match answers {
        Some(mut answers) => match answers.take_additionals() {
            Some(additionals) => (answers, additionals),
            None => (
                answers,
                Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
            ),
        },
        None => (
            Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
            Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
        ),
    };

    LookupSections {
        answers,
        ns: ns.unwrap_or_else(|| Box::new(AuthLookup::default()) as Box<dyn LookupObject>),
        soa: soa.unwrap_or_else(|| Box::new(AuthLookup::default()) as Box<dyn LookupObject>),
        additionals,
    }
}

async fn send_forwarded_response(
    future: BoxedLookupFuture,
    response_header: &mut Header,
) -> LookupSections {
    let answers = match future.await {
        Ok(rsp) => rsp,
        Err(e) => {
            if e.is_nx_domain() {
                response_header.set_response_code(ResponseCode::NXDomain);
            }
            error!("error resolving: {}", e);
            Box::new(EmptyLookup)
        }
    };

    response_header.set_authoritative(false);
    LookupSections {
        answers,
        ns: Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
        soa: Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
        additionals: Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
    }
}

struct LookupSections {
    answers: Box<dyn LookupObject>,
    ns: Box<dyn LookupObject>,
    soa: Box<dyn LookupObject>,
    additionals: Box<dyn LookupObject>,
}
