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
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures::{ready, Future, FutureExt, TryFutureExt};
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
    authorities: HashMap<LowerName, Arc<RwLock<Box<dyn AuthorityObject>>>>,
}

fn send_response<R: ResponseHandler>(
    response_edns: Option<Edns>,
    mut response: MessageResponse,
    response_handle: R,
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

#[async_trait]
impl RequestHandler for Arc<Mutex<Catalog>> {
    /// Determines what needs to happen given the type of request, i.e. Query or Update.
    ///
    /// # Arguments
    ///
    /// * `request` - the requested action to perform.
    /// * `response_handle` - sink for the response message to be sent
    async fn handle_request<R: ResponseHandler>(&self, request: Request, response_handle: R) {
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
                log_error(
                    response_handle.send_response(response.build_no_records(response_header)),
                );
                return;
            }

            response_edns = Some(resp_edns);
        } else {
            response_edns = None;
        }

        match request_message.message_type() {
            // TODO think about threading query lookups for multiple lookups, this could be a huge improvement
            //  especially for recursive lookups
            MessageType::Query => match request_message.op_code() {
                OpCode::Query => {
                    debug!("query received: {}", request_message.id());
                    let locked = self.lock().expect("lock poisoned");
                    locked
                        .lookup(request_message, response_edns, response_handle)
                        .await;
                }
                OpCode::Update => {
                    debug!("update received: {}", request_message.id());
                    // TODO: this should be a future
                    let locked = self.lock().expect("lock poisoned");
                    log_error(locked.update(&request_message, response_edns, response_handle));
                }
                c => {
                    warn!("unimplemented op_code: {:?}", c);
                    let response = MessageResponseBuilder::new(Some(request_message.raw_queries()));
                    log_error(response_handle.send_response(response.error_msg(
                        request_message.id(),
                        request_message.op_code(),
                        ResponseCode::NotImp,
                    )));
                }
            },
            MessageType::Response => {
                warn!(
                    "got a response as a request from id: {}",
                    request_message.id()
                );
                let response = MessageResponseBuilder::new(Some(request_message.raw_queries()));

                log_error(response_handle.send_response(response.error_msg(
                    request_message.id(),
                    request_message.op_code(),
                    ResponseCode::FormErr,
                )));
            }
        }
    }
}

fn log_error(result: io::Result<()>) {
    if let Err(e) = result {
        error!("update failed: {}", e);
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
        // self.authorities.insert(name, Arc::new(RwLock::new(authority)));
        self.authorities
            .insert(name, Arc::new(RwLock::new(authority)));
    }

    /// Remove a zone from the catalog
    pub fn remove(&mut self, name: &LowerName) -> Option<Arc<RwLock<Box<dyn AuthorityObject>>>> {
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
        let response = MessageResponseBuilder::new(None);
        let mut response_header = Header::default();
        response_header.set_id(update.id());
        response_header.set_op_code(OpCode::Update);
        response_header.set_message_type(MessageType::Response);

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
        if zones.len() != 1 || ztype != RecordType::SOA {
            warn!(
                "invalid update request zones must be 1 and not SOA records, zones: {} ztype: {}",
                zones.len(),
                ztype
            );
            response_header.set_response_code(ResponseCode::FormErr);

            return send_response(
                response_edns,
                response.build_no_records(response_header),
                response_handle,
            );
        }

        if let Some(authority) = zones
            .first()
            .map(LowerQuery::name)
            .and_then(|name| self.find(name))
        {
            let mut authority = authority.write().unwrap(); // poison errors should panic...

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
                    response_header.set_response_code(ResponseCode::NotImp);

                    send_response(
                        response_edns,
                        response.build_no_records(response_header),
                        response_handle,
                    )
                }
                ZoneType::Primary | ZoneType::Master => {
                    let update_result = authority.update(update);
                    match update_result {
                        // successful update
                        Ok(..) => {
                            response_header.set_response_code(ResponseCode::NoError);
                        }
                        Err(response_code) => {
                            response_header.set_response_code(response_code);
                        }
                    }

                    send_response(
                        response_edns,
                        response.build_no_records(response_header),
                        response_handle,
                    )
                }
                _ => {
                    response_header.set_response_code(ResponseCode::NotAuth);

                    send_response(
                        response_edns,
                        response.build_no_records(response_header),
                        response_handle,
                    )
                }
            }
        } else {
            response_header.set_response_code(ResponseCode::Refused);

            send_response(
                response_edns,
                response.build_no_records(response_header),
                response_handle,
            )
        }
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
        request: MessageRequest,
        response_edns: Option<Edns>,
        response_handle: R,
    ) {
        let request = Arc::new(request);
        let response_edns = response_edns.map(Arc::new);

        // TODO: the spec is very unclear on what to do with multiple queries
        //  we will search for each, in the future, maybe make this threaded to respond even faster.
        //  the current impl will return on the first query result

        // collect all the queries and lookups
        let queries_and_authorities = request
            .queries()
            .iter()
            .enumerate()
            .filter_map(|(idx, q)| {
                self.find(q.name())
                    .map(|authority| (idx, Arc::clone(authority)))
            })
            .collect::<Vec<_>>();

        if queries_and_authorities.is_empty() {
            let response = MessageResponseBuilder::new(Some(request.raw_queries()));
            log_error(send_response(
                response_edns
                    .as_ref()
                    .map(|arc| Borrow::<Edns>::borrow(arc).clone()),
                response.error_msg(request.id(), request.op_code(), ResponseCode::NXDomain),
                response_handle.clone(),
            ));
            return;
        }

        lookup(
            request,
            response_edns,
            response_handle,
            queries_and_authorities,
        )
        .await
    }

    /// Recursively searches the catalog for a matching authority
    pub fn find(&self, name: &LowerName) -> Option<&Arc<RwLock<Box<dyn AuthorityObject>>>> {
        debug!("searching authorities for: {}", name);
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

#[allow(clippy::type_complexity)]
async fn lookup<R: ResponseHandler>(
    request: Arc<MessageRequest>,
    response_edns: Option<Arc<Edns>>,
    response_handle: R,
    mut queries_and_authorities: Vec<(usize, Arc<RwLock<Box<dyn AuthorityObject>>>)>,
) {
    while let Some((query_idx, ref_authority)) = queries_and_authorities.pop() {
        let query = if let Some(query) = request.queries().get(query_idx) {
            query
        } else {
            // bad state, could just panic
            error!("query_idx out of bounds? {}", query_idx);
            continue;
        };

        let authority = &ref_authority.read().unwrap(); // poison errors should panic
        info!(
            "request: {} found authority: {}",
            request.id(),
            authority.origin()
        );

        let mut response_header = Header::new();
        response_header.set_id(request.id());
        response_header.set_op_code(OpCode::Query);
        response_header.set_message_type(MessageType::Response);
        response_header.set_authoritative(authority.zone_type().is_authoritative());

        let (is_dnssec, supported_algorithms) =
            request
                .edns()
                .map_or((false, SupportedAlgorithms::new()), |edns| {
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
                request.id(),
                supported_algorithms
            );
        }

        debug!("performing {} on {}", query, authority.origin());
        let lookup_future = authority.search(query, is_dnssec, supported_algorithms);

        let request_params = RequestParams {
            is_dnssec,
            supported_algorithms,
            query: query.clone(),
            request: Arc::clone(&request),
        };
        let response_params = ResponseParams {
            response_edns: response_edns.clone(),
            response_header,
            response_handle: response_handle.clone(),
        };

        #[allow(deprecated)]
        match authority.zone_type() {
            ZoneType::Primary | ZoneType::Secondary | ZoneType::Master | ZoneType::Slave => {
                AuthorityLookup::authority(
                    request.id(),
                    response_params,
                    request_params,
                    lookup_future,
                    Arc::clone(&ref_authority),
                ).await
            }
            ZoneType::Forward | ZoneType::Hint => {
                AuthorityLookup::resolve(
                    request.id(),
                    response_params,
                    request_params,
                    lookup_future,
                    Arc::clone(&ref_authority),
                ).await
            }
        }
    }
}

struct RequestParams {
    is_dnssec: bool,
    supported_algorithms: SupportedAlgorithms,
    query: LowerQuery,
    request: Arc<MessageRequest>,
}

struct ResponseParams<R: ResponseHandler> {
    response_edns: Option<Arc<Edns>>,
    response_header: Header,
    response_handle: R,
}

/// Authority Lookup future to perform all actions for authoritative responses.
#[must_use = "futures do nothing unless polled"]
struct AuthorityLookup<R: ResponseHandler> {
    response_params: Option<ResponseParams<R>>,
    request_params: RequestParams,
    authority: Arc<RwLock<Box<dyn AuthorityObject>>>,
    state: AuthOrResolve,
}

impl<R: ResponseHandler> AuthorityLookup<R> {
    fn authority(
        request_id: u16,
        response_params: ResponseParams<R>,
        request_params: RequestParams,
        record_lookup: BoxedLookupFuture,
        authority: Arc<RwLock<Box<dyn AuthorityObject>>>,
    ) -> Self {
        debug!("handling authoritative request: {}", request_id);

        AuthorityLookup {
            response_params: Some(response_params),
            request_params,
            authority,
            state: AuthOrResolve::AuthorityLookupState(AuthorityLookupState::Records {
                record_lookup,
            }),
        }
    }

    fn resolve(
        request_id: u16,
        response_params: ResponseParams<R>,
        request_params: RequestParams,
        record_lookup: BoxedLookupFuture,
        authority: Arc<RwLock<Box<dyn AuthorityObject>>>,
    ) -> Self {
        debug!("handling forwarded resolve: {}", request_id);

        AuthorityLookup {
            response_params: Some(response_params),
            request_params,
            authority,
            state: AuthOrResolve::ResolveLookupState(ResolveLookupState::Records { record_lookup }),
        }
    }
}

impl<R: ResponseHandler> AuthorityLookup<R> {
    #[allow(clippy::type_complexity)]
    fn split(
        &mut self,
    ) -> (
        &mut ResponseParams<R>,
        &RequestParams,
        &Arc<RwLock<Box<dyn AuthorityObject>>>,
        &mut AuthOrResolve,
    ) {
        (
            self.response_params
                .as_mut()
                .expect("bad state, response_params should not be none here"),
            &self.request_params,
            &self.authority,
            &mut self.state,
        )
    }
}

impl<R: ResponseHandler> Future for AuthorityLookup<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let (response_params, request_params, authority, state) = self.split();

        let sections = ready!(state.poll(cx, request_params, response_params, authority));

        let records = sections.answers;
        let soa = sections.soa;
        let ns = sections.ns;
        let additionals = sections.additionals;

        let response_params = self
            .response_params
            .take()
            .expect("AuthorityLookup already complete");
        let response_edns = response_params.response_edns;
        let response = MessageResponseBuilder::new(Some(self.request_params.request.raw_queries()));
        let response_header = response_params.response_header;
        let response_handle = response_params.response_handle;

        send_response(
            response_edns
                .as_ref()
                .map(|arc| Borrow::<Edns>::borrow(arc).clone()),
            response.build(
                response_header,
                records.iter(),
                ns.iter(),
                soa.iter(),
                additionals.iter(),
            ),
            response_handle,
        )
        .map_err(|e| error!("error sending response: {}", e))
        .ok();

        Poll::Ready(())
    }
}

struct LookupSections {
    answers: Box<dyn LookupObject>,
    soa: Box<dyn LookupObject>,
    ns: Box<dyn LookupObject>,
    additionals: Box<dyn LookupObject>,
}

#[must_use = "futures do nothing unless polled"]
enum AuthOrResolve {
    AuthorityLookupState(AuthorityLookupState),
    ResolveLookupState(ResolveLookupState),
}

impl AuthOrResolve {
    #[allow(clippy::type_complexity)]
    fn poll<R: ResponseHandler>(
        &mut self,
        cx: &mut Context,
        request_params: &RequestParams,
        response_params: &mut ResponseParams<R>,
        authority: &Arc<RwLock<Box<dyn AuthorityObject>>>,
    ) -> Poll<LookupSections> {
        match self {
            AuthOrResolve::AuthorityLookupState(a) => {
                a.poll(cx, request_params, response_params, authority)
            }
            AuthOrResolve::ResolveLookupState(r) => {
                r.poll(cx, request_params, response_params, authority)
            }
        }
    }
}

/// state machine for handling the response to the request
#[must_use = "futures do nothing unless polled"]
enum AuthorityLookupState {
    /// This is the initial lookup for the Records
    Records { record_lookup: BoxedLookupFuture },
    /// This performs the lookup for NS records, transitions to complete after
    LookupNs {
        ns_lookup: BoxedLookupFuture,
        records: Option<Box<dyn LookupObject>>,
    },
    /// In a negative response case, we need to return the NSEC records
    NxLookupNsec { nsec_lookup: BoxedLookupFuture },
    /// In a negative response case, we need to return the NSEC records
    NxLookupSoa {
        soa_lookup: BoxedLookupFuture,
        nsecs: Option<Box<dyn LookupObject>>,
    },
    /// The Completion state
    Complete {
        // TODO: convert to a single Option with all Boxes
        records: Option<Box<dyn LookupObject>>,
        soa: Option<Box<dyn LookupObject>>,
        ns: Option<Box<dyn LookupObject>>,
    },
}

// TODO: turn this into a real future
impl AuthorityLookupState {
    #[allow(clippy::type_complexity)]
    fn poll<R: ResponseHandler>(
        &mut self,
        cx: &mut Context,
        request_params: &RequestParams,
        response_params: &mut ResponseParams<R>,
        authority: &Arc<RwLock<Box<dyn AuthorityObject>>>,
    ) -> Poll<LookupSections> {
        loop {
            *self = match self {
                // In this state we await the records, on success we transition to getting
                //   NS records, which indicate an authoritative response.
                //
                // On Errors, the transition depends on the type of error.
                AuthorityLookupState::Records { record_lookup } => {
                    match record_lookup.poll_unpin(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(records)) => {
                            response_params
                                .response_header
                                .set_response_code(ResponseCode::NoError);
                            response_params.response_header.set_authoritative(true);

                            // This was a successful authoritative lookup:
                            //   get the NS records
                            let ns_lookup = authority.read().expect("authority poisoned").ns(
                                request_params.is_dnssec,
                                request_params.supported_algorithms,
                            );
                            AuthorityLookupState::LookupNs {
                                ns_lookup,
                                records: Some(records),
                            }
                        }
                        // This request was refused
                        // TODO: there are probably other error cases that should just drop through (FormErr, ServFail)
                        Poll::Ready(Err(LookupError::ResponseCode(ResponseCode::Refused))) => {
                            response_params
                                .response_header
                                .set_response_code(ResponseCode::Refused);

                            let ns = Box::new(AuthLookup::default()) as Box<dyn LookupObject>;
                            let soa = Box::new(AuthLookup::default()) as Box<dyn LookupObject>;
                            let records = Box::new(AuthLookup::default()) as Box<dyn LookupObject>;

                            AuthorityLookupState::Complete {
                                records: Some(records),
                                soa: Some(soa),
                                ns: Some(ns),
                            }
                        }
                        // in the not found case it's standard to return the SOA in the authority section
                        //   if the name is in this zone, etc.
                        // see https://tools.ietf.org/html/rfc2308 for proper response construct
                        Poll::Ready(Err(e)) => {
                            if e.is_nx_domain() {
                                response_params
                                    .response_header
                                    .set_response_code(ResponseCode::NXDomain);
                            } else if e.is_name_exists() {
                                response_params
                                    .response_header
                                    .set_response_code(ResponseCode::NoError);
                            };

                            // in the dnssec case, nsec records should exist, we return NoError + NoData + NSec...
                            let nsec_lookup = if request_params.is_dnssec {
                                debug!(
                                    "request: {} non-existent adding nsecs",
                                    request_params.request.id()
                                );

                                // get NSEC records
                                let nsecs = authority
                                    .read()
                                    .expect("authority poisoned")
                                    .get_nsec_records(
                                        request_params.query.name(),
                                        true,
                                        request_params.supported_algorithms,
                                    );

                                BoxedLookupFuture::from(nsecs)
                            } else {
                                // place holder...
                                debug!("request: {} non-existent", request_params.request.id());
                                BoxedLookupFuture::empty()
                            };

                            AuthorityLookupState::NxLookupNsec { nsec_lookup }
                        }
                    }
                }
                // This is still a successful path, getting the ns records,
                //   which represent an Authoritative answer
                AuthorityLookupState::LookupNs { ns_lookup, records } => {
                    // ns is allowed to fail
                    let ns = match ns_lookup.poll_unpin(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(ns)) => ns,
                        Poll::Ready(Err(e)) => {
                            warn!("ns_lookup errored: {}", e);
                            Box::new(AuthLookup::default()) as Box<dyn LookupObject>
                        }
                    };

                    let soa = Box::new(AuthLookup::default()) as Box<dyn LookupObject>;
                    AuthorityLookupState::Complete {
                        records: records.take(),
                        soa: Some(soa),
                        ns: Some(ns),
                    }
                }
                // run the nsec lookup future, and then transition to get soa
                AuthorityLookupState::NxLookupNsec { nsec_lookup } => {
                    let nsecs = match nsec_lookup.poll_unpin(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(nsecs)) => nsecs,
                        Poll::Ready(Err(e)) => {
                            warn!("failed to lookup nsecs: {}", e);
                            Box::new(AuthLookup::default()) as Box<dyn LookupObject>
                        }
                    };

                    let soa_lookup = authority.read().expect("authority poisoned").soa_secure(
                        request_params.is_dnssec,
                        request_params.supported_algorithms,
                    );

                    AuthorityLookupState::NxLookupSoa {
                        soa_lookup,
                        nsecs: Some(nsecs),
                    }
                }
                // run the soa lookup, and then transition to complete
                AuthorityLookupState::NxLookupSoa { soa_lookup, nsecs } => {
                    let soa = match soa_lookup.poll_unpin(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(soa)) => soa,
                        Poll::Ready(Err(e)) => {
                            warn!("failed to lookup soa: {}", e);
                            Box::new(AuthLookup::default()) as Box<dyn LookupObject>
                        }
                    };

                    let records = Box::new(AuthLookup::default()) as Box<dyn LookupObject>;
                    AuthorityLookupState::Complete {
                        records: Some(records),
                        soa: Some(soa),
                        ns: nsecs.take(),
                    }
                }
                // everything is done, return results.
                AuthorityLookupState::Complete { records, soa, ns } => {
                    let mut records = records
                        .take()
                        .expect("AuthorityLookupState already complete");
                    let additionals = records.take_additionals();

                    let sections = LookupSections {
                        answers: records,
                        soa: soa.take().expect("AuthorityLookupState already complete"),
                        ns: ns.take().expect("AuthorityLookupState already complete"),
                        additionals: additionals.unwrap_or_else(|| {
                            Box::new(AuthLookup::default()) as Box<dyn LookupObject>
                        }),
                    };

                    return Poll::Ready(sections);
                }
            }
        }
    }
}

/// state machine for handling the response to the request
#[must_use = "futures do nothing unless polled"]
enum ResolveLookupState {
    /// This is the initial lookup for the Records
    Records { record_lookup: BoxedLookupFuture },
}

impl ResolveLookupState {
    #[allow(clippy::type_complexity)]
    fn poll<R: ResponseHandler>(
        &mut self,
        cx: &mut Context,
        _request_params: &RequestParams,
        response_params: &mut ResponseParams<R>,
        _authority: &Arc<RwLock<Box<dyn AuthorityObject>>>,
    ) -> Poll<LookupSections> {
        #[allow(clippy::never_loop)]
        loop {
            // TODO: way more states to consider.
            /* *self = */
            match self {
                // In this state we await the records.
                //
                // On Errors, the transition depends on the type of error.
                ResolveLookupState::Records { record_lookup } => {
                    let records = ready!(record_lookup
                        .map_err(|e| {
                            if e.is_nx_domain() {
                                response_params
                                    .response_header
                                    .set_response_code(ResponseCode::NXDomain);
                            };
                            error!("error resolving: {}", e)
                        })
                        .map(|r: Result<_, ()>| match r {
                            Ok(r) => r,
                            Err(()) => Box::new(EmptyLookup),
                        })
                        .poll_unpin(cx));
                    // need to clone the result codes...

                    response_params.response_header.set_authoritative(false);

                    let sections = LookupSections {
                        answers: records,
                        soa: Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
                        ns: Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
                        additionals: Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
                    };

                    return Poll::Ready(sections);
                }
            }
        }
    }
}
