// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// TODO, I've implemented this as a separate entity from the cache, but I wonder if the cache
//  should be the only "front-end" for lookups, where if that misses, then we go to the catalog
//  then, if requested, do a recursive lookup... i.e. the catalog would only point to files.
use std::{borrow::Borrow, collections::HashMap, io};

use cfg_if::cfg_if;
use tracing::{debug, error, info, trace, warn};

#[cfg(feature = "dnssec")]
use crate::proto::rr::{
    dnssec::{Algorithm, SupportedAlgorithms},
    rdata::opt::{EdnsCode, EdnsOption},
};
use crate::{
    authority::{
        AuthLookup, AuthorityObject, EmptyLookup, LookupControlFlow, LookupError, LookupObject,
        LookupOptions, MessageResponse, MessageResponseBuilder, ZoneType,
    },
    proto::op::{Edns, Header, LowerQuery, MessageType, OpCode, ResponseCode},
    proto::rr::{LowerName, Record, RecordType},
    server::{Request, RequestHandler, RequestInfo, ResponseHandler, ResponseInfo},
};

/// Set of authorities, zones, available to this server.
#[derive(Default)]
pub struct Catalog {
    authorities: HashMap<LowerName, Box<dyn AuthorityObject>>,
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
            // set edns DAU and DHU
            // send along the algorithms which are supported by this authority
            let mut algorithms = SupportedAlgorithms::default();
            algorithms.set(Algorithm::RSASHA256);
            algorithms.set(Algorithm::ECDSAP256SHA256);
            algorithms.set(Algorithm::ECDSAP384SHA384);
            algorithms.set(Algorithm::ED25519);

            let dau = EdnsOption::DAU(algorithms);
            let dhu = EdnsOption::DHU(algorithms);

            resp_edns.options_mut().insert(dau);
            resp_edns.options_mut().insert(dhu);
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

        // verify the zone type and number of zones in request, then find the zone to update
        let request_info = verify_request();
        let authority = request_info.as_ref().map_err(|e| *e).and_then(|info| {
            self.find(info.query.name())
                .map(|a| a.box_clone())
                .ok_or(ResponseCode::Refused)
        });

        let response_code = match authority {
            Ok(authority) => {
                #[allow(deprecated)]
                match authority.zone_type() {
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
                }
            }
            Err(response_code) => response_code,
        };

        let response = MessageResponseBuilder::new(Some(update.raw_query()));
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
        .await
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
        let authority = self.find(request_info.query.name());

        if let Some(authority) = authority {
            let result = lookup(
                request_info,
                authority,
                request,
                response_edns
                    .as_ref()
                    .map(|arc| Borrow::<Edns>::borrow(arc).clone()),
                response_handle.clone(),
            )
            .await;

            match result {
                // The current authority in the chain did not handle the request, so we need to try the next one, if any.
                LookupControlFlow::Skip => {
                    debug!("catalog::lookup::authority DID NOT handle request.");
                    panic!("Correct implementation is part of the chained recursor PR.");
                }
                LookupControlFlow::Continue(Ok(lookup)) | LookupControlFlow::Break(Ok(lookup)) => {
                    debug!("result: {lookup:?}");
                    debug!(
                        "catalog::lookup::authority did handle request with {}. Stopping.",
                        result.variant_as_str(),
                    );

                    lookup
                }
                LookupControlFlow::Continue(Err(e)) | LookupControlFlow::Break(Err(e)) => {
                    debug!("An unexpected error occured during catalog lookup: {e:?}");
                    ResponseInfo::serve_failed()
                }
            }
        } else {
            // if this is empty then the there are no authorities registered that can handle the request
            let response = MessageResponseBuilder::new(Some(request.raw_query()));

            let result = send_response(
                response_edns,
                response.error_msg(request.header(), ResponseCode::Refused),
                response_handle,
            )
            .await;

            match result {
                Err(e) => {
                    error!("failed to send response: {}", e);
                    ResponseInfo::serve_failed()
                }
                Ok(r) => r,
            }
        }
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

async fn lookup<'a, R: ResponseHandler + Unpin>(
    request_info: RequestInfo<'_>,
    authority: &dyn AuthorityObject,
    request: &Request,
    response_edns: Option<Edns>,
    response_handle: R,
) -> LookupControlFlow<ResponseInfo> {
    let query = request_info.query;
    debug!(
        "request: {} found authority: {}",
        request.id(),
        authority.origin()
    );

    let response = build_response(
        authority,
        request_info,
        request.id(),
        request.header(),
        query,
        request.edns(),
    )
    .await;

    let is_continue = response.is_continue();

    match response {
        LookupControlFlow::Continue(Ok(lookup)) | LookupControlFlow::Break(Ok(lookup)) => {
            let (response_header, sections) = lookup;
            let message_response = MessageResponseBuilder::new(Some(request.raw_query())).build(
                response_header,
                sections.answers.iter(),
                sections.ns.iter(),
                sections.soa.iter(),
                sections.additionals.iter(),
            );

            let result = send_response(
                response_edns.clone(),
                message_response,
                response_handle.clone(),
            )
            .await;

            match result {
                Err(e) => {
                    error!("error sending response: {}", e);
                    if is_continue {
                        LookupControlFlow::Continue(Err(LookupError::Io(e)))
                    } else {
                        LookupControlFlow::Break(Err(LookupError::Io(e)))
                    }
                }
                Ok(l) => {
                    if is_continue {
                        LookupControlFlow::Continue(Ok(l))
                    } else {
                        LookupControlFlow::Break(Ok(l))
                    }
                }
            }
        }
        LookupControlFlow::Continue(Err(e)) => LookupControlFlow::Continue(Err(e)),
        LookupControlFlow::Break(Err(e)) => LookupControlFlow::Break(Err(e)),
        LookupControlFlow::Skip => LookupControlFlow::Skip,
    }
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

async fn build_response(
    authority: &dyn AuthorityObject,
    request_info: RequestInfo<'_>,
    request_id: u16,
    request_header: &Header,
    query: &LowerQuery,
    edns: Option<&Edns>,
) -> LookupControlFlow<(Header, LookupSections)> {
    let lookup_options = lookup_options_for_edns(edns);

    // log algorithms being requested
    if lookup_options.dnssec_ok() {
        info!(
            "request: {} lookup_options: {:?}",
            request_id, lookup_options
        );
    }

    let mut response_header = Header::response_from_request(request_header);
    response_header.set_authoritative(authority.zone_type().is_authoritative());

    debug!("performing {} on {}", query, authority.origin());

    // Wait so we can determine if we need to fire a request to the next authority in a chained
    // configuration if the current authority declines to answer. NOTE: This is in preparation
    // for the chained authority PR.
    let result = authority.search(request_info, lookup_options).await;

    // Abort only if the authority declined to handle the request.
    if let LookupControlFlow::Skip = result {
        trace!("build_response: Aborting search on None");
        return LookupControlFlow::Skip;
    }

    #[allow(deprecated)]
    let sections = match authority.zone_type() {
        ZoneType::Primary | ZoneType::Secondary | ZoneType::Master | ZoneType::Slave => {
            send_authoritative_response(
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
            send_forwarded_response(
                result,
                request_header,
                &mut response_header,
                authority.can_validate_dnssec(),
            )
            .await
        }
    };

    LookupControlFlow::Continue(Ok((response_header, sections)))
}

async fn send_authoritative_response(
    response: LookupControlFlow<Box<dyn LookupObject>>,
    authority: &dyn AuthorityObject,
    response_header: &mut Header,
    lookup_options: LookupOptions,
    request_id: u16,
    query: &LowerQuery,
) -> LookupSections {
    // In this state we await the records, on success we transition to getting
    // NS records, which indicate an authoritative response.
    //
    // On Errors, the transition depends on the type of error.
    let answers = match response {
        LookupControlFlow::Continue(Ok(records)) | LookupControlFlow::Break(Ok(records)) => {
            response_header.set_response_code(ResponseCode::NoError);
            response_header.set_authoritative(true);
            Some(records)
        }
        // This request was refused
        // TODO: there are probably other error cases that should just drop through (FormErr, ServFail)
        LookupControlFlow::Continue(Err(LookupError::ResponseCode(ResponseCode::Refused)))
        | LookupControlFlow::Break(Err(LookupError::ResponseCode(ResponseCode::Refused))) => {
            response_header.set_response_code(ResponseCode::Refused);
            return LookupSections {
                answers: Box::<AuthLookup>::default(),
                ns: Box::<AuthLookup>::default(),
                soa: Box::<AuthLookup>::default(),
                additionals: Box::<AuthLookup>::default(),
            };
        }
        LookupControlFlow::Continue(Err(e)) | LookupControlFlow::Break(Err(e)) => {
            if e.is_nx_domain() {
                response_header.set_response_code(ResponseCode::NXDomain);
            } else if e.is_name_exists() {
                response_header.set_response_code(ResponseCode::NoError);
            };
            None
        }
        LookupControlFlow::Skip => {
            debug!("Unexpected lookup skip");
            None
        }
    };

    let (ns, soa) = if answers.is_some() {
        // SOA queries should return the NS records as well.
        if query.query_type().is_soa() {
            // This was a successful authoritative lookup for SOA:
            //   get the NS records as well.
            match authority.ns(lookup_options).await {
                LookupControlFlow::Continue(Ok(ns)) | LookupControlFlow::Break(Ok(ns)) => {
                    (Some(ns), None)
                }
                LookupControlFlow::Continue(Err(e)) | LookupControlFlow::Break(Err(e)) => {
                    warn!("ns_lookup errored: {}", e);
                    (None, None)
                }
                LookupControlFlow::Skip => {
                    warn!("ns_lookup unexpected skip");
                    (None, None)
                }
            }
        } else {
            (None, None)
        }
    } else {
        let nsecs = if lookup_options.dnssec_ok() {
            // in the dnssec case, nsec records should exist, we return NoError + NoData + NSec...
            debug!("request: {} non-existent adding nsecs", request_id);
            // run the nsec lookup future, and then transition to get soa
            let future = authority.get_nsec_records(query.name(), lookup_options);
            match future.await {
                // run the soa lookup
                LookupControlFlow::Continue(Ok(nsecs)) | LookupControlFlow::Break(Ok(nsecs)) => {
                    Some(nsecs)
                }
                LookupControlFlow::Continue(Err(e)) | LookupControlFlow::Break(Err(e)) => {
                    warn!("failed to lookup nsecs: {}", e);
                    None
                }
                LookupControlFlow::Skip => {
                    warn!("Unexpected lookup skip");
                    None
                }
            }
        } else {
            None
        };

        match authority.soa_secure(lookup_options).await {
            LookupControlFlow::Continue(Ok(soa)) | LookupControlFlow::Break(Ok(soa)) => {
                (nsecs, Some(soa))
            }
            LookupControlFlow::Continue(Err(e)) | LookupControlFlow::Break(Err(e)) => {
                warn!("failed to lookup soa: {}", e);
                (nsecs, None)
            }
            LookupControlFlow::Skip => {
                warn!("Unexpected lookup skip");
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

async fn send_forwarded_response(
    response: LookupControlFlow<Box<dyn LookupObject>>,
    request_header: &Header,
    response_header: &mut Header,
    can_validate_dnssec: bool,
) -> LookupSections {
    response_header.set_recursion_available(true);
    response_header.set_authoritative(false);

    // Don't perform the recursive query if this is disabled...
    let mut answers = if !request_header.recursion_desired() {
        info!(
            "request disabled recursion, returning no records: {}",
            request_header.id()
        );

        Box::new(EmptyLookup)
    } else {
        match response {
            LookupControlFlow::Continue(Ok(lookup)) | LookupControlFlow::Break(Ok(lookup)) => {
                lookup
            }
            LookupControlFlow::Continue(Err(e)) | LookupControlFlow::Break(Err(e)) => {
                if e.is_nx_domain() {
                    response_header.set_response_code(ResponseCode::NXDomain);
                }
                debug!("error resolving: {}", e);
                Box::new(EmptyLookup)
            }
            LookupControlFlow::Skip => {
                info!("Unexpected lookup skip");
                Box::new(EmptyLookup)
            }
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
        if answers.dnssec_validated() {
            response_header.set_authentic_data(true);
        } else if !request_header.checking_disabled() {
            response_header.set_response_code(ResponseCode::ServFail);
            // do not return (Insecure | Bogus) records when CD=0
            answers = Box::new(EmptyLookup);
        }
    }

    LookupSections {
        answers,
        ns: Box::<AuthLookup>::default(),
        soa: Box::<AuthLookup>::default(),
        additionals: Box::<AuthLookup>::default(),
    }
}

struct LookupSections {
    answers: Box<dyn LookupObject>,
    ns: Box<dyn LookupObject>,
    soa: Box<dyn LookupObject>,
    additionals: Box<dyn LookupObject>,
}
