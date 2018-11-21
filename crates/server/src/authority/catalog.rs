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
// TODO, I've implemented this as a seperate entity from the cache, but I wonder if the cache
//  should be the only "front-end" for lookups, where if that misses, then we go to the catalog
//  then, if requested, do a recursive lookup... i.e. the catalog would only point to files.
use std::collections::HashMap;
use std::io;
use std::sync::RwLock;

use server::{Request, RequestHandler, ResponseHandler};
use trust_dns::op::{Edns, Header, LowerQuery, MessageType, OpCode, ResponseCode};
use trust_dns::rr::dnssec::{Algorithm, SupportedAlgorithms};
use trust_dns::rr::rdata::opt::{EdnsCode, EdnsOption};
use trust_dns::rr::{LowerName, RecordType};

use authority::{
    AuthLookup, Authority, MessageRequest, MessageResponse, MessageResponseBuilder, ZoneType,
};
use store::sqlite::LookupRecords;

/// Set of authorities, zones, available to this server.
#[derive(Default)]
pub struct Catalog {
    authorities: HashMap<LowerName, RwLock<Box<dyn Authority>>>,
}

fn send_response<R: ResponseHandler + 'static>(
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

impl RequestHandler for Catalog {
    /// Determine's what needs to happen given the type of request, i.e. Query or Update.
    ///
    /// # Arguments
    ///
    /// * `request` - the requested action to perform.
    /// * `response_handle` - sink for the response message to be sent
    fn handle_request<'q, 'a, R: ResponseHandler + 'static>(
        &'a self,
        request: &'q Request,
        response_handle: R,
    ) -> io::Result<()> {
        let request_message = &request.message;
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
                return response_handle.send_response(response.build(response_header));
            }

            response_edns = Some(resp_edns);
        } else {
            response_edns = None;
        }

        match request_message.message_type() {
            // TODO think about threading query lookups for multiple lookups, this could be a huge improvement
            //  especially for recursive lookups
            MessageType::Query => match request_message.op_code() {
                OpCode::Query => self.lookup(request_message, response_edns, response_handle),
                OpCode::Update => self.update(request_message, response_edns, response_handle),
                c => {
                    error!("unimplemented op_code: {:?}", c);
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
        }
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
    pub fn upsert(&mut self, name: LowerName, authority: Box<dyn Authority>) {
        self.authorities.insert(name, RwLock::new(authority));
    }

    /// Remove a zone from the catalog
    pub fn remove(&mut self, name: &LowerName) -> Option<RwLock<Box<dyn Authority>>> {
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
    ///   to the requestor.  If the server is a zone slave, the request will be
    ///   forwarded toward the primary master.
    ///
    ///   3.1.2 - Pseudocode For Zone Section Processing
    ///
    ///      if (zcount != 1 || ztype != SOA)
    ///           return (FORMERR)
    ///      if (zone_type(zname, zclass) == SLAVE)
    ///           return forward()
    ///      if (zone_type(zname, zclass) == MASTER)
    ///           return update()
    ///      return (NOTAUTH)
    ///
    ///   Sections 3.2 through 3.8 describe the primary master's behaviour,
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
        if zones.len() != 1 || zones[0].query_type() != RecordType::SOA {
            response_header.set_response_code(ResponseCode::FormErr);

            return send_response(
                response_edns,
                response.build(response_header),
                response_handle,
            );
        }

        if let Some(authority) = self.find(zones[0].name()) {
            let mut authority = authority.write().unwrap(); // poison errors should panic...
            match authority.zone_type() {
                ZoneType::Slave => {
                    error!("slave forwarding for update not yet implemented");
                    response_header.set_response_code(ResponseCode::NotImp);

                    return send_response(
                        response_edns,
                        response.build(response_header),
                        response_handle,
                    );
                }
                ZoneType::Master => {
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

                    return send_response(
                        response_edns,
                        response.build(response_header),
                        response_handle,
                    );
                }
                _ => {
                    response_header.set_response_code(ResponseCode::NotAuth);

                    return send_response(
                        response_edns,
                        response.build(response_header),
                        response_handle,
                    );
                }
            }
        } else {
            response_header.set_response_code(ResponseCode::NXDomain);

            return send_response(
                response_edns,
                response.build(response_header),
                response_handle,
            );
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
    pub fn lookup<'q, R: ResponseHandler + 'static>(
        &self,
        request: &'q MessageRequest,
        response_edns: Option<Edns>,
        response_handle: R,
    ) -> io::Result<()> {
        // TODO: the spec is very unclear on what to do with multiple queries
        //  we will search for each, in the future, maybe make this threaded to respond even faster.
        for query in request.queries() {
            if let Some(ref_authority) = self.find(query.name()) {
                let authority = &ref_authority.read().unwrap(); // poison errors should panic
                info!(
                    "request: {} found authority: {}",
                    request.id(),
                    authority.origin()
                );

                let mut response = MessageResponseBuilder::new(Some(request.raw_queries()));
                let mut response_header = Header::new();
                response_header.set_id(request.id());
                response_header.set_op_code(OpCode::Query);
                response_header.set_message_type(MessageType::Response);

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

                let records = authority.search(query, is_dnssec, supported_algorithms);

                // setup headers
                //  and add records
                if !records.is_empty() {
                    response_header.set_response_code(ResponseCode::NoError);
                    response_header.set_authoritative(true);
                    response.answers(records);

                    // get the NS records
                    let ns = authority.ns(is_dnssec, supported_algorithms);
                    // chain here to match type below...
                    response.name_servers(ns.chain(LookupRecords::NxDomain));
                } else if records.is_refused() {
                    response_header.set_response_code(ResponseCode::Refused);
                } else {
                    // in the not found case it's standard to return the SOA in the authority section
                    //   if the name is in this zone, etc.
                    // see https://tools.ietf.org/html/rfc2308 for proper response construct
                    match records {
                        AuthLookup::NxDomain => {
                            response_header.set_response_code(ResponseCode::NXDomain)
                        }
                        AuthLookup::NameExists => {
                            response_header.set_response_code(ResponseCode::NoError)
                        }
                        AuthLookup::Refused => {
                            panic!("programming error, should have return Refused above")
                        }
                        AuthLookup::Records(_) | AuthLookup::SOA(_) | AuthLookup::AXFR(_) => {
                            panic!(
                                "programming error, should have return NoError with records above"
                            )
                        }
                    };

                    // in the dnssec case, nsec records should exist, we return NoError + NoData + NSec...
                    let ns = if is_dnssec {
                        // get NSEC records
                        let mut nsecs = authority.get_nsec_records(
                            query.name(),
                            is_dnssec,
                            supported_algorithms,
                        );
                        debug!("request: {} non-existent adding nsecs", request.id(),);

                        response_header.set_response_code(ResponseCode::NoError);
                        nsecs
                    } else {
                        // place holder...
                        debug!("request: {} non-existent", request.id());
                        LookupRecords::NxDomain
                    };

                    let soa = authority.soa_secure(is_dnssec, supported_algorithms);
                    let ns = ns.chain(soa);

                    response.name_servers(ns);
                }

                return send_response(
                    response_edns,
                    response.build(response_header),
                    response_handle,
                );
            }
        }

        let response = MessageResponseBuilder::new(Some(request.raw_queries()));
        send_response(
            response_edns,
            response.error_msg(request.id(), request.op_code(), ResponseCode::NXDomain),
            response_handle,
        )
    }

    /// Recursively searches the catalog for a matching authority
    pub fn find(&self, name: &LowerName) -> Option<&RwLock<Box<dyn Authority>>> {
        self.authorities.get(name).or_else(|| {
            let name = name.base_name();
            if !name.is_root() {
                self.find(&name)
            } else {
                None
            }
        })
    }
}
