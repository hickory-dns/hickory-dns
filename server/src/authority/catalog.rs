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
use std::sync::RwLock;

use trust_dns::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode, UpdateMessage};
use trust_dns::rr::{Name, RecordType};
use trust_dns::rr::dnssec::{Algorithm, SupportedAlgorithms};
use trust_dns::rr::rdata::opt::{EdnsCode, EdnsOption};
use server::{Request, RequestHandler};

use authority::{AuthLookup, Authority, ZoneType};

/// Set of authorities, zones, available to this server.
pub struct Catalog {
    authorities: HashMap<Name, RwLock<Authority>>,
}

impl RequestHandler for Catalog {
    /// Determine's what needs to happen given the type of request, i.e. Query or Update.
    ///
    /// # Arguments
    ///
    /// * `request` - the requested action to perform.
    fn handle_request(&self, request: &Request) -> Message {
        let request_message = &request.message;
        trace!("request: {:?}", request_message);

        let mut resp_edns_opt: Option<Edns> = None;

        // check if it's edns
        if let Some(req_edns) = request_message.edns() {
            let mut response = Message::new();
            response.set_id(request_message.id());

            let mut resp_edns: Edns = Edns::new();

            // check our version against the request
            // TODO: what version are we?
            let our_version = 0;
            resp_edns.set_dnssec_ok(true);
            resp_edns.set_max_payload(if req_edns.max_payload() < 512 {
                512
            } else {
                req_edns.max_payload()
            });
            resp_edns.set_version(our_version);

            if req_edns.version() > our_version {
                warn!(
                    "request edns version greater than {}: {}",
                    our_version,
                    req_edns.version()
                );
                response.set_response_code(ResponseCode::BADVERS);
                response.set_edns(resp_edns);
                return response;
            }

            // TODO: add padding for private key hashing, need better knowledge of the length of the
            //   response.
            // resp_edns.set_option()

            resp_edns_opt = Some(resp_edns);
        }

        let mut response: Message = match request_message.message_type() {
            // TODO think about threading query lookups for multiple lookups, this could be a huge improvement
            //  especially for recursive lookups
            MessageType::Query => {
                match request_message.op_code() {
                    OpCode::Query => {
                        let response = self.lookup(&request_message);
                        trace!("query response: {:?}", response);
                        response
                        // TODO, handle recursion here or in the catalog?
                        // recursive queries should be cached.
                    }
                    OpCode::Update => {
                        let response = self.update(request_message);
                        trace!("update response: {:?}", response);
                        response
                    }
                    c @ _ => {
                        error!("unimplemented op_code: {:?}", c);
                        Message::error_msg(
                            request_message.id(),
                            request_message.op_code(),
                            ResponseCode::NotImp,
                        )
                    }
                }
            }
            MessageType::Response => {
                warn!(
                    "got a response as a request from id: {}",
                    request_message.id()
                );
                Message::error_msg(
                    request_message.id(),
                    request_message.op_code(),
                    ResponseCode::NotImp,
                )
            }
        };

        if let Some(mut resp_edns) = resp_edns_opt {
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
            // TODO: if DNSSec supported, sign the package with SIG0
            // get this servers private key ideally use pkcs11
            // sign response and then add SIG0 or TSIG to response
        }

        response
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
    pub fn upsert(&mut self, name: Name, authority: Authority) {
        self.authorities.insert(name, RwLock::new(authority));
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
    pub fn update(&self, update: &Message) -> Message {
        let mut response: Message = Message::new();
        response.set_id(update.id());
        response.set_op_code(OpCode::Update);
        response.set_message_type(MessageType::Response);

        let zones: &[Query] = update.zones();

        // 2.3 - Zone Section
        //
        //  All records to be updated must be in the same zone, and
        //  therefore the Zone Section is allowed to contain exactly one record.
        //  The ZNAME is the zone name, the ZTYPE must be SOA, and the ZCLASS is
        //  the zone's class.
        if zones.len() != 1 || zones[0].query_type() != RecordType::SOA {
            response.set_response_code(ResponseCode::FormErr);
            return response;
        }

        if let Some(authority) = self.find_auth_recurse(zones[0].name()) {
            let mut authority = authority.write().unwrap(); // poison errors should panic...
            match authority.zone_type() {
                ZoneType::Slave => {
                    error!("slave forwarding for update not yet implemented");
                    response.set_response_code(ResponseCode::NotImp);
                    return response;
                }
                ZoneType::Master => {
                    let update_result = authority.update(update);
                    match update_result {
                        // successful update
                        Ok(..) => {
                            response.set_response_code(ResponseCode::NoError);
                        }
                        Err(response_code) => {
                            response.set_response_code(response_code);
                        }
                    }
                    return response;
                }
                _ => {
                    response.set_response_code(ResponseCode::NotAuth);
                    return response;
                }
            }
        } else {
            response.set_response_code(ResponseCode::NXDomain);
            response
        }
    }

    /// Given the requested query, lookup and return any matching results.
    ///
    /// # Arguments
    ///
    /// * `request` - the query message.
    pub fn lookup(&self, request: &Message) -> Message {
        let mut response: Message = Message::new();
        response.set_id(request.id());
        response.set_op_code(OpCode::Query);
        response.set_message_type(MessageType::Response);
        response.add_queries(request.queries().into_iter().cloned());

        // TODO: the spec is very unclear on what to do with multiple queries
        //  we will search for each, in the future, maybe make this threaded to respond even faster.
        for query in request.queries() {
            if let Some(ref_authority) = self.find_auth_recurse(query.name()) {
                let authority = &ref_authority.read().unwrap(); // poison errors should panic
                info!(
                    "request: {} found authority: {}",
                    request.id(),
                    authority.origin()
                );
                let (is_dnssec, supported_algorithms) = request.edns().map_or(
                    (false, SupportedAlgorithms::new()),
                    |edns| {
                        let supported_algorithms =
                            if let Some(&EdnsOption::DAU(algs)) = edns.option(&EdnsCode::DAU) {
                                algs
                            } else {
                                debug!("no DAU in request, used default SupportAlgorithms");
                                Default::default()
                            };

                        (edns.dnssec_ok(), supported_algorithms)
                    },
                );

                // log algorithms being requested
                if is_dnssec {
                    info!(
                        "request: {} supported_algs: {}",
                        request.id(),
                        supported_algorithms
                    );
                }

                let records = authority.search(query, is_dnssec, supported_algorithms);
                if !records.is_empty() {
                    response.set_response_code(ResponseCode::NoError);
                    response.set_authoritative(true);
                    response.add_answers(records.iter().cloned());

                    // get the NS records
                    let ns = authority.ns(is_dnssec, supported_algorithms);
                    if ns.is_empty() {
                        warn!("there are no NS records for: {:?}", authority.origin());
                    } else {
                        response.add_name_servers(ns.iter().cloned());
                    }
                } else {
                    // in the not found case it's standard to return the SOA in the authority section
                    //   if the name is in this zone, etc.
                    // see https://tools.ietf.org/html/rfc2308 for proper response construct
                    match records {
                        AuthLookup::NoName => response.set_response_code(ResponseCode::NXDomain),
                        AuthLookup::NameExists => response.set_response_code(ResponseCode::NoError),
                        AuthLookup::Records(..) => panic!(
                            "programming error, should have return NoError with records above"
                        ),
                    };

                    // in the dnssec case, nsec records should exist, we return NoError + NoData + NSec...
                    if is_dnssec {
                        // get NSEC records
                        let nsecs = authority.get_nsec_records(
                            query.name(),
                            is_dnssec,
                            supported_algorithms,
                        );
                        info!(
                            "request: {} non-existent adding nsecs: {}",
                            request.id(),
                            nsecs.len()
                        );
                        response.add_name_servers(nsecs.into_iter().cloned());
                        response.set_response_code(ResponseCode::NoError);
                    } else {
                        info!("request: {} non-existent", request.id());
                    }

                    let soa = authority.soa_secure(is_dnssec, supported_algorithms);
                    if soa.is_empty() {
                        warn!("there is no SOA record for: {:?}", authority.origin());
                    } else {
                        response.add_name_servers(soa.iter().cloned());
                    }
                }
            } else {
                // we found nothing.
                // TODO: improve: see https://tools.ietf.org/html/rfc2308 for proper response construct
                response.set_response_code(ResponseCode::NXDomain);
            }
        }

        // TODO: a lot of authorities do a recursive query for non-A or AAAA records, and return those in
        //  additional
        response
    }

    /// recursively searches the catalog for a matching auhtority.
    fn find_auth_recurse(&self, name: &Name) -> Option<&RwLock<Authority>> {
        let authority = self.authorities.get(name);
        if authority.is_some() {
            return authority;
        } else {
            let name = name.base_name();
            if !name.is_root() {
                return self.find_auth_recurse(&name);
            }
        }

        None
    }
}
