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

use ::rr::{Record, Name, RecordType};
use ::authority::{Authority, ZoneType};
use ::op::*;

#[derive(Debug)]
pub struct Catalog {
  authorities: HashMap<Name, RwLock<Authority>>,
}

impl Catalog {
  pub fn new() -> Self {
    Catalog{ authorities: HashMap::new() }
  }

  pub fn handle_request(&self, request: &Message) -> Message {
    info!("id: {} type: {:?} op_code: {:?}", request.get_id(), request.get_message_type(), request.get_op_code());
    debug!("request: {:?}", request);

    let mut resp_edns_opt: Option<Edns> = None;

    // check if it's edns
    if let Some(req_edns) = request.get_edns() {
      let mut response = Message::new();
      response.id(request.get_id());

      let mut resp_edns: Edns = Edns::new();

      // check our version against the request
      // TODO: what version are we?
      let our_version = 0;
      resp_edns.set_dnssec_ok(true);
      resp_edns.set_max_payload( if req_edns.get_max_payload() < 512 { 512 } else { req_edns.get_max_payload() } );
      resp_edns.set_version(our_version);

      if req_edns.get_version() > our_version {
        warn!("request edns version greater than {}: {}", our_version, req_edns.get_version());
        response.response_code(ResponseCode::BADVERS);
        response.set_edns(resp_edns);
        return response
      }

      // TODO: inform of supported DNSSec protocols...
      // TODO: add padding for private key hashing, need better knowledge of the length of the
      //   response.
      // resp_edns.set_option()

      resp_edns_opt = Some(resp_edns);
    }

    let mut response: Message = match request.get_message_type() {
      // TODO think about threading query lookups for multiple lookups, this could be a huge improvement
      //  especially for recursive lookups
      MessageType::Query => {
        match request.get_op_code() {
          OpCode::Query => {
            let response = self.lookup(&request);
            debug!("query response: {:?}", response);
            response
            // TODO, handle recursion here or in the catalog?
            // recursive queries should be cached.
          },
          OpCode::Update => {
            let response = self.update(&request);
            debug!("update response: {:?}", response);
            response
          }
          c @ _ => {
            error!("unimplemented op_code: {:?}", c);
            Self::error_msg(request.get_id(), request.get_op_code(), ResponseCode::NotImp)
          },
        }
      },
      MessageType::Response => {
        warn!("got a response as a request from id: {}", request.get_id());
        Self::error_msg(request.get_id(), request.get_op_code(), ResponseCode::NotImp)
      },
    };

    if let Some(resp_edns) = resp_edns_opt {
      response.set_edns(resp_edns);

      // TODO: if DNSSec supported, sign the package with SIG0
      // get this servers private key ideally use pkcs11
      // sign response and then add SIG0 or TSIG to response
    }

    response
  }

  pub fn error_msg(id: u16, op_code: OpCode, response_code: ResponseCode) -> Message {
    let mut message: Message = Message::new();
    message.message_type(MessageType::Response);
    message.id(id);
    message.response_code(response_code);
    message.op_code(op_code);

    return message;
  }

  pub fn upsert(&mut self, name: Name, authority: Authority) {
    self.authorities.insert(name, RwLock::new(authority));
  }

  /*
   * RFC 2136                       DNS Update                     April 1997
   *
   * 3.1 - Process Zone Section
   *
   *   3.1.1. The Zone Section is checked to see that there is exactly one
   *   RR therein and that the RR's ZTYPE is SOA, else signal FORMERR to the
   *   requestor.  Next, the ZNAME and ZCLASS are checked to see if the zone
   *   so named is one of this server's authority zones, else signal NOTAUTH
   *   to the requestor.  If the server is a zone slave, the request will be
   *   forwarded toward the primary master.
   *
   *   3.1.2 - Pseudocode For Zone Section Processing
   *
   *      if (zcount != 1 || ztype != SOA)
   *           return (FORMERR)
   *      if (zone_type(zname, zclass) == SLAVE)
   *           return forward()
   *      if (zone_type(zname, zclass) == MASTER)
   *           return update()
   *      return (NOTAUTH)
   *
   *   Sections 3.2 through 3.8 describe the primary master's behaviour,
   *   whereas Section 6 describes a forwarder's behaviour.
   *
   * 3.8 - Response
   *
   *   At the end of UPDATE processing, a response code will be known.  A
   *   response message is generated by copying the ID and Opcode fields
   *   from the request, and either copying the ZOCOUNT, PRCOUNT, UPCOUNT,
   *   and ADCOUNT fields and associated sections, or placing zeros (0) in
   *   the these "count" fields and not including any part of the original
   *   update.  The QR bit is set to one (1), and the response is sent back
   *   to the requestor.  If the requestor used UDP, then the response will
   *   be sent to the requestor's source UDP port.  If the requestor used
   *   TCP, then the response will be sent back on the requestor's open TCP
   *   connection.
   */
  /// The "request" should be an update formatted message.
  ///  The response will be in the alternate, all 0's format described in RFC 2136 section 3.8
  ///  as this is more efficient.
  pub fn update(&self, request: &Message) -> Message {
    let mut response: Message = Message::new();
    response.id(request.get_id());
    response.op_code(OpCode::Update);
    response.message_type(MessageType::Response);

    let update: &UpdateMessage = request;

    let zones: &[Query] = update.get_zones();
    if zones.len() != 1 || zones[0].get_query_type() != RecordType::SOA {
      response.response_code(ResponseCode::FormErr);
      return response;
    }

    if let Some(authority) = self.find_auth_recurse(zones[0].get_name()) {
      let mut authority = authority.write().unwrap(); // poison errors should panic...
      match authority.get_zone_type() {
        ZoneType::Slave => {
          error!("slave forwarding for update not yet implemented");
          response.response_code(ResponseCode::NotImp);
          return response;
        },
        ZoneType::Master => {
          let update_result = authority.update(update);
          match update_result {
            // successful update
            Ok(..) => { response.response_code(ResponseCode::NoError); },
            Err(response_code) => { response.response_code(response_code); },
          }
          return response
        },
        _ => {
          response.response_code(ResponseCode::NotAuth);
          return response;
        }
      }
    } else {
      response.response_code(ResponseCode::NXDomain);
      response
    }
  }

  pub fn lookup(&self, request: &Message) -> Message {
    let mut response: Message = Message::new();
    response.id(request.get_id());
    response.op_code(OpCode::Query);
    response.message_type(MessageType::Response);

    // TODO: the spec is very unclear on what to do with multiple queries
    //  we will search for each, in the future, maybe make this threaded to respond even faster.
    for query in request.get_queries() {
      if let Some((authority, records)) = self.search(query) {
        let authority = authority.read().unwrap(); // poison errors should panic
        if records.is_some() {
          response.response_code(ResponseCode::NoError);
          response.authoritative(true);
          response.add_all_answers(&records.unwrap());

          // get the NS records
          let ns = authority.get_ns();
          if ns.is_none() { warn!("there are no NS records for: {:?}", authority.get_origin()); }
          else {
            response.add_all_name_servers(&ns.unwrap());
          }
        } else {
          // in the not found case it's standard to return the SOA in the authority section
          response.response_code(ResponseCode::NXDomain);

          let soa = authority.get_soa();
          if soa.is_none() { warn!("there is no SOA record for: {:?}", authority.get_origin()); }
          else {
            response.add_name_server(soa.unwrap());
          }
        }
      } else {
        // we found nothing.
        response.response_code(ResponseCode::NXDomain);
      }
    }

    // TODO a lot of things do a recursive query for non-A or AAAA records, and return those in
    //  additional
    response
  }

  pub fn search(&self, query: &Query) -> Option<(&RwLock<Authority>, Option<Vec<Record>>)> {
    if let Some(ref_authority) = self.find_auth_recurse(query.get_name()) {
      let authority = ref_authority.read().unwrap(); // poison errors should panic
      debug!("found authority: {:?}", authority.get_origin());

      let record_type: RecordType = query.get_query_type();

      // if this is an AXFR zone transfer, verify that this is either the slave or master
      //  for AXFR the first and last record must be the SOA
      if RecordType::AXFR == record_type {
        match authority.get_zone_type() {
          ZoneType::Master | ZoneType::Slave => (),
          // TODO Forward?
          _ => return None, // TODO this sould be an error.
        }
      }

      // it would be better to stream this back, rather than packaging everything up in an array
      //  though for UDP it would still need to be bundled
      let mut query_result: Option<Vec<_>> = authority.lookup(query.get_name(), record_type, query.get_query_class());

      if RecordType::AXFR == record_type {
        if let Some(soa) = authority.get_soa() {
          let mut xfr: Vec<Record> = query_result.unwrap_or(Vec::with_capacity(2));
          // TODO: probably make Records Rc or Arc, to remove the clone
          xfr.insert(0, soa.clone());
          xfr.push(soa);

          query_result = Some(xfr);
        } else {
          return None; // TODO is this an error?
        }
      }

      Some((&ref_authority, query_result))
    } else {
      None
    }
  }

  fn find_auth_recurse(&self, name: &Name) -> Option<&RwLock<Authority>> {
    let authority = self.authorities.get(name);
    if authority.is_some() { return authority; }
    else {
      let name = name.base_name();
      if !name.is_root() {
        return self.find_auth_recurse(&name);
      }
    }

    None
  }
}

#[cfg(test)]
mod catalog_tests {
  use std::collections::*;
  use ::authority::{Authority, ZoneType};
  use ::authority::authority_tests::create_example;
  use super::*;
  use ::rr::*;
  use ::op::*;
  use std::net::*;

  #[test]
  fn test_catalog_search() {
    let example = create_example();
    let origin = example.get_origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin.clone(), example);

    let mut query: Query = Query::new();
    query.name(origin.clone());

    if let Some((_, result)) = catalog.search(&query) {
      assert!(result.is_some());
      assert_eq!(result.as_ref().unwrap().first().unwrap().get_rr_type(), RecordType::A);
      assert_eq!(result.as_ref().unwrap().first().unwrap().get_dns_class(), DNSClass::IN);
      assert_eq!(result.as_ref().unwrap().first().unwrap().get_rdata(), &RData::A{ address: Ipv4Addr::new(93,184,216,34) });
    } else {
      panic!("expected a result");
    }
  }

  /// this is a litte more interesting b/c it requires a recursive lookup for the origin
  #[test]
  fn test_catalog_search_www() {
    let example = create_example();
    let www_name = Name::parse("www.example.com.", None).unwrap();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(example.get_origin().clone(), example);

    let mut query: Query = Query::new();
    query.name(www_name.clone());

    if let Some((_, result)) = catalog.search(&query) {
      assert!(result.is_some());
      assert_eq!(result.as_ref().unwrap().first().unwrap().get_rr_type(), RecordType::A);
      assert_eq!(result.as_ref().unwrap().first().unwrap().get_dns_class(), DNSClass::IN);
      assert_eq!(result.as_ref().unwrap().first().unwrap().get_rdata(), &RData::A{ address: Ipv4Addr::new(93,184,216,34) });
    } else {
      panic!("expected a result");
    }
  }

  pub fn create_test() -> Authority {
    let origin: Name = Name::parse("test.com.", None).unwrap();
    let mut records: Authority = Authority::new(origin.clone(), HashMap::new(), ZoneType::Master, false);
    records.upsert(origin.clone(), Record::new().name(origin.clone()).ttl(3600).rr_type(RecordType::SOA).dns_class(DNSClass::IN).rdata(RData::SOA{ mname: Name::parse("sns.dns.icann.org.", None).unwrap(), rname: Name::parse("noc.dns.icann.org.", None).unwrap(), serial: 2015082403, refresh: 7200, retry: 3600, expire: 1209600, minimum: 3600 }).clone());

    records.upsert(origin.clone(), Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS{ nsdname: Name::parse("a.iana-servers.net.", None).unwrap() }).clone());
    records.upsert(origin.clone(), Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS{ nsdname: Name::parse("b.iana-servers.net.", None).unwrap() }).clone());

    records.upsert(origin.clone(), Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::A{ address: Ipv4Addr::new(94,184,216,34) }).clone());
    records.upsert(origin.clone(), Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::AAAA).dns_class(DNSClass::IN).rdata(RData::AAAA{ address: Ipv6Addr::new(0x2606,0x2800,0x220,0x1,0x248,0x1893,0x25c8,0x1946) }).clone());

    let www_name: Name = Name::parse("www.test.com.", None).unwrap();
    records.upsert(origin.clone(), Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::A{ address: Ipv4Addr::new(94,184,216,34) }).clone());
    records.upsert(origin.clone(), Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::AAAA).dns_class(DNSClass::IN).rdata(RData::AAAA{ address: Ipv6Addr::new(0x2606,0x2800,0x220,0x1,0x248,0x1893,0x25c8,0x1946) }).clone());

    records
  }

  #[test]
  fn test_catalog_lookup() {
    let example = create_example();
    let test = create_test();
    let origin = example.get_origin().clone();
    let test_origin = test.get_origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin.clone(), example);
    catalog.upsert(test_origin.clone(), test);

    let mut question: Message = Message::new();

    let mut query: Query = Query::new();
    query.name(origin.clone());

    question.add_query(query);

    let result: Message = catalog.lookup(&question);

    assert_eq!(result.get_response_code(), ResponseCode::NoError);
    assert_eq!(result.get_message_type(), MessageType::Response);

    let answers: &[Record] = result.get_answers();

    assert!(!answers.is_empty());
    assert_eq!(answers.first().unwrap().get_rr_type(), RecordType::A);
    assert_eq!(answers.first().unwrap().get_rdata(), &RData::A{ address: Ipv4Addr::new(93,184,216,34) });

    let mut ns: Vec<Record> = result.get_name_servers().to_vec();
    ns.sort();

    assert_eq!(ns.len(), 2);
    assert_eq!(ns.first().unwrap().get_rr_type(), RecordType::NS);
    assert_eq!(ns.first().unwrap().get_rdata(), &RData::NS{ nsdname: Name::parse("a.iana-servers.net.", None).unwrap() });
    assert_eq!(ns.last().unwrap().get_rr_type(), RecordType::NS);
    assert_eq!(ns.last().unwrap().get_rdata(), &RData::NS{ nsdname: Name::parse("b.iana-servers.net.", None).unwrap() });

    // other zone
    let mut query: Query = Query::new();
    query.name(test_origin.clone());

    question.add_query(query);

    let result: Message = catalog.lookup(&question);

    assert_eq!(result.get_response_code(), ResponseCode::NoError);
    assert_eq!(result.get_message_type(), MessageType::Response);

    let answers: &[Record] = result.get_answers();

    assert!(!answers.is_empty());
    assert_eq!(answers.first().unwrap().get_rr_type(), RecordType::A);
    assert_eq!(answers.first().unwrap().get_rdata(), &RData::A{ address: Ipv4Addr::new(93,184,216,34) });
  }

  #[test]
  fn test_catalog_nx_soa() {
    let example = create_example();
    let origin = example.get_origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin.clone(), example);

    let mut question: Message = Message::new();

    let mut query: Query = Query::new();
    query.name(Name::parse("nx.example.com.", None).unwrap());

    question.add_query(query);

    let result: Message = catalog.lookup(&question);

    assert_eq!(result.get_response_code(), ResponseCode::NXDomain);
    assert_eq!(result.get_message_type(), MessageType::Response);

    let ns: &[Record] = result.get_name_servers();

    assert_eq!(ns.len(), 1);
    assert_eq!(ns.first().unwrap().get_rr_type(), RecordType::SOA);
    assert_eq!(ns.first().unwrap().get_rdata(), &RData::SOA{ mname: Name::parse("sns.dns.icann.org.", None).unwrap(), rname: Name::parse("noc.dns.icann.org.", None).unwrap(), serial: 2015082403, refresh: 7200, retry: 3600, expire: 1209600, minimum: 3600 });
  }

  #[test]
  fn test_axfr() {
    let test = create_test();
    let origin = test.get_origin().clone();
    let soa = Record::new().name(origin.clone()).ttl(3600).rr_type(RecordType::SOA).dns_class(DNSClass::IN).rdata(RData::SOA{ mname: Name::parse("sns.dns.icann.org.", None).unwrap(), rname: Name::parse("noc.dns.icann.org.", None).unwrap(), serial: 2015082403, refresh: 7200, retry: 3600, expire: 1209600, minimum: 3600 }).clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin.clone(), test);

    let mut query: Query = Query::new();
    query.name(origin.clone());
    query.query_type(RecordType::AXFR);

    let mut question: Message = Message::new();
    question.add_query(query);

    let result: Message = catalog.lookup(&question);
    let mut answers: Vec<Record> = result.get_answers().to_vec();

    assert_eq!(answers.first().unwrap(), &soa);
    assert_eq!(answers.last().unwrap(), &soa);

    answers.sort();

    let www_name: Name = Name::parse("www.test.com.", None).unwrap();
    let mut expected_set = vec![
      Record::new().name(origin.clone()).ttl(3600).rr_type(RecordType::SOA).dns_class(DNSClass::IN).rdata(RData::SOA{ mname: Name::parse("sns.dns.icann.org.", None).unwrap(), rname: Name::parse("noc.dns.icann.org.", None).unwrap(), serial: 2015082403, refresh: 7200, retry: 3600, expire: 1209600, minimum: 3600 }).clone(),
      Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS{ nsdname: Name::parse("a.iana-servers.net.", None).unwrap() }).clone(),
      Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS{ nsdname: Name::parse("b.iana-servers.net.", None).unwrap() }).clone(),
      Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::A{ address: Ipv4Addr::new(94,184,216,34) }).clone(),
      Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::AAAA).dns_class(DNSClass::IN).rdata(RData::AAAA{ address: Ipv6Addr::new(0x2606,0x2800,0x220,0x1,0x248,0x1893,0x25c8,0x1946) }).clone(),
      Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::A{ address: Ipv4Addr::new(94,184,216,34) }).clone(),
      Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::AAAA).dns_class(DNSClass::IN).rdata(RData::AAAA{ address: Ipv6Addr::new(0x2606,0x2800,0x220,0x1,0x248,0x1893,0x25c8,0x1946) }).clone(),
      Record::new().name(origin.clone()).ttl(3600).rr_type(RecordType::SOA).dns_class(DNSClass::IN).rdata(RData::SOA{ mname: Name::parse("sns.dns.icann.org.", None).unwrap(), rname: Name::parse("noc.dns.icann.org.", None).unwrap(), serial: 2015082403, refresh: 7200, retry: 3600, expire: 1209600, minimum: 3600 }).clone(),
    ];

    expected_set.sort();

    assert_eq!(expected_set, answers);
  }
}
