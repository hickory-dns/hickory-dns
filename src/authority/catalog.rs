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

use ::rr::Record;
use ::rr::Name;
use ::authority::Authority;
use ::op::*;

pub struct Catalog {
  authorities: HashMap<Name, Authority>,
}

impl Catalog {
  pub fn new() -> Self {
    Catalog{ authorities: HashMap::new() }
  }

  pub fn upsert(&mut self, name: Name, authority: Authority) {
    self.authorities.insert(name, authority);
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
          // in the nx section it's standard to return the SOA in the authority section
          response.response_code(ResponseCode::NXDomain);

          println!("getting SOA");

          let soa = authority.get_soa();
          if soa.is_none() { warn!("there is no SOA record for: {:?}", authority.get_origin()); }
          else {
            response.add_name_server(soa.unwrap());
          }
        }
      } else {
        // we found nothing.
        println!("found nothing");
        response.response_code(ResponseCode::NXDomain);
      }
    }

    // TODO a lot of things do a recursive query for non-A or AAAA records, and return those in
    //  additional
    response
  }

  pub fn search(&self, query: &Query) -> Option<(&Authority, Option<Vec<Record>>)> {
    if let Some(authority) = self.find_auth_recurse(query.get_name()) {
      println!("found authority");
      Some((authority, authority.lookup(query.get_name(), query.get_query_type(), query.get_query_class())))
    } else {
      None
    }
  }

  fn find_auth_recurse(&self, name: &Name) -> Option<&Authority> {
    println!("searching for {:?}", name);
    let authority = self.authorities.get(name);
    if authority.is_some() { return authority; }
    else if let Some(name) = name.base_name() {
      return self.find_auth_recurse(&name);
    }

    None
  }
}

#[cfg(test)]
mod catalog_tests {
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

  #[test]
  fn test_catalog_lookup() {
    let example = create_example();
    let origin = example.get_origin().clone();

    let mut catalog: Catalog = Catalog::new();
    catalog.upsert(origin.clone(), example);

    let mut question: Message = Message::new();

    let mut query: Query = Query::new();
    query.name(origin.clone());

    question.add_query(query);

    let result: Message = catalog.lookup(&question);

    assert_eq!(result.get_response_code(), ResponseCode::NoError);
    assert_eq!(result.get_message_type(), MessageType::Response);

    let answers: &Vec<Record> = result.get_answers();

    assert!(!answers.is_empty());
    assert_eq!(answers.first().unwrap().get_rr_type(), RecordType::A);
    assert_eq!(answers.first().unwrap().get_rdata(), &RData::A{ address: Ipv4Addr::new(93,184,216,34) });

    let ns: &Vec<Record> = result.get_name_servers();

    assert_eq!(ns.len(), 2);
    assert_eq!(ns.first().unwrap().get_rr_type(), RecordType::NS);
    assert_eq!(ns.first().unwrap().get_rdata(), &RData::NS{ nsdname: Name::parse("a.iana-servers.net.", None).unwrap() });
    assert_eq!(ns.last().unwrap().get_rr_type(), RecordType::NS);
    assert_eq!(ns.last().unwrap().get_rdata(), &RData::NS{ nsdname: Name::parse("b.iana-servers.net.", None).unwrap() });
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

    let ns: &Vec<Record> = result.get_name_servers();

    assert_eq!(ns.len(), 1);
    assert_eq!(ns.first().unwrap().get_rr_type(), RecordType::SOA);
    assert_eq!(ns.first().unwrap().get_rdata(), &RData::SOA{ mname: Name::parse("sns.dns.icann.org.", None).unwrap(), rname: Name::parse("noc.dns.icann.org.", None).unwrap(), serial: 2015082403, refresh: 7200, retry: 3600, expire: 1209600, minimum: 3600 });
  }
}
