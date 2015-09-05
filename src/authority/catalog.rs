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

  pub fn lookup(&self, request: &Message) -> Message {
    let mut response: Message = Message::new();
    response.id(request.get_id());
    response.op_code(OpCode::Query);
    response.message_type(MessageType::Response);

    // TODO: the spec is very unclear on what to do with multiple queries
    //  we will search for each, in the future, maybe make this threaded to respond even faster.
    for query in request.get_queries() {
      let record = self.search(query);
      if record.is_some() {
        response.add_all_answers(&record.unwrap());
      }
    }

    if !response.get_answers().is_empty() {
      response.response_code(ResponseCode::NoError);
      response.authoritative(true);
    } else {
      response.response_code(ResponseCode::NXDomain);
    }

    response
  }

  pub fn search(&self, query: &Query) -> Option<Vec<Record>> {
    if let Some(authority) = self.find_auth_recurse(query.get_name()) {
      authority.lookup(query.get_name(), query.get_query_type(), query.get_query_class())
    } else {
      None
    }
  }

  fn find_auth_recurse(&self, name: &Name) -> Option<&Authority> {
    let authority = self.authorities.get(name);
    if authority.is_some() { return authority; }
    else if let Some(name) = name.base_name() {
      return self.find_auth_recurse(&name);
    }

    None
  }
}
