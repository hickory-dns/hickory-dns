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
use std::collections::HashMap;

use ::rr::*;

/// Authority is the storage method for all
///
pub struct Authority {
  origin: Name,
  records: HashMap<(Name, RecordType), Vec<Record>>,
  // this controls if this server responds to queries with authoritative answers for the autority
  owned_by_me: bool,
}

impl Authority {
  pub fn new(origin: Name, records: HashMap<(Name, RecordType), Vec<Record>>) -> Authority {
    Authority{ origin: origin, records: records, owned_by_me: false }
  }

  pub fn get_soa(&self) -> Option<Record> {
    // SOA should be origin|SOA
    self.lookup(&self.origin, RecordType::SOA, DNSClass::IN).and_then(|v|v.first().cloned())
  }

  pub fn lookup(&self, name: &Name, rtype: RecordType, class: DNSClass) -> Option<Vec<Record>> {
    // TODO this should be an unnecessary clone... need to create a key type, and then use that for
    //  all queries
    //self.records.get(&(self.origin.clone(), RecordType::SOA)).map(|v|v.first())
    // TODO: lots of clones here... need to clean this up to work with refs... probably will affect
    //  things like Message which will need two variants for owned vs. shared memory.
    self.records.get(&(name.clone(), rtype)).map(|v|v.clone().iter().filter(|r|r.get_dns_class() == class).cloned().collect())
  }
}
