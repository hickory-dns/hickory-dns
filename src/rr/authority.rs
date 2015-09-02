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

use ::rr::{RecordType, Record, Name};

/// Authority is the storage method for all
///
pub struct Authority {
  origin: Name,
  records: HashMap<(Name, RecordType), Vec<Record>>,
}

impl Authority {
  pub fn new(origin: Name, records: HashMap<(Name, RecordType), Vec<Record>>) -> Authority {
    Authority{ origin: origin, records: records }
  }

  pub fn get_soa(&self) -> Option<&Record> {
    // SOA should be origin|SOA
    self.lookup(&self.origin, RecordType::SOA).and_then(|v|v.first())
  }

  pub fn lookup(&self, name: &Name, rtype: RecordType) -> Option<&Vec<Record>> {
    // TODO this should be an unnecessary copy... need to create a key type, and then use that for
    //  all queries
    //self.records.get(&(self.origin.clone(), RecordType::SOA)).map(|v|v.first())
    self.records.get(&(name.clone(), rtype))
  }
}
