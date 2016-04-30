/*
 * Copyright (C) 2015-2016 Benjamin Fry <benjaminfry@me.com>
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
use ::rr::{Name, Record, RecordType, RData};

#[derive(Debug)]
pub struct RRSet {
  name: Name,
  record_type: RecordType,
  records: Vec<Record>,
  rrsig: Option<Record>,
}

impl RRSet {
  pub fn new(name: &Name, record_type: RecordType) -> RRSet {
    RRSet{name: name.clone(), record_type: record_type, records: Vec::new(), rrsig: None}
  }

  pub fn get_name(&self) -> &Name {
    &self.name
  }

  pub fn get_record_type(&self) -> RecordType {
    self.record_type
  }

  pub fn get_records(&self) -> &[Record] {
    &self.records
  }

  pub fn is_empty(&self) -> bool {
    self.records.is_empty()
  }

  pub fn insert(&mut self, record: Record) -> bool {
    assert_eq!(record.get_name(), &self.name);
    assert_eq!(record.get_rr_type(), self.record_type);

    // RFC 2136                       DNS Update                     April 1997
    //
    // 1.1.5. The following RR types cannot be appended to an RRset.  If the
    //  following comparison rules are met, then an attempt to add the new RR
    //  will result in the replacement of the previous RR:
    //
    // SOA    compare only NAME, CLASS and TYPE -- it is not possible to
    //         have more than one SOA per zone, even if any of the data
    //         fields differ.
    //
    // CNAME  compare only NAME, CLASS, and TYPE -- it is not possible
    //         to have more than one CNAME RR, even if their data fields
    //         differ.
    match record.get_rr_type() {
      RecordType::SOA => {
        assert!(self.records.len() <= 1);

        if let Some(soa_record) = self.records.iter().next() {
          match soa_record.get_rdata() {
            &RData::SOA{ serial: existing_serial, .. } => {
              if let &RData::SOA{ serial: new_serial, ..} = record.get_rdata() {
                if new_serial <= existing_serial {
                  info!("update ignored serial out of data: {} <= {}", new_serial, existing_serial);
                  return false;
                }
              } else {
                // not panicking here, b/c this is a bad record from the client or something, ingnore
                info!("wrong rdata for SOA update: {:?}", record.get_rdata());
                return false;
              }
            },
            rdata @ _ => panic!("wrong rdata: {:?}", rdata),
          }
        }

        // if we got here, we're updating...
        self.records.clear();
      },
      RecordType::CNAME => {
        assert!(self.records.len() <= 1);
        self.records.clear();
      },
      _ => (),
    }

    // collect any records to update based on rdata
    let to_replace: Vec<usize> = self.records.iter().enumerate()
                                            .filter(|&(_, rr)| rr.get_rdata() == record.get_rdata())
                                            .map(|(i, _)| i)
                                            .collect::<Vec<usize>>();

    // if the Records are identical, ignore the update, update all that are not (ttl, etc.)
    let mut replaced = false;
    for i in to_replace {
      if self.records[i] == record {
        return false;
      }

      // TODO: this shouldn't really need a clone since there should only be one...
      self.records.push(record.clone());
      self.records.swap_remove(i);
      replaced = true;
    }

    if !replaced {
      self.records.push(record);
      true
    } else {
      replaced
    }
  }

  pub fn remove(&mut self, record: &Record) -> bool {
    assert_eq!(record.get_name(), &self.name);
    assert!(record.get_rr_type() == self.record_type || record.get_rr_type() == RecordType::ANY);

    match record.get_rr_type() {
      // never delete the last NS record
      RecordType::NS => {
        if self.records.len() <= 1 {
          info!("ignoring delete of last NS record: {:?}", record);
          return false;
        }
      },
      // never delete SOA
      RecordType::SOA => {
        info!("ignored delete of SOA");
        return false;
      },
      _ => (), // move on to the delete
    }

    // remove the records, first collect all the indexes, then remove the records
    let to_remove: Vec<usize> = self.records.iter().enumerate()
                                            .filter(|&(_, rr)| rr.get_rdata() == record.get_rdata())
                                            .map(|(i, _)| i)
                                            .collect::<Vec<usize>>();

    let mut removed = false;
    for i in to_remove {
      self.records.remove(i);
      removed = true;
    }

    removed
  }
}

#[cfg(test)]
mod test {
  use std::net::Ipv4Addr;
  use ::rr::*;
  use super::RRSet;

  #[test]
  fn test_insert() {
    let name = Name::new().label("www").label("example").label("com");
    let record_type = RecordType::A;
    let mut rr_set = RRSet::new(&name, record_type);

    let insert = Record::new().name(name.clone()).ttl(86400).rr_type(record_type).dns_class(DNSClass::IN).rdata(RData::A{ address: Ipv4Addr::new(93,184,216,24) }).clone();

    assert!(rr_set.insert(insert.clone()));
    assert_eq!(rr_set.get_records().len(), 1);
    assert!(rr_set.get_records().contains(&insert));

    // dups ignored
    assert!(!rr_set.insert(insert.clone()));
    assert_eq!(rr_set.get_records().len(), 1);
    assert!(rr_set.get_records().contains(&insert));

    // add one
    let insert1 = Record::new().name(name.clone()).ttl(86400).rr_type(record_type).dns_class(DNSClass::IN).rdata(RData::A{ address: Ipv4Addr::new(93,184,216,25) }).clone();
    assert!(rr_set.insert(insert1.clone()));
    assert_eq!(rr_set.get_records().len(), 2);
    assert!(rr_set.get_records().contains(&insert));
    assert!(rr_set.get_records().contains(&insert1));
  }

  #[test]
  fn test_insert_soa() {
    let name = Name::new().label("example").label("com");
    let record_type = RecordType::SOA;
    let mut rr_set = RRSet::new(&name, record_type);

    let insert = Record::new().name(name.clone()).ttl(3600).rr_type(RecordType::SOA).dns_class(DNSClass::IN).rdata(RData::SOA{ mname: Name::parse("sns.dns.icann.org.", None).unwrap(), rname: Name::parse("noc.dns.icann.org.", None).unwrap(), serial: 2015082403, refresh: 7200, retry: 3600, expire: 1209600, minimum: 3600 }).clone();
    let same_serial = Record::new().name(name.clone()).ttl(3600).rr_type(RecordType::SOA).dns_class(DNSClass::IN).rdata(RData::SOA{ mname: Name::parse("sns.dns.icann.net.", None).unwrap(), rname: Name::parse("noc.dns.icann.net.", None).unwrap(), serial: 2015082403, refresh: 7200, retry: 3600, expire: 1209600, minimum: 3600 }).clone();
    let new_serial = Record::new().name(name.clone()).ttl(3600).rr_type(RecordType::SOA).dns_class(DNSClass::IN).rdata(RData::SOA{ mname: Name::parse("sns.dns.icann.net.", None).unwrap(), rname: Name::parse("noc.dns.icann.net.", None).unwrap(), serial: 2015082404, refresh: 7200, retry: 3600, expire: 1209600, minimum: 3600 }).clone();

    assert!(rr_set.insert(insert.clone()));
    assert!(rr_set.get_records().contains(&insert));
    // same serial number
    assert!(!rr_set.insert(same_serial.clone()));
    assert!(rr_set.get_records().contains(&insert));
    assert!(!rr_set.get_records().contains(&same_serial));

    assert!(rr_set.insert(new_serial.clone()));
    assert!(!rr_set.insert(same_serial.clone()));
    assert!(!rr_set.insert(insert.clone()));

    assert!(rr_set.get_records().contains(&new_serial));
    assert!(!rr_set.get_records().contains(&insert));
    assert!(!rr_set.get_records().contains(&same_serial));
  }

  #[test]
  fn test_insert_cname() {
    let name = Name::new().label("web").label("example").label("com");
    let cname = Name::new().label("www").label("example").label("com");
    let new_cname = Name::new().label("w2").label("example").label("com");

    let record_type = RecordType::CNAME;
    let mut rr_set = RRSet::new(&name, record_type);

    let insert = Record::new().name(name.clone()).ttl(3600).rr_type(RecordType::CNAME).dns_class(DNSClass::IN).rdata(RData::CNAME{ cname: cname.clone() }).clone();
    let new_record = Record::new().name(name.clone()).ttl(3600).rr_type(RecordType::CNAME).dns_class(DNSClass::IN).rdata(RData::CNAME{ cname: new_cname.clone() }).clone();

    assert!(rr_set.insert(insert.clone()));
    assert!(rr_set.get_records().contains(&insert));

    // update the record
    assert!(rr_set.insert(new_record.clone()));
    assert!(!rr_set.get_records().contains(&insert));
    assert!(rr_set.get_records().contains(&new_record));
  }

  #[test]
  fn test_remove() {
    let name = Name::new().label("www").label("example").label("com");
    let record_type = RecordType::A;
    let mut rr_set = RRSet::new(&name, record_type);

    let insert = Record::new().name(name.clone()).ttl(86400).rr_type(record_type).dns_class(DNSClass::IN).rdata(RData::A{ address: Ipv4Addr::new(93,184,216,24) }).clone();
    let insert1 = Record::new().name(name.clone()).ttl(86400).rr_type(record_type).dns_class(DNSClass::IN).rdata(RData::A{ address: Ipv4Addr::new(93,184,216,25) }).clone();

    assert!(rr_set.insert(insert.clone()));
    assert!(rr_set.insert(insert1.clone()));

    assert!(rr_set.remove(&insert));
    assert!(!rr_set.remove(&insert));
    assert!(rr_set.remove(&insert1));
    assert!(!rr_set.remove(&insert1));
  }

  #[test]
  fn test_remove_soa() {
    let name = Name::new().label("example").label("com");
    let record_type = RecordType::SOA;
    let mut rr_set = RRSet::new(&name, record_type);

    let insert = Record::new().name(name.clone()).ttl(3600).rr_type(RecordType::SOA).dns_class(DNSClass::IN).rdata(RData::SOA{ mname: Name::parse("sns.dns.icann.org.", None).unwrap(), rname: Name::parse("noc.dns.icann.org.", None).unwrap(), serial: 2015082403, refresh: 7200, retry: 3600, expire: 1209600, minimum: 3600 }).clone();

    assert!(rr_set.insert(insert.clone()));
    assert!(!rr_set.remove(&insert));
    assert!(rr_set.get_records().contains(&insert));
  }

  #[test]
  fn test_remove_ns() {
    let name = Name::new().label("example").label("com");
    let record_type = RecordType::NS;
    let mut rr_set = RRSet::new(&name, record_type);

    let ns1 = Record::new().name(name.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS{ nsdname: Name::parse("a.iana-servers.net.", None).unwrap() }).clone();
    let ns2 = Record::new().name(name.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS{ nsdname: Name::parse("b.iana-servers.net.", None).unwrap() }).clone();

    assert!(rr_set.insert(ns1.clone()));
    assert!(rr_set.insert(ns2.clone()));

    // ok to remove one, but not two...
    assert!(rr_set.remove(&ns1));
    assert!(!rr_set.remove(&ns2));

    // check that we can swap which ones are removed
    assert!(rr_set.insert(ns1.clone()));

    assert!(rr_set.remove(&ns2));
    assert!(!rr_set.remove(&ns1));
  }
}
