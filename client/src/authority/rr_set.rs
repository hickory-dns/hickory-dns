// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use  std::slice::Iter;

use ::rr::{Name, Record, RecordType, RData};

/// Set of resource records associated to a name and type
#[derive(Debug, PartialEq)]
pub struct RRSet {
  name: Name,
  record_type: RecordType,
  ttl: u32,
  records: Vec<Record>,
  rrsigs: Vec<Record>,
  serial: u32, // serial number at which this record was modified
}

impl RRSet {
  /// Creates a new Resource Record Set.
  ///
  /// # Arguments
  ///
  /// * `name` - The label for the `RRSet`
  /// * `record_type` - `RecordType` of this `RRSet`, all records in the `RRSet` must be of the
  ///                   specified `RecordType`.
  /// * `serial` - current serial number of the `SOA` record, this is to be used for `IXFR` and
  ///              signing for DNSSec after updates.
  ///
  /// # Return value
  ///
  /// The newly created Resource Record Set
  pub fn new(name: &Name, record_type: RecordType, serial: u32) -> RRSet {
    RRSet{name: name.clone(), record_type: record_type, ttl: 0, records: Vec::new(), rrsigs: Vec::new(), serial: serial}
  }

  /// # Return value
  ///
  /// Label of the Resource Record Set
  pub fn get_name(&self) -> &Name {
    &self.name
  }

  /// # Return value
  ///
  /// `RecordType` of the Resource Record Set
  pub fn get_record_type(&self) -> RecordType {
    self.record_type
  }

  /// # Return value
  ///
  /// TTL, time-to-live, of the Resource Record Set, this is the maximum length of time that an
  /// RRSet should be cached.
  pub fn get_ttl(&self) -> u32 {
    self.ttl
  }

  /// # Return value
  ///
  /// Slice of all records in the set
  pub fn get_records(&self, and_rrsigs: bool) -> Vec<&Record> {
    if and_rrsigs {
      self.records.iter().chain(self.rrsigs.iter()).collect()
    } else {
      self.records.iter().collect()
    }
  }

  /// Returns an iterator over the records in the set
  pub fn iter<'s>(&'s self) -> Iter<'s, Record> {
    self.records.iter()
  }

  /// # Return value
  ///
  /// True if there are no records in this set
  pub fn is_empty(&self) -> bool {
    self.records.is_empty()
  }

  /// # Return value
  ///
  /// The serial number at which the record was updated.
  pub fn get_serial(&self) -> u32 {
    self.serial
  }

  pub fn get_rrsigs(&self) -> &[Record] {
    &self.rrsigs
  }

  pub fn insert_rrsig(&mut self, rrsig: Record) {
    self.rrsigs.push(rrsig)
  }

  pub fn clear_rrsigs(&mut self) {
    self.rrsigs.clear()
  }

  fn updated(&mut self, serial: u32) {
    self.serial = serial;
    self.rrsigs.clear(); // on updates, the rrsigs are invalid
  }

  /// Inserts a new Resource Record into the Set.
  ///
  /// If the record is inserted, the ttl for the most recent record will be used for the ttl of
  /// the entire resource record set.
  ///
  /// This abides by the following restrictions in RFC 2136, April 1997:
  ///
  /// ```text
  /// 1.1.5. The following RR types cannot be appended to an RRset.  If the
  ///  following comparison rules are met, then an attempt to add the new RR
  ///  will result in the replacement of the previous RR:
  ///
  /// SOA    compare only NAME, CLASS and TYPE -- it is not possible to
  ///         have more than one SOA per zone, even if any of the data
  ///         fields differ.
  ///
  /// CNAME  compare only NAME, CLASS, and TYPE -- it is not possible
  ///         to have more than one CNAME RR, even if their data fields
  ///         differ.
  /// ```
  ///
  /// # Arguments
  ///
  /// * `record` - `Record` asserts that the `name` and `record_type` match the `RRSet`.
  /// * `serial` - current serial number of the `SOA` record, this is to be used for `IXFR` and
  ///              signing for DNSSec after updates. The serial will only be updated if the
  ///              record was added.
  ///
  /// # Return value
  ///
  /// True if the record was inserted.
  pub fn insert(&mut self, record: Record, serial: u32) -> bool {
    assert_eq!(record.get_name(), &self.name);
    assert_eq!(record.get_rr_type(), self.record_type);

    // RFC 2136                       DNS Update                     April 1997
    //
    // 1.1.5. The following RR types cannot be appended to an RRset.  If the
    //  following comparison rules are met, then an attempt to add the new RR
    //  will result in the replacement of the previous RR:
    match record.get_rr_type() {
      // SOA    compare only NAME, CLASS and TYPE -- it is not possible to
      //         have more than one SOA per zone, even if any of the data
      //         fields differ.
      RecordType::SOA => {
        assert!(self.records.len() <= 1);

        if let Some(soa_record) = self.records.iter().next() {
          match soa_record.get_rdata() {
            &RData::SOA(ref existing_soa) => {
              if let &RData::SOA(ref new_soa) = record.get_rdata() {
                if new_soa.get_serial() <= existing_soa.get_serial() {
                  info!("update ignored serial out of data: {:?} <= {:?}", new_soa, existing_soa);
                  return false;
                }
              } else {
                // not panicking here, b/c this is a bad record from the client or something, ingnore
                info!("wrong rdata for SOA update: {:?}", record.get_rdata());
                return false;
              }
            },
            rdata @ _ => panic!("wrong rdata: {:?}", rdata), // valid panic, never should happen
          }
        }

        // if we got here, we're updating...
        self.records.clear();
      },
      // CNAME  compare only NAME, CLASS, and TYPE -- it is not possible
      //         to have more than one CNAME RR, even if their data fields
      //         differ.
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
      self.ttl = record.get_ttl();
      self.updated(serial);
      replaced = true;
    }

    if !replaced {
      self.ttl = record.get_ttl();
      self.updated(serial);
      self.records.push(record);
      true
    } else {
      replaced
    }
  }

  /// Removes the Resource Record if it exists.
  ///
  /// # Arguments
  ///
  /// * `record` - `Record` asserts that the `name` and `record_type` match the `RRSet`. Removes
  ///              any `record` if the record data, `RData`, match.
  /// * `serial` - current serial number of the `SOA` record, this is to be used for `IXFR` and
  ///              signing for DNSSec after updates. The serial will only be updated if the
  ///              record was added.
  ///
  /// # Return value
  ///
  /// True if a record was removed.
  pub fn remove(&mut self, record: &Record, serial: u32) -> bool {
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
      self.updated(serial);
    }

    removed
  }
}

#[cfg(test)]
mod test {
  use std::net::Ipv4Addr;
  use ::rr::*;
  use ::rr::rdata::SOA;
  use super::RRSet;

  #[test]
  fn test_insert() {
    let name = Name::new().label("www").label("example").label("com");
    let record_type = RecordType::A;
    let mut rr_set = RRSet::new(&name, record_type, 0);

    let insert = Record::new().name(name.clone()).ttl(86400).rr_type(record_type).dns_class(DNSClass::IN).rdata(RData::A(Ipv4Addr::new(93,184,216,24))).clone();

    assert!(rr_set.insert(insert.clone(), 0));
    assert_eq!(rr_set.get_records(false).len(), 1);
    assert!(rr_set.get_records(false).contains(&&insert));

    // dups ignored
    assert!(!rr_set.insert(insert.clone(), 0));
    assert_eq!(rr_set.get_records(false).len(), 1);
    assert!(rr_set.get_records(false).contains(&&insert));

    // add one
    let insert1 = Record::new().name(name.clone()).ttl(86400).rr_type(record_type).dns_class(DNSClass::IN).rdata(RData::A(Ipv4Addr::new(93,184,216,25))).clone();
    assert!(rr_set.insert(insert1.clone(), 0));
    assert_eq!(rr_set.get_records(false).len(), 2);
    assert!(rr_set.get_records(false).contains(&&insert));
    assert!(rr_set.get_records(false).contains(&&insert1));
  }

  #[test]
  fn test_insert_soa() {
    let name = Name::new().label("example").label("com");
    let record_type = RecordType::SOA;
    let mut rr_set = RRSet::new(&name, record_type, 0);

    let insert = Record::new().name(name.clone()).ttl(3600).rr_type(RecordType::SOA).dns_class(DNSClass::IN).rdata(RData::SOA(SOA::new(Name::parse("sns.dns.icann.org.", None).unwrap(), Name::parse("noc.dns.icann.org.", None).unwrap(), 2015082403, 7200, 3600, 1209600, 3600 ))).clone();
    let same_serial = Record::new().name(name.clone()).ttl(3600).rr_type(RecordType::SOA).dns_class(DNSClass::IN).rdata(RData::SOA(SOA::new(Name::parse("sns.dns.icann.net.", None).unwrap(), Name::parse("noc.dns.icann.net.", None).unwrap(), 2015082403, 7200, 3600, 1209600, 3600 ))).clone();
    let new_serial = Record::new().name(name.clone()).ttl(3600).rr_type(RecordType::SOA).dns_class(DNSClass::IN).rdata(RData::SOA(SOA::new(Name::parse("sns.dns.icann.net.", None).unwrap(), Name::parse("noc.dns.icann.net.", None).unwrap(), 2015082404, 7200, 3600, 1209600, 3600 ))).clone();

    assert!(rr_set.insert(insert.clone(), 0));
    assert!(rr_set.get_records(false).contains(&&insert));
    // same serial number
    assert!(!rr_set.insert(same_serial.clone(), 0));
    assert!(rr_set.get_records(false).contains(&&insert));
    assert!(!rr_set.get_records(false).contains(&&same_serial));

    assert!(rr_set.insert(new_serial.clone(), 0));
    assert!(!rr_set.insert(same_serial.clone(), 0));
    assert!(!rr_set.insert(insert.clone(), 0));

    assert!(rr_set.get_records(false).contains(&&new_serial));
    assert!(!rr_set.get_records(false).contains(&&insert));
    assert!(!rr_set.get_records(false).contains(&&same_serial));
  }

  #[test]
  fn test_insert_cname() {
    let name = Name::new().label("web").label("example").label("com");
    let cname = Name::new().label("www").label("example").label("com");
    let new_cname = Name::new().label("w2").label("example").label("com");

    let record_type = RecordType::CNAME;
    let mut rr_set = RRSet::new(&name, record_type, 0);

    let insert = Record::new().name(name.clone()).ttl(3600).rr_type(RecordType::CNAME).dns_class(DNSClass::IN).rdata(RData::CNAME(cname.clone()) ).clone();
    let new_record = Record::new().name(name.clone()).ttl(3600).rr_type(RecordType::CNAME).dns_class(DNSClass::IN).rdata(RData::CNAME(new_cname.clone()) ).clone();

    assert!(rr_set.insert(insert.clone(), 0));
    assert!(rr_set.get_records(false).contains(&&insert));

    // update the record
    assert!(rr_set.insert(new_record.clone(), 0));
    assert!(!rr_set.get_records(false).contains(&&insert));
    assert!(rr_set.get_records(false).contains(&&new_record));
  }

  #[test]
  fn test_remove() {
    let name = Name::new().label("www").label("example").label("com");
    let record_type = RecordType::A;
    let mut rr_set = RRSet::new(&name, record_type, 0);

    let insert = Record::new().name(name.clone()).ttl(86400).rr_type(record_type).dns_class(DNSClass::IN).rdata(RData::A(Ipv4Addr::new(93,184,216,24))).clone();
    let insert1 = Record::new().name(name.clone()).ttl(86400).rr_type(record_type).dns_class(DNSClass::IN).rdata(RData::A(Ipv4Addr::new(93,184,216,25))).clone();

    assert!(rr_set.insert(insert.clone(), 0));
    assert!(rr_set.insert(insert1.clone(), 0));

    assert!(rr_set.remove(&insert, 0));
    assert!(!rr_set.remove(&insert, 0));
    assert!(rr_set.remove(&insert1, 0));
    assert!(!rr_set.remove(&insert1, 0));
  }

  #[test]
  fn test_remove_soa() {
    let name = Name::new().label("example").label("com");
    let record_type = RecordType::SOA;
    let mut rr_set = RRSet::new(&name, record_type, 0);

    let insert = Record::new().name(name.clone()).ttl(3600).rr_type(RecordType::SOA).dns_class(DNSClass::IN).rdata(RData::SOA(SOA::new(Name::parse("sns.dns.icann.org.", None).unwrap(), Name::parse("noc.dns.icann.org.", None).unwrap(), 2015082403, 7200, 3600, 1209600, 3600 ))).clone();

    assert!(rr_set.insert(insert.clone(), 0));
    assert!(!rr_set.remove(&insert, 0));
    assert!(rr_set.get_records(false).contains(&&insert));
  }

  #[test]
  fn test_remove_ns() {
    let name = Name::new().label("example").label("com");
    let record_type = RecordType::NS;
    let mut rr_set = RRSet::new(&name, record_type, 0);

    let ns1 = Record::new().name(name.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()) ).clone();
    let ns2 = Record::new().name(name.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS(Name::parse("b.iana-servers.net.", None).unwrap()) ).clone();

    assert!(rr_set.insert(ns1.clone(), 0));
    assert!(rr_set.insert(ns2.clone(), 0));

    // ok to remove one, but not two...
    assert!(rr_set.remove(&ns1, 0));
    assert!(!rr_set.remove(&ns2, 0));

    // check that we can swap which ones are removed
    assert!(rr_set.insert(ns1.clone(), 0));

    assert!(rr_set.remove(&ns2, 0));
    assert!(!rr_set.remove(&ns1, 0));
  }
}
