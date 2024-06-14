// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{iter::Chain, slice::Iter, vec};

use tracing::{info, warn};

use crate::rr::{DNSClass, Name, RData, Record, RecordType};

#[cfg(feature = "dnssec")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
use crate::rr::dnssec::SupportedAlgorithms;

/// Set of resource records associated to a name and type
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordSet {
    name: Name,
    record_type: RecordType,
    dns_class: DNSClass,
    ttl: u32,
    records: Vec<Record>,
    rrsigs: Vec<Record>,
    serial: u32, // serial number at which this record was modified
}

impl RecordSet {
    /// Creates a new Resource Record Set.
    ///
    /// # Arguments
    ///
    /// * `name` - The label for the `RecordSet`
    /// * `record_type` - `RecordType` of this `RecordSet`, all records in the `RecordSet` must be of the
    ///                   specified `RecordType`.
    /// * `serial` - current serial number of the `SOA` record, this is to be used for `IXFR` and
    ///              signing for DNSSEC after updates.
    ///
    /// # Return value
    ///
    /// The newly created Resource Record Set
    /// TODO: make all cloned params pass by value
    pub fn new(name: &Name, record_type: RecordType, serial: u32) -> Self {
        Self {
            name: name.clone(),
            record_type,
            dns_class: DNSClass::IN,
            ttl: 0,
            records: Vec::new(),
            rrsigs: Vec::new(),
            serial,
        }
    }

    /// Creates a new Resource Record Set.
    ///
    /// # Arguments
    ///
    /// * `name` - The label for the `RecordSet`
    /// * `record_type` - `RecordType` of this `RecordSet`, all records in the `RecordSet` must be of the
    ///                   specified `RecordType`.
    /// * `ttl` - time-to-live for the `RecordSet` in seconds.
    ///
    /// # Return value
    ///
    /// The newly created Resource Record Set
    /// TODO: make all cloned params pass by value
    pub fn with_ttl(name: Name, record_type: RecordType, ttl: u32) -> Self {
        Self {
            name,
            record_type,
            dns_class: DNSClass::IN,
            ttl,
            records: Vec::new(),
            rrsigs: Vec::new(),
            serial: 0,
        }
    }

    /// # Return value
    ///
    /// Label of the Resource Record Set
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// # Return value
    ///
    /// `RecordType` of the Resource Record Set
    pub fn record_type(&self) -> RecordType {
        self.record_type
    }

    /// Sets the DNSClass to the specified value
    ///
    /// This will traverse every record and associate with it the specified dns_class
    pub fn set_dns_class(&mut self, dns_class: DNSClass) {
        self.dns_class = dns_class;
        for r in &mut self.records {
            r.set_dns_class(dns_class);
        }
    }

    /// Returns the `DNSClass` of the RecordSet
    pub fn dns_class(&self) -> DNSClass {
        self.dns_class
    }

    /// Sets the TTL, in seconds, to the specified value
    ///
    /// This will traverse every record and associate with it the specified ttl
    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
        for r in &mut self.records {
            r.set_ttl(ttl);
        }
    }

    /// Returns the time-to-live for the record.
    ///
    /// # Return value
    ///
    /// TTL, time-to-live, of the Resource Record Set, this is the maximum length of time that an
    /// RecordSet should be cached.
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Returns a Vec of all records in the set.
    ///
    /// # Arguments
    ///
    /// * `and_rrsigs` - if true, RRSIGs will be returned if they exist
    /// * `supported_algorithms` - the RRSIGs will be filtered by the set of supported_algorithms,
    ///                            and then only the maximal RRSIG algorithm will be returned.
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    pub fn records(
        &self,
        and_rrsigs: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> RrsetRecords<'_> {
        if and_rrsigs {
            self.records_with_rrsigs(supported_algorithms)
        } else {
            self.records_without_rrsigs()
        }
    }

    /// Returns a Vec of all records in the set, with RRSIGs, if present.
    ///
    /// # Arguments
    ///
    /// * `supported_algorithms` - the RRSIGs will be filtered by the set of supported_algorithms,
    ///                            and then only the maximal RRSIG algorithm will be returned.
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    pub fn records_with_rrsigs(
        &self,
        supported_algorithms: SupportedAlgorithms,
    ) -> RrsetRecords<'_> {
        if self.records.is_empty() {
            RrsetRecords::Empty
        } else {
            let rrsigs = RrsigsByAlgorithms {
                rrsigs: self.rrsigs.iter(),
                supported_algorithms,
            };
            RrsetRecords::RecordsAndRrsigs(RecordsAndRrsigsIter(self.records.iter().chain(rrsigs)))
        }
    }

    /// Returns a Vec of all records in the set, without any RRSIGs.
    pub fn records_without_rrsigs(&self) -> RrsetRecords<'_> {
        if self.records.is_empty() {
            RrsetRecords::Empty
        } else {
            RrsetRecords::RecordsOnly(self.records.iter())
        }
    }

    /// Returns an iterator over the records in the set
    #[deprecated(note = "see `records_without_rrsigs`")]
    pub fn iter(&self) -> Iter<'_, Record> {
        self.records.iter()
    }

    /// Returns true if there are no records in this set
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns the serial number at which the record was updated.
    pub fn serial(&self) -> u32 {
        self.serial
    }

    /// Returns a slice of all the Records signatures in the RecordSet
    pub fn rrsigs(&self) -> &[Record] {
        &self.rrsigs
    }

    /// Inserts a Signature for the Record set
    ///
    /// Many can be associated with the RecordSet. Once added, the RecordSet should not be changed
    ///
    /// # Arguments
    ///
    /// * `rrsig` - A signature which covers the RecordSet.
    pub fn insert_rrsig(&mut self, rrsig: Record) {
        self.rrsigs.push(rrsig)
    }

    /// Useful for clearing all signatures when the RecordSet is updated, or keys are rotated.
    pub fn clear_rrsigs(&mut self) {
        self.rrsigs.clear()
    }

    fn updated(&mut self, serial: u32) {
        self.serial = serial;
        self.rrsigs.clear(); // on updates, the rrsigs are invalid
    }

    /// creates a new Record as part of this RecordSet, adding the associated RData
    ///
    /// this interface may be deprecated in the future.
    pub fn new_record(&mut self, rdata: &RData) -> &Record {
        self.add_rdata(rdata.clone());

        self.records
            .iter()
            .find(|r| r.data() == rdata)
            .expect("insert failed")
    }

    /// creates a new Record as part of this RecordSet, adding the associated RData
    pub fn add_rdata(&mut self, rdata: RData) -> bool {
        debug_assert_eq!(self.record_type, rdata.record_type());

        let record = Record::from_rdata(self.name.clone(), self.ttl, rdata);
        self.insert(record, 0)
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
    /// * `record` - `Record` asserts that the `name` and `record_type` match the `RecordSet`.
    /// * `serial` - current serial number of the `SOA` record, this is to be used for `IXFR` and
    ///              signing for DNSSEC after updates. The serial will only be updated if the
    ///              record was added.
    ///
    /// # Return value
    ///
    /// True if the record was inserted.
    ///
    /// TODO: make a default add without serial number for basic usage
    pub fn insert(&mut self, record: Record, serial: u32) -> bool {
        assert_eq!(record.name(), &self.name);
        assert_eq!(record.record_type(), self.record_type);

        // RFC 2136                       DNS Update                     April 1997
        //
        // 1.1.5. The following RR types cannot be appended to an RRset.  If the
        //  following comparison rules are met, then an attempt to add the new RR
        //  will result in the replacement of the previous RR:
        match record.record_type() {
            // SOA    compare only NAME, CLASS and TYPE -- it is not possible to
            //         have more than one SOA per zone, even if any of the data
            //         fields differ.
            RecordType::SOA => {
                assert!(self.records.len() <= 1);

                if let Some(soa_record) = self.records.first() {
                    match soa_record.data() {
                        RData::SOA(ref existing_soa) => {
                            if let RData::SOA(ref new_soa) = record.data() {
                                if new_soa.serial() <= existing_soa.serial() {
                                    info!(
                                        "update ignored serial out of data: {:?} <= {:?}",
                                        new_soa, existing_soa
                                    );
                                    return false;
                                }
                            } else {
                                // not panicking here, b/c this is a bad record from the client or something, ignore
                                info!("wrong rdata for SOA update: {:?}", record.data());
                                return false;
                            }
                        }
                        rdata => {
                            warn!("wrong rdata: {:?}, expected SOA", rdata);
                            return false;
                        }
                    }
                }

                // if we got here, we're updating...
                self.records.clear();
            }
            // RFC 1034/1035
            // CNAME  compare only NAME, CLASS, and TYPE -- it is not possible
            //         to have more than one CNAME RR, even if their data fields
            //         differ.
            //
            // ANAME https://tools.ietf.org/html/draft-ietf-dnsop-aname-02
            //    2.2.  Coexistence with other types
            //
            //   Only one ANAME <target> can be defined per <owner>.  An ANAME RRset
            //   MUST NOT contain more than one resource record.
            //
            //   An ANAME's sibling address records are under the control of ANAME
            //   processing (see Section 5) and are not first-class records in their
            //   own right.  They MAY exist in zone files, but they can subsequently
            //   be altered by ANAME processing.
            //
            //   ANAME records MAY freely coexist at the same owner name with other RR
            //   types, except they MUST NOT coexist with CNAME or any other RR type
            //   that restricts the types with which it can itself coexist.
            //
            //   Like other types, ANAME records can coexist with DNAME records at the
            //   same owner name; in fact, the two can be used cooperatively to
            //   redirect both the owner name address records (via ANAME) and
            //   everything under it (via DNAME).
            RecordType::CNAME | RecordType::ANAME => {
                assert!(self.records.len() <= 1);
                self.records.clear();
            }
            _ => (),
        }

        // collect any records to update based on rdata
        let to_replace: Vec<usize> = self
            .records
            .iter()
            .enumerate()
            .filter(|&(_, rr)| rr.data() == record.data())
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
            self.ttl = record.ttl();
            self.updated(serial);
            replaced = true;
        }

        if !replaced {
            self.ttl = record.ttl();
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
    /// * `record` - `Record` asserts that the `name` and `record_type` match the `RecordSet`. Removes
    ///              any `record` if the record data, `RData`, match.
    /// * `serial` - current serial number of the `SOA` record, this is to be used for `IXFR` and
    ///              signing for DNSSEC after updates. The serial will only be updated if the
    ///              record was added.
    ///
    /// # Return value
    ///
    /// True if a record was removed.
    pub fn remove(&mut self, record: &Record, serial: u32) -> bool {
        assert_eq!(record.name(), &self.name);
        assert!(
            record.record_type() == self.record_type || record.record_type() == RecordType::ANY
        );

        match record.record_type() {
            // never delete the last NS record
            RecordType::NS => {
                if self.records.len() <= 1 {
                    info!("ignoring delete of last NS record: {:?}", record);
                    return false;
                }
            }
            // never delete SOA
            RecordType::SOA => {
                info!("ignored delete of SOA");
                return false;
            }
            _ => (), // move on to the delete
        }

        // remove the records, first collect all the indexes, then remove the records
        let to_remove: Vec<usize> = self
            .records
            .iter()
            .enumerate()
            .filter(|&(_, rr)| rr.data() == record.data())
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

    /// Consumes `RecordSet` and returns its components
    pub fn into_parts(self) -> RecordSetParts {
        self.into()
    }
}

/// Consumes `RecordSet` giving public access to fields of `RecordSet` so they can
/// be destructured and taken by value
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordSetParts {
    pub name: Name,
    pub record_type: RecordType,
    pub dns_class: DNSClass,
    pub ttl: u32,
    pub records: Vec<Record>,
    pub rrsigs: Vec<Record>,
    pub serial: u32, // serial number at which this record was modified,
}

impl From<RecordSet> for RecordSetParts {
    fn from(rset: RecordSet) -> Self {
        let RecordSet {
            name,
            record_type,
            dns_class,
            ttl,
            records,
            rrsigs,
            serial,
        } = rset;
        Self {
            name,
            record_type,
            dns_class,
            ttl,
            records,
            rrsigs,
            serial,
        }
    }
}

impl From<Record> for RecordSet {
    fn from(record: Record) -> Self {
        Self {
            name: record.name().clone(),
            record_type: record.record_type(),
            dns_class: record.dns_class(),
            ttl: record.ttl(),
            records: vec![record],
            rrsigs: vec![],
            serial: 0,
        }
    }
}

/// Types which implement this can be converted into a RecordSet
#[deprecated(note = "use From/Into")]
pub trait IntoRecordSet: Sized {
    /// Performs the conversion to a RecordSet
    fn into_record_set(self) -> RecordSet;
}

#[allow(deprecated)]
impl IntoRecordSet for RecordSet {
    fn into_record_set(self) -> Self {
        self
    }
}

impl IntoIterator for RecordSet {
    type Item = Record;
    type IntoIter = Chain<vec::IntoIter<Record>, vec::IntoIter<Record>>;

    fn into_iter(self) -> Self::IntoIter {
        self.records.into_iter().chain(self.rrsigs)
    }
}

/// An iterator over all the records and their signatures
#[cfg(feature = "dnssec")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
#[derive(Debug)]
pub struct RecordsAndRrsigsIter<'r>(Chain<Iter<'r, Record>, RrsigsByAlgorithms<'r>>);

#[cfg(feature = "dnssec")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
impl<'r> Iterator for RecordsAndRrsigsIter<'r> {
    type Item = &'r Record;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

/// An iterator that limits the record signatures by SupportedAlgorithms
#[cfg(feature = "dnssec")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
#[derive(Debug)]
pub(crate) struct RrsigsByAlgorithms<'r> {
    rrsigs: Iter<'r, Record>,
    supported_algorithms: SupportedAlgorithms,
}

#[cfg(feature = "dnssec")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
impl<'r> Iterator for RrsigsByAlgorithms<'r> {
    type Item = &'r Record;

    fn next(&mut self) -> Option<Self::Item> {
        use crate::rr::dnssec::rdata::DNSSECRData;
        use crate::rr::dnssec::Algorithm;

        let supported_algorithms = self.supported_algorithms;

        // disable rfc 6975 when no supported_algorithms specified
        if supported_algorithms.is_empty() {
            self.rrsigs.next()
        } else {
            self.rrsigs
                .by_ref()
                .filter(|record| {
                    if let RData::DNSSEC(DNSSECRData::RRSIG(ref rrsig)) = record.data() {
                        supported_algorithms.has(rrsig.algorithm())
                    } else {
                        false
                    }
                })
                .max_by_key(|record| {
                    if let RData::DNSSEC(DNSSECRData::RRSIG(ref rrsig)) = record.data() {
                        rrsig.algorithm()
                    } else {
                        #[allow(deprecated)]
                        Algorithm::RSASHA1
                    }
                })
        }
    }
}

/// An iterator over the RecordSet data
#[derive(Debug)]
pub enum RrsetRecords<'r> {
    /// There are no records in the record set
    Empty,
    /// The records associated with the record set
    RecordsOnly(Iter<'r, Record>),
    /// The records along with their signatures in the record set
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    RecordsAndRrsigs(RecordsAndRrsigsIter<'r>),
}

impl<'r> RrsetRecords<'r> {
    /// This is a best effort emptiness check
    pub fn is_empty(&self) -> bool {
        matches!(*self, RrsetRecords::Empty)
    }
}

impl<'r> Iterator for RrsetRecords<'r> {
    type Item = &'r Record;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            RrsetRecords::Empty => None,
            RrsetRecords::RecordsOnly(i) => i.next(),
            #[cfg(feature = "dnssec")]
            RrsetRecords::RecordsAndRrsigs(i) => i.next(),
        }
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use crate::rr::rdata::{CNAME, NS, SOA};
    use crate::rr::*;

    #[test]
    fn test_insert() {
        let name = Name::from_str("www.example.com.").unwrap();
        let record_type = RecordType::A;
        let mut rr_set = RecordSet::new(&name, record_type, 0);

        let insert = Record::from_rdata(
            name.clone(),
            86400,
            RData::A(Ipv4Addr::new(93, 184, 216, 24).into()),
        )
        .set_dns_class(DNSClass::IN)
        .clone();

        assert!(rr_set.insert(insert.clone(), 0));
        assert_eq!(rr_set.records_without_rrsigs().count(), 1);
        assert!(rr_set.records_without_rrsigs().any(|ref x| x == &&insert));

        // dups ignored
        assert!(!rr_set.insert(insert.clone(), 0));
        assert_eq!(rr_set.records_without_rrsigs().count(), 1);
        assert!(rr_set.records_without_rrsigs().any(|ref x| x == &&insert));

        // add one
        let insert1 = Record::from_rdata(
            name,
            86400,
            RData::A(Ipv4Addr::new(93, 184, 216, 25).into()),
        )
        .set_dns_class(DNSClass::IN)
        .clone();
        assert!(rr_set.insert(insert1.clone(), 0));
        assert_eq!(rr_set.records_without_rrsigs().count(), 2);
        assert!(rr_set.records_without_rrsigs().any(|ref x| x == &&insert));
        assert!(rr_set.records_without_rrsigs().any(|ref x| x == &&insert1));
    }

    #[test]
    #[allow(clippy::unreadable_literal)]
    fn test_insert_soa() {
        let name = Name::from_str("example.com.").unwrap();
        let record_type = RecordType::SOA;
        let mut rr_set = RecordSet::new(&name, record_type, 0);

        let insert = Record::from_rdata(
            name.clone(),
            3600,
            RData::SOA(SOA::new(
                Name::from_str("sns.dns.icann.org.").unwrap(),
                Name::from_str("noc.dns.icann.org.").unwrap(),
                2015082403,
                7200,
                3600,
                1209600,
                3600,
            )),
        )
        .set_dns_class(DNSClass::IN)
        .clone();
        let same_serial = Record::from_rdata(
            name.clone(),
            3600,
            RData::SOA(SOA::new(
                Name::from_str("sns.dns.icann.net.").unwrap(),
                Name::from_str("noc.dns.icann.net.").unwrap(),
                2015082403,
                7200,
                3600,
                1209600,
                3600,
            )),
        )
        .set_dns_class(DNSClass::IN)
        .clone();
        let new_serial = Record::from_rdata(
            name,
            3600,
            RData::SOA(SOA::new(
                Name::from_str("sns.dns.icann.net.").unwrap(),
                Name::from_str("noc.dns.icann.net.").unwrap(),
                2015082404,
                7200,
                3600,
                1209600,
                3600,
            )),
        )
        .set_dns_class(DNSClass::IN)
        .clone();

        assert!(rr_set.insert(insert.clone(), 0));
        assert!(rr_set.records_without_rrsigs().any(|ref x| x == &&insert));
        // same serial number
        assert!(!rr_set.insert(same_serial.clone(), 0));
        assert!(rr_set.records_without_rrsigs().any(|ref x| x == &&insert));
        assert!(!rr_set
            .records_without_rrsigs()
            .any(|ref x| x == &&same_serial));

        assert!(rr_set.insert(new_serial.clone(), 0));
        assert!(!rr_set.insert(same_serial.clone(), 0));
        assert!(!rr_set.insert(insert.clone(), 0));

        assert!(rr_set
            .records_without_rrsigs()
            .any(|ref x| x == &&new_serial));
        assert!(!rr_set.records_without_rrsigs().any(|ref x| x == &&insert));
        assert!(!rr_set
            .records_without_rrsigs()
            .any(|ref x| x == &&same_serial));
    }

    #[test]
    fn test_insert_cname() {
        let name = Name::from_str("web.example.com.").unwrap();
        let cname = Name::from_str("www.example.com.").unwrap();
        let new_cname = Name::from_str("w2.example.com.").unwrap();

        let record_type = RecordType::CNAME;
        let mut rr_set = RecordSet::new(&name, record_type, 0);

        let insert = Record::from_rdata(name.clone(), 3600, RData::CNAME(CNAME(cname)))
            .set_dns_class(DNSClass::IN)
            .clone();
        let new_record = Record::from_rdata(name, 3600, RData::CNAME(CNAME(new_cname)))
            .set_dns_class(DNSClass::IN)
            .clone();

        assert!(rr_set.insert(insert.clone(), 0));
        assert!(rr_set.records_without_rrsigs().any(|ref x| x == &&insert));

        // update the record
        assert!(rr_set.insert(new_record.clone(), 0));
        assert!(!rr_set.records_without_rrsigs().any(|ref x| x == &&insert));
        assert!(rr_set
            .records_without_rrsigs()
            .any(|ref x| x == &&new_record));
    }

    #[test]
    fn test_remove() {
        let name = Name::from_str("www.example.com.").unwrap();
        let record_type = RecordType::A;
        let mut rr_set = RecordSet::new(&name, record_type, 0);

        let insert = Record::from_rdata(
            name.clone(),
            86400,
            RData::A(Ipv4Addr::new(93, 184, 216, 24).into()),
        )
        .set_dns_class(DNSClass::IN)
        .clone();
        let insert1 = Record::from_rdata(
            name,
            86400,
            RData::A(Ipv4Addr::new(93, 184, 216, 25).into()),
        )
        .set_dns_class(DNSClass::IN)
        .clone();

        assert!(rr_set.insert(insert.clone(), 0));
        assert!(rr_set.insert(insert1.clone(), 0));

        assert!(rr_set.remove(&insert, 0));
        assert!(!rr_set.remove(&insert, 0));
        assert!(rr_set.remove(&insert1, 0));
        assert!(!rr_set.remove(&insert1, 0));
    }

    #[test]
    #[allow(clippy::unreadable_literal)]
    fn test_remove_soa() {
        let name = Name::from_str("www.example.com.").unwrap();
        let record_type = RecordType::SOA;
        let mut rr_set = RecordSet::new(&name, record_type, 0);

        let insert = Record::from_rdata(
            name,
            3600,
            RData::SOA(SOA::new(
                Name::from_str("sns.dns.icann.org.").unwrap(),
                Name::from_str("noc.dns.icann.org.").unwrap(),
                2015082403,
                7200,
                3600,
                1209600,
                3600,
            )),
        )
        .set_dns_class(DNSClass::IN)
        .clone();

        assert!(rr_set.insert(insert.clone(), 0));
        assert!(!rr_set.remove(&insert, 0));
        assert!(rr_set.records_without_rrsigs().any(|ref x| x == &&insert));
    }

    #[test]
    fn test_remove_ns() {
        let name = Name::from_str("example.com.").unwrap();
        let record_type = RecordType::NS;
        let mut rr_set = RecordSet::new(&name, record_type, 0);

        let ns1 = Record::from_rdata(
            name.clone(),
            86400,
            RData::NS(NS(Name::from_str("a.iana-servers.net.").unwrap())),
        )
        .set_dns_class(DNSClass::IN)
        .clone();
        let ns2 = Record::from_rdata(
            name,
            86400,
            RData::NS(NS(Name::from_str("b.iana-servers.net.").unwrap())),
        )
        .set_dns_class(DNSClass::IN)
        .clone();

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

    #[test]
    #[cfg(feature = "dnssec")] // This tests RFC 6975, a DNSSEC-specific feature.
    #[allow(clippy::blocks_in_conditions)]
    fn test_get_filter() {
        use crate::rr::dnssec::rdata::DNSSECRData;
        use crate::rr::dnssec::rdata::RRSIG;
        use crate::rr::dnssec::{Algorithm, SupportedAlgorithms};

        let name = Name::root();
        let rsasha256 = RRSIG::new(
            RecordType::A,
            Algorithm::RSASHA256,
            0,
            0,
            0,
            0,
            0,
            Name::root(),
            vec![],
        );
        let ecp256 = RRSIG::new(
            RecordType::A,
            Algorithm::ECDSAP256SHA256,
            0,
            0,
            0,
            0,
            0,
            Name::root(),
            vec![],
        );
        let ecp384 = RRSIG::new(
            RecordType::A,
            Algorithm::ECDSAP384SHA384,
            0,
            0,
            0,
            0,
            0,
            Name::root(),
            vec![],
        );
        let ed25519 = RRSIG::new(
            RecordType::A,
            Algorithm::ED25519,
            0,
            0,
            0,
            0,
            0,
            Name::root(),
            vec![],
        );

        let rrsig_rsa = Record::from_rdata(
            name.clone(),
            3600,
            RData::DNSSEC(DNSSECRData::RRSIG(rsasha256)),
        )
        .set_dns_class(DNSClass::IN)
        .clone();
        let rrsig_ecp256 = Record::from_rdata(
            name.clone(),
            3600,
            RData::DNSSEC(DNSSECRData::RRSIG(ecp256)),
        )
        .set_dns_class(DNSClass::IN)
        .clone();
        let rrsig_ecp384 = Record::from_rdata(
            name.clone(),
            3600,
            RData::DNSSEC(DNSSECRData::RRSIG(ecp384)),
        )
        .set_dns_class(DNSClass::IN)
        .clone();
        let rrsig_ed25519 = Record::from_rdata(
            name.clone(),
            3600,
            RData::DNSSEC(DNSSECRData::RRSIG(ed25519)),
        )
        .set_dns_class(DNSClass::IN)
        .clone();

        let a = Record::from_rdata(name, 3600, RData::A(Ipv4Addr::new(93, 184, 216, 24).into()))
            .set_dns_class(DNSClass::IN)
            .clone();

        let mut rrset = RecordSet::from(a);
        rrset.insert_rrsig(rrsig_rsa);
        rrset.insert_rrsig(rrsig_ecp256);
        rrset.insert_rrsig(rrsig_ecp384);
        rrset.insert_rrsig(rrsig_ed25519);

        assert!(rrset
            .records_with_rrsigs(SupportedAlgorithms::all(),)
            .any(
                |r| if let RData::DNSSEC(DNSSECRData::RRSIG(ref sig)) = r.data() {
                    sig.algorithm() == Algorithm::ED25519
                } else {
                    false
                },
            ));

        let mut supported_algorithms = SupportedAlgorithms::new();
        supported_algorithms.set(Algorithm::ECDSAP384SHA384);
        assert!(rrset.records_with_rrsigs(supported_algorithms).any(|r| {
            if let RData::DNSSEC(DNSSECRData::RRSIG(ref sig)) = r.data() {
                sig.algorithm() == Algorithm::ECDSAP384SHA384
            } else {
                false
            }
        }));

        let mut supported_algorithms = SupportedAlgorithms::new();
        supported_algorithms.set(Algorithm::ED25519);
        assert!(rrset.records_with_rrsigs(supported_algorithms).any(|r| {
            if let RData::DNSSEC(DNSSECRData::RRSIG(ref sig)) = r.data() {
                sig.algorithm() == Algorithm::ED25519
            } else {
                false
            }
        }));
    }
}
