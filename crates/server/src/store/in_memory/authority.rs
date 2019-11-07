// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! All authority related types

use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::Arc;

use futures::future::{self, Future, TryFutureExt};

use trust_dns_client::op::{LowerQuery, ResponseCode};
use trust_dns_client::rr::dnssec::{DnsSecResult, Signer, SupportedAlgorithms};
use trust_dns_client::rr::rdata::key::KEY;
#[cfg(feature = "dnssec")]
use trust_dns_client::rr::rdata::DNSSECRData;
use trust_dns_client::rr::rdata::DNSSECRecordType;
use trust_dns_client::rr::rdata::SOA;
use trust_dns_client::rr::{
    DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType, RrKey,
};

use crate::authority::{
    AnyRecords, AuthLookup, Authority, LookupError, LookupRecords, LookupResult, MessageRequest,
    UpdateResult, ZoneType,
};

/// InMemoryAuthority is responsible for storing the resource records for a particular zone.
///
/// Authorities default to DNSClass IN. The ZoneType specifies if this should be treated as the
/// start of authority for the zone, is a slave, or a cached zone.
pub struct InMemoryAuthority {
    origin: LowerName,
    class: DNSClass,
    records: BTreeMap<RrKey, Arc<RecordSet>>,
    zone_type: ZoneType,
    allow_axfr: bool,
    // Private key mapped to the Record of the DNSKey
    //  TODO: these private_keys should be stored securely. Ideally, we have keys only stored per
    //   server instance, but that requires requesting updates from the parent zone, which may or
    //   may not support dynamic updates to register the new key... Trust-DNS will provide support
    //   for this, in some form, perhaps alternate root zones...
    secure_keys: Vec<Signer>,
}

impl InMemoryAuthority {
    /// Creates a new Authority.
    ///
    /// # Arguments
    ///
    /// * `origin` - The zone `Name` being created, this should match that of the `RecordType::SOA`
    ///              record.
    /// * `records` - The map of the initial set of records in the zone.
    /// * `zone_type` - The type of zone, i.e. is this authoritative?
    /// * `allow_update` - If true, then this zone accepts dynamic updates.
    /// * `is_dnssec_enabled` - If true, then the zone will sign the zone with all registered keys,
    ///                         (see `add_zone_signing_key()`)
    ///
    /// # Return value
    ///
    /// The new `Authority`.
    pub fn new(
        origin: Name,
        records: BTreeMap<RrKey, RecordSet>,
        zone_type: ZoneType,
        allow_axfr: bool,
    ) -> Result<Self, String> {
        let mut this = Self::empty(origin.clone(), zone_type, allow_axfr);

        // SOA must be present
        let serial = records
            .iter()
            .find(|(key, _)| key.record_type == RecordType::SOA)
            .and_then(|(_, rrset)| rrset.records_without_rrsigs().next())
            .and_then(|record| record.rdata().as_soa())
            .map(SOA::serial)
            .ok_or_else(|| format!("SOA record must be present: {}", origin))?;

        let iter = records.into_iter().map(|(_key, record)| record);

        // add soa to the records
        for rrset in iter {
            let name = rrset.name().clone();
            let rr_type = rrset.record_type();

            for record in rrset.records_without_rrsigs() {
                if !this.upsert(record.clone(), serial) {
                    return Err(format!(
                        "Failed to insert {} {} to zone: {}",
                        name, rr_type, origin
                    ));
                };
            }
        }

        Ok(this)
    }

    /// Creates an empty Authority
    ///
    /// # Warning
    ///
    /// This is an invalid zone, SOA must be added
    pub fn empty(origin: Name, zone_type: ZoneType, allow_axfr: bool) -> Self {
        Self {
            origin: LowerName::new(&origin),
            class: DNSClass::IN,
            records: BTreeMap::new(),
            zone_type,
            allow_axfr,
            secure_keys: Vec::new(),
        }
    }

    /// Clears all records (including SOA, etc)
    pub fn clear(&mut self) {
        self.records.clear()
    }

    /// Get the DNSClass of the zone
    pub fn class(&self) -> DNSClass {
        self.class
    }

    /// Enables AXFRs of all the zones records
    pub fn set_allow_axfr(&mut self, allow_axfr: bool) {
        self.allow_axfr = allow_axfr;
    }

    /// Retrieve the Signer, which contains the private keys, for this zone
    pub fn secure_keys(&self) -> &[Signer] {
        &self.secure_keys
    }

    /// Get all the records
    pub fn records(&self) -> &BTreeMap<RrKey, Arc<RecordSet>> {
        &self.records
    }

    /// Get a mutable reference to the records
    pub fn records_mut(&mut self) -> &mut BTreeMap<RrKey, Arc<RecordSet>> {
        &mut self.records
    }

    fn inner_soa(&self) -> Option<&SOA> {
        let rr_key = RrKey::new(self.origin.clone(), RecordType::SOA);

        self.records
            .get(&rr_key)
            .and_then(|rrset| rrset.records_without_rrsigs().next())
            .and_then(|record| record.rdata().as_soa())
    }

    /// Returns the minimum ttl (as used in the SOA record)
    pub fn minimum_ttl(&self) -> u32 {
        let soa = self.inner_soa();

        let soa = match soa {
            Some(soa) => soa,
            None => {
                error!("could not lookup SOA for authority: {}", self.origin);
                return 0;
            }
        };

        soa.minimum()
    }

    /// get the current serial number for the zone.
    pub fn serial(&self) -> u32 {
        let soa = self.inner_soa();

        let soa = match soa {
            Some(soa) => soa,
            None => {
                error!("could not lookup SOA for authority: {}", self.origin);
                return 0;
            }
        };

        soa.serial()
    }

    fn inner_lookup(
        &self,
        name: &LowerName,
        record_type: RecordType,
        and_rrsigs: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> Option<Arc<RecordSet>> {
        // this range covers all the records for any of the RecordTypes at a given label.
        let start_range_key = RrKey::new(name.clone(), RecordType::Unknown(u16::min_value()));
        let end_range_key = RrKey::new(name.clone(), RecordType::Unknown(u16::max_value()));

        fn aname_covers_type(key_type: RecordType, query_type: RecordType) -> bool {
            (query_type == RecordType::A || query_type == RecordType::AAAA)
                && key_type == RecordType::ANAME
        }

        let lookup = self
            .records
            .range(&start_range_key..&end_range_key)
            // remember CNAME can be the only record at a particular label
            .find(|(key, _)| {
                key.record_type == record_type
                    || key.record_type == RecordType::CNAME
                    || aname_covers_type(key.record_type, record_type)
            })
            .map(|(_key, rr_set)| rr_set);

        // TODO: maybe unwrap this recursion.
        match lookup {
            None => self.inner_lookup_wildcard(name, record_type, and_rrsigs, supported_algorithms),
            l => l.cloned(),
        }
    }

    fn inner_lookup_wildcard(
        &self,
        name: &LowerName,
        record_type: RecordType,
        and_rrsigs: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> Option<Arc<RecordSet>> {
        let wildcard = if name.is_wildcard() {
            return None;
        } else {
            name.clone().into_wildcard()
        };

        self.inner_lookup(&wildcard, record_type, and_rrsigs, supported_algorithms)
            // we need to change the name to the query name in the result set since this was a wildcard
            .map(|rrset| {
                let mut new_answer =
                    RecordSet::new(name.borrow(), rrset.record_type(), rrset.ttl());

                let (records, _rrsigs): (Vec<&Record>, Vec<&Record>) = rrset
                    .records(and_rrsigs, supported_algorithms)
                    .partition(|r| r.record_type() != RecordType::DNSSEC(DNSSECRecordType::RRSIG));

                for record in records {
                    new_answer.add_rdata(record.rdata().clone());
                }

                #[cfg(feature = "dnssec")]
                for rrsig in _rrsigs {
                    new_answer.insert_rrsig(rrsig.clone())
                }

                Arc::new(new_answer)
            })
    }

    /// Search for additional records to include in the response
    ///
    /// # Arguments
    ///
    /// * query_type - original type in the request query
    /// * next_name - the name from the CNAME, ANAME, MX, etc. record that is being searched
    /// * search_type - the root search type, ANAME, CNAME, MX, i.e. the begging of the chain
    fn additional_search(
        &self,
        query_type: RecordType,
        next_name: LowerName,
        _search_type: RecordType,
        and_rrsigs: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> Option<Vec<Arc<RecordSet>>> {
        let mut additionals: Vec<Arc<RecordSet>> = vec![];

        // if it's a CNAME or other forwarding record, we'll be adding additional records based on the query_type
        let mut query_types_arr = [query_type; 2];
        let query_types: &[RecordType] = match query_type {
            RecordType::ANAME | RecordType::NS | RecordType::MX | RecordType::SRV => {
                query_types_arr = [RecordType::A, RecordType::AAAA];
                &query_types_arr[..]
            }
            _ => &query_types_arr[..1],
        };

        for query_type in query_types {
            // loop and collect any additional records to send
            let mut next_name = Some(next_name.clone());
            while let Some(search) = next_name.take() {
                let additional =
                    self.inner_lookup(&search, *query_type, and_rrsigs, supported_algorithms);
                let mut continue_name = None;

                if let Some(additional) = additional {
                    // assuming no crazy long chains...
                    if !additionals.contains(&additional) {
                        additionals.push(additional.clone());
                    }

                    continue_name =
                        maybe_next_name(&additional, *query_type).map(|(name, _search_type)| name);
                }

                next_name = continue_name;
            }
        }

        if !additionals.is_empty() {
            Some(additionals)
        } else {
            None
        }
    }

    #[cfg(any(feature = "dnssec", feature = "sqlite"))]
    pub(crate) fn increment_soa_serial(&mut self) -> u32 {
        // we'll remove the SOA and then replace it
        let rr_key = RrKey::new(self.origin.clone(), RecordType::SOA);
        let record = self
            .records
            .remove(&rr_key)
            // TODO: there should be an unwrap on rrset, but it's behind Arc
            .and_then(|rrset| rrset.records_without_rrsigs().next().cloned());

        let mut record = if let Some(record) = record {
            record
        } else {
            error!("could not lookup SOA for authority: {}", self.origin);
            return 0;
        };

        let serial = if let RData::SOA(ref mut soa_rdata) = *record.rdata_mut() {
            soa_rdata.increment_serial();
            soa_rdata.serial()
        } else {
            panic!("This was not an SOA record"); // valid panic, never should happen
        };

        self.upsert(record, serial);
        serial
    }

    /// Inserts or updates a `Record` depending on it's existence in the authority.
    ///
    /// Guarantees that SOA, CNAME only has one record, will implicitly update if they already exist.
    ///
    /// # Arguments
    ///
    /// * `record` - The `Record` to be inserted or updated.
    /// * `serial` - Current serial number to be recorded against updates.
    ///
    /// # Return value
    ///
    /// true if the value was inserted, false otherwise
    pub fn upsert(&mut self, record: Record, serial: u32) -> bool {
        assert_eq!(self.class, record.dns_class());

        #[cfg(feature = "dnssec")]
        fn is_nsec(upsert_type: RecordType, occupied_type: RecordType) -> bool {
            // NSEC is always allowed
            upsert_type == RecordType::DNSSEC(DNSSECRecordType::NSEC)
                || upsert_type == RecordType::DNSSEC(DNSSECRecordType::NSEC3)
                || occupied_type == RecordType::DNSSEC(DNSSECRecordType::NSEC)
                || occupied_type == RecordType::DNSSEC(DNSSECRecordType::NSEC3)
        }

        #[cfg(not(feature = "dnssec"))]
        fn is_nsec(_upsert_type: RecordType, _occupied_type: RecordType) -> bool {
            // TODO: we should make the DNSSec RecordTypes always visible
            false
        }

        /// returns true if an only if the label can not cooccupy space with the checked type
        #[allow(clippy::nonminimal_bool)]
        fn label_does_not_allow_multiple(
            upsert_type: RecordType,
            occupied_type: RecordType,
            check_type: RecordType,
        ) -> bool {
            // it's a CNAME/ANAME but there's a record that's not a CNAME/ANAME at this location
            (upsert_type == check_type && occupied_type != check_type) ||
                // it's a different record, but there is already a CNAME/ANAME here
                (upsert_type != check_type && occupied_type == check_type)
        };

        // check that CNAME and ANAME is either not already present, or no other records are if it's a CNAME
        let start_range_key =
            RrKey::new(record.name().into(), RecordType::Unknown(u16::min_value()));
        let end_range_key = RrKey::new(record.name().into(), RecordType::Unknown(u16::max_value()));

        let multiple_records_at_label_disallowed = self
            .records
            .range(&start_range_key..&end_range_key)
            // remember CNAME can be the only record at a particular label
            .any(|(key, _)| {
                !is_nsec(record.record_type(), key.record_type)
                    && label_does_not_allow_multiple(
                        record.record_type(),
                        key.record_type,
                        RecordType::CNAME,
                    )
            });

        if multiple_records_at_label_disallowed {
            // consider making this an error?
            return false;
        }

        let rr_key = RrKey::new(record.name().into(), record.rr_type());
        let records: &mut Arc<RecordSet> = self
            .records
            .entry(rr_key)
            .or_insert_with(|| Arc::new(RecordSet::new(record.name(), record.rr_type(), serial)));

        // because this is and Arc, we need to clone and then replace the entry
        let mut records_clone = RecordSet::clone(&*records);
        if records_clone.insert(record, serial) {
            *records = Arc::new(records_clone);
            true
        } else {
            false
        }
    }

    /// (Re)generates the nsec records, increments the serial number and signs the zone
    #[cfg(feature = "dnssec")]
    pub fn secure_zone(&mut self) -> DnsSecResult<()> {
        // TODO: only call nsec_zone after adds/deletes
        // needs to be called before incrementing the soa serial, to make sure IXFR works properly
        self.nsec_zone();

        // need to resign any records at the current serial number and bump the number.
        // first bump the serial number on the SOA, so that it is resigned with the new serial.
        self.increment_soa_serial();

        // TODO: should we auto sign here? or maybe up a level...
        self.sign_zone()
    }

    /// (Re)generates the nsec records, increments the serial number and signs the zone
    #[cfg(not(feature = "dnssec"))]
    pub fn secure_zone(&mut self) -> Result<(), &str> {
        Err("DNSSEC was not enabled during compilation.")
    }

    /// Dummy implementation for when DNSSEC is disabled.
    #[cfg(feature = "dnssec")]
    fn nsec_zone(&mut self) {
        use trust_dns_client::rr::rdata::NSEC;

        // only create nsec records for secure zones
        if self.secure_keys.is_empty() {
            return;
        }
        debug!("generating nsec records: {}", self.origin);

        // first remove all existing nsec records
        let delete_keys: Vec<RrKey> = self
            .records
            .keys()
            .filter(|k| k.record_type == RecordType::DNSSEC(DNSSECRecordType::NSEC))
            .cloned()
            .collect();

        for key in delete_keys {
            self.records.remove(&key);
        }

        // now go through and generate the nsec records
        let ttl = self.minimum_ttl();
        let serial = self.serial();
        let mut records: Vec<Record> = vec![];

        {
            let mut nsec_info: Option<(&Name, Vec<RecordType>)> = None;
            for key in self.records.keys() {
                match nsec_info {
                    None => nsec_info = Some((key.name.borrow(), vec![key.record_type])),
                    Some((name, ref mut vec)) if LowerName::new(name) == key.name => {
                        vec.push(key.record_type)
                    }
                    Some((name, vec)) => {
                        // names aren't equal, create the NSEC record
                        let mut record = Record::with(
                            name.clone(),
                            RecordType::DNSSEC(DNSSECRecordType::NSEC),
                            ttl,
                        );
                        let rdata = NSEC::new_cover_self(key.name.clone().into(), vec);
                        record.set_rdata(RData::DNSSEC(DNSSECRData::NSEC(rdata)));
                        records.push(record);

                        // new record...
                        nsec_info = Some((&key.name.borrow(), vec![key.record_type]))
                    }
                }
            }

            // the last record
            if let Some((name, vec)) = nsec_info {
                // names aren't equal, create the NSEC record
                let mut record = Record::with(
                    name.clone(),
                    RecordType::DNSSEC(DNSSECRecordType::NSEC),
                    ttl,
                );
                let rdata = NSEC::new_cover_self(Authority::origin(self).clone().into(), vec);
                record.set_rdata(RData::DNSSEC(DNSSECRData::NSEC(rdata)));
                records.push(record);
            }
        }

        // insert all the nsec records
        for record in records {
            let upserted = self.upsert(record, serial);
            debug_assert!(upserted);
        }
    }

    /// Signs an RecordSet, and stores the RRSIGs in the RecordSet
    ///
    /// This will sign the RecordSet with all the registered keys in the zone
    ///
    /// # Arguments
    ///
    /// * `rr_set` - RecordSet to sign
    /// * `secure_keys` - Set of keys to use to sign the RecordSet, see `self.signers()`
    /// * `zone_ttl` - the zone TTL, see `self.minimum_ttl()`
    /// * `zone_class` - DNSClass of the zone, see `self.zone_class()`
    #[cfg(feature = "dnssec")]
    fn sign_rrset(
        rr_set: &mut RecordSet,
        secure_keys: &[Signer],
        zone_ttl: u32,
        zone_class: DNSClass,
    ) -> DnsSecResult<()> {
        use chrono::Utc;
        use trust_dns_client::rr::dnssec::tbs;
        use trust_dns_client::rr::rdata::SIG;

        let inception = Utc::now();

        rr_set.clear_rrsigs();

        let rrsig_temp = Record::with(
            rr_set.name().clone(),
            RecordType::DNSSEC(DNSSECRecordType::RRSIG),
            zone_ttl,
        );

        for signer in secure_keys {
            debug!(
                "signing rr_set: {}, {} with: {}",
                rr_set.name(),
                rr_set.record_type(),
                signer.algorithm(),
            );

            let expiration = inception + signer.sig_duration();

            let tbs = tbs::rrset_tbs(
                rr_set.name(),
                zone_class,
                rr_set.name().num_labels(),
                rr_set.record_type(),
                signer.algorithm(),
                rr_set.ttl(),
                expiration.timestamp() as u32,
                inception.timestamp() as u32,
                signer.calculate_key_tag()?,
                signer.signer_name(),
                // TODO: this is a nasty clone... the issue is that the vec
                //  from records is of Vec<&R>, but we really want &[R]
                &rr_set
                    .records_without_rrsigs()
                    .cloned()
                    .collect::<Vec<Record>>(),
            );

            // TODO, maybe chain these with some ETL operations instead?
            let tbs = match tbs {
                Ok(tbs) => tbs,
                Err(err) => {
                    error!("could not serialize rrset to sign: {}", err);
                    continue;
                }
            };

            let signature = signer.sign(&tbs);
            let signature = match signature {
                Ok(signature) => signature,
                Err(err) => {
                    error!("could not sign rrset: {}", err);
                    continue;
                }
            };

            let mut rrsig = rrsig_temp.clone();
            rrsig.set_rdata(RData::DNSSEC(DNSSECRData::SIG(SIG::new(
                // type_covered: RecordType,
                rr_set.record_type(),
                // algorithm: Algorithm,
                signer.algorithm(),
                // num_labels: u8,
                rr_set.name().num_labels(),
                // original_ttl: u32,
                rr_set.ttl(),
                // sig_expiration: u32,
                expiration.timestamp() as u32,
                // sig_inception: u32,
                inception.timestamp() as u32,
                // key_tag: u16,
                signer.calculate_key_tag()?,
                // signer_name: Name,
                signer.signer_name().clone(),
                // sig: Vec<u8>
                signature,
            ))));

            rr_set.insert_rrsig(rrsig);
        }

        Ok(())
    }

    /// Signs any records in the zone that have serial numbers greater than or equal to `serial`
    #[cfg(feature = "dnssec")]
    fn sign_zone(&mut self) -> DnsSecResult<()> {
        debug!("signing zone: {}", self.origin);

        let minimum_ttl = self.minimum_ttl();
        let secure_keys = &self.secure_keys;
        let records = &mut self.records;

        // TODO: should this be an error?
        if secure_keys.is_empty() {
            warn!("attempt to sign_zone for dnssec, but no keys available!")
        }

        // sign all record_sets, as of 0.12.1 this includes DNSKEY
        for rr_set_orig in records.values_mut() {
            // because the rrset is an Arc, it must be cloned before mutated
            let rr_set = Arc::make_mut(rr_set_orig);
            Self::sign_rrset(rr_set, secure_keys, minimum_ttl, self.class)?;
        }

        Ok(())
    }
}

/// Gets the next search name, and returns the RecordType that it originated from
fn maybe_next_name(
    record_set: &RecordSet,
    query_type: RecordType,
) -> Option<(LowerName, RecordType)> {
    match (record_set.record_type(), query_type) {
        // ANAME is similar to CNAME,
        //  unlike CNAME, it is only something that continue to additional processing if the
        //  the query was for address (A, AAAA, or ANAME itself) record types.
        (t @ RecordType::ANAME, RecordType::A)
        | (t @ RecordType::ANAME, RecordType::AAAA)
        | (t @ RecordType::ANAME, RecordType::ANAME) => record_set
            .records_without_rrsigs()
            .next()
            .and_then(|record| record.rdata().as_aname().cloned())
            .map(LowerName::from)
            .map(|name| (name, t)),
        (t @ RecordType::NS, RecordType::NS) => record_set
            .records_without_rrsigs()
            .next()
            .and_then(|record| record.rdata().as_ns().cloned())
            .map(LowerName::from)
            .map(|name| (name, t)),
        // CNAME will continue to additional processing for any query type
        (t @ RecordType::CNAME, _) => record_set
            .records_without_rrsigs()
            .next()
            .and_then(|record| record.rdata().as_cname().cloned())
            .map(LowerName::from)
            .map(|name| (name, t)),
        (t @ RecordType::MX, RecordType::MX) => record_set
            .records_without_rrsigs()
            .next()
            .and_then(|record| record.rdata().as_mx())
            .map(|mx| mx.exchange().clone())
            .map(LowerName::from)
            .map(|name| (name, t)),
        (t @ RecordType::SRV, RecordType::SRV) => record_set
            .records_without_rrsigs()
            .next()
            .and_then(|record| record.rdata().as_srv())
            .map(|srv| srv.target().clone())
            .map(LowerName::from)
            .map(|name| (name, t)),
        // other additional collectors can be added here can be added here
        _ => None,
    }
}

impl Authority for InMemoryAuthority {
    type Lookup = AuthLookup;
    type LookupFuture = future::Ready<Result<Self::Lookup, LookupError>>;

    /// What type is this zone
    fn zone_type(&self) -> ZoneType {
        self.zone_type
    }

    /// Return true if AXFR is allowed
    fn is_axfr_allowed(&self) -> bool {
        self.allow_axfr
    }

    /// Takes the UpdateMessage, extracts the Records, and applies the changes to the record set.
    ///
    /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    ///
    /// 3.4 - Process Update Section
    ///
    ///   Next, the Update Section is processed as follows.
    ///
    /// 3.4.2 - Update
    ///
    ///   The Update Section is parsed into RRs and these RRs are processed in
    ///   order.
    ///
    /// 3.4.2.1. If any system failure (such as an out of memory condition,
    ///   or a hardware error in persistent storage) occurs during the
    ///   processing of this section, signal SERVFAIL to the requestor and undo
    ///   all updates applied to the zone during this transaction.
    ///
    /// 3.4.2.2. Any Update RR whose CLASS is the same as ZCLASS is added to
    ///   the zone.  In case of duplicate RDATAs (which for SOA RRs is always
    ///   the case, and for WKS RRs is the case if the ADDRESS and PROTOCOL
    ///   fields both match), the Zone RR is replaced by Update RR.  If the
    ///   TYPE is SOA and there is no Zone SOA RR, or the new SOA.SERIAL is
    ///   lower (according to [RFC1982]) than or equal to the current Zone SOA
    ///   RR's SOA.SERIAL, the Update RR is ignored.  In the case of a CNAME
    ///   Update RR and a non-CNAME Zone RRset or vice versa, ignore the CNAME
    ///   Update RR, otherwise replace the CNAME Zone RR with the CNAME Update
    ///   RR.
    ///
    /// 3.4.2.3. For any Update RR whose CLASS is ANY and whose TYPE is ANY,
    ///   all Zone RRs with the same NAME are deleted, unless the NAME is the
    ///   same as ZNAME in which case only those RRs whose TYPE is other than
    ///   SOA or NS are deleted.  For any Update RR whose CLASS is ANY and
    ///   whose TYPE is not ANY all Zone RRs with the same NAME and TYPE are
    ///   deleted, unless the NAME is the same as ZNAME in which case neither
    ///   SOA or NS RRs will be deleted.
    ///
    /// 3.4.2.4. For any Update RR whose class is NONE, any Zone RR whose
    ///   NAME, TYPE, RDATA and RDLENGTH are equal to the Update RR is deleted,
    ///   unless the NAME is the same as ZNAME and either the TYPE is SOA or
    ///   the TYPE is NS and the matching Zone RR is the only NS remaining in
    ///   the RRset, in which case this Update RR is ignored.
    ///
    /// 3.4.2.5. Signal NOERROR to the requestor.
    /// ```
    ///
    /// # Arguments
    ///
    /// * `update` - The `UpdateMessage` records will be extracted and used to perform the update
    ///              actions as specified in the above RFC.
    ///
    /// # Return value
    ///
    /// true if any of additions, updates or deletes were made to the zone, false otherwise. Err is
    ///  returned in the case of bad data, etc.
    fn update(&mut self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName {
        &self.origin
    }

    /// Looks up all Resource Records matching the giving `Name` and `RecordType`.
    ///
    /// # Arguments
    ///
    /// * `name` - The `Name`, label, to lookup.
    /// * `rtype` - The `RecordType`, to lookup. `RecordType::ANY` will return all records matching
    ///             `name`. `RecordType::AXFR` will return all record types except `RecordType::SOA`
    ///             due to the requirements that on zone transfers the `RecordType::SOA` must both
    ///             precede and follow all other records.
    /// * `is_secure` - If the DO bit is set on the EDNS OPT record, then return RRSIGs as well.
    ///
    /// # Return value
    ///
    /// None if there are no matching records, otherwise a `Vec` containing the found records.
    fn lookup(
        &self,
        name: &LowerName,
        query_type: RecordType,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        // Collect the records from each rr_set
        let (result, additionals): (LookupResult<LookupRecords>, Option<LookupRecords>) =
            match query_type {
                RecordType::AXFR | RecordType::ANY => {
                    let result = AnyRecords::new(
                        is_secure,
                        supported_algorithms,
                        self.records.values().cloned().collect(),
                        query_type,
                        name.clone(),
                    );
                    (Ok(LookupRecords::AnyRecords(result)), None)
                }
                _ => {
                    // perform the lookup
                    let answer =
                        self.inner_lookup(name, query_type, is_secure, supported_algorithms);

                    // evaluate any cnames for additional inclusion
                    let additionals_root_chain_type: Option<(_, _)> = answer
                        .as_ref()
                        .and_then(|a| maybe_next_name(&*a, query_type))
                        .and_then(|(search_name, search_type)| {
                            self.additional_search(
                                query_type,
                                search_name,
                                search_type,
                                is_secure,
                                supported_algorithms,
                            )
                            .map(|adds| (adds, search_type))
                        });

                    // if the chain started with an ANAME, take the A or AAAA record from the list
                    let (additionals, answer) =
                        match (additionals_root_chain_type, answer, query_type) {
                            (
                                Some((additionals, RecordType::ANAME)),
                                Some(answer),
                                RecordType::A,
                            )
                            | (
                                Some((additionals, RecordType::ANAME)),
                                Some(answer),
                                RecordType::AAAA,
                            ) => {
                                // This should always be true...
                                debug_assert_eq!(answer.record_type(), RecordType::ANAME);

                                // in the case of ANAME the final record should be the A or AAAA record
                                let (rdatas, a_aaaa_ttl) = {
                                    let last_record = additionals.last();
                                    let a_aaaa_ttl =
                                        last_record.map_or(u32::max_value(), |r| r.ttl());

                                    // grap the rdatas
                                    let rdatas: Option<Vec<RData>> = last_record
                                        .and_then(|record| match record.record_type() {
                                            RecordType::A | RecordType::AAAA => {
                                                // the RRSIGS will be useless since we're changing the record type
                                                Some(record.records_without_rrsigs())
                                            }
                                            _ => None,
                                        })
                                        .map(|records| {
                                            records.map(Record::rdata).cloned().collect::<Vec<_>>()
                                        });

                                    (rdatas, a_aaaa_ttl)
                                };

                                // now build up a new RecordSet
                                //   the name comes from the ANAME record
                                //   according to the rfc the ttl is from the ANAME
                                //   TODO: technically we should take the min of the potential CNAME chain
                                let ttl = answer.ttl().min(a_aaaa_ttl);
                                let mut new_answer = RecordSet::new(answer.name(), query_type, ttl);

                                for rdata in rdatas.into_iter().flatten() {
                                    new_answer.add_rdata(rdata);
                                }

                                // if DNSSEC is enabled, and the request had the DO set, sign the recordset
                                #[cfg(feature = "dnssec")]
                                {
                                    // ANAME's are constructed on demand, so need to be signed before return
                                    if is_secure {
                                        Self::sign_rrset(
                                            &mut new_answer,
                                            self.secure_keys(),
                                            self.minimum_ttl(),
                                            self.class(),
                                        )
                                        // rather than failing the request, we'll just warn
                                        .map_err(|e| warn!("failed to sign ANAME record: {}", e))
                                        .ok();
                                    }
                                }

                                // prepend answer to additionals here (answer is the ANAME record)
                                let additionals = std::iter::once(answer)
                                    .chain(additionals.into_iter())
                                    .collect();

                                // return the new answer
                                //   because the searched set was an Arc, we need to arc too
                                (Some(additionals), Some(Arc::new(new_answer)))
                            }
                            (Some((additionals, _)), answer, _) => (Some(additionals), answer),
                            (None, answer, _) => (None, answer),
                        };

                    // map the answer to a result
                    let answer = answer
                        .map_or(Err(LookupError::from(ResponseCode::NXDomain)), |rr_set| {
                            Ok(LookupRecords::new(is_secure, supported_algorithms, rr_set))
                        });

                    let additionals = additionals
                        .map(|a| LookupRecords::many(is_secure, supported_algorithms, a));

                    (answer, additionals)
                }
            };

        // This is annoying. The 1035 spec literally specifies that most DNS authorities would want to store
        //   records in a list except when there are a lot of records. But this makes indexed lookups by name+type
        //   always return empty sets. This is only important in the negative case, where other DNS authorities
        //   generally return NoError and no results when other types exist at the same name. bah.
        // TODO: can we get rid of this?
        let result = match result {
            Err(LookupError::ResponseCode(ResponseCode::NXDomain)) => {
                if self
                    .records
                    .keys()
                    .any(|key| key.name() == name || name.zone_of(key.name()))
                {
                    return Box::pin(future::err(LookupError::NameExists));
                } else {
                    return Box::pin(future::err(LookupError::from(ResponseCode::NXDomain)));
                }
            }
            Err(e) => return Box::pin(future::err(e)),
            o => o,
        };

        Box::pin(future::ready(
            result.map(|answers| AuthLookup::answers(answers, additionals)),
        ))
    }

    fn search(
        &self,
        query: &LowerQuery,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        debug!("searching InMemoryAuthority for: {}", query);

        let lookup_name = query.name();
        let record_type: RecordType = query.query_type();

        // if this is an AXFR zone transfer, verify that this is either the slave or master
        //  for AXFR the first and last record must be the SOA
        if RecordType::AXFR == record_type {
            // TODO: support more advanced AXFR options
            if !self.is_axfr_allowed() {
                return Box::pin(future::err(LookupError::from(ResponseCode::Refused)));
            }

            match self.zone_type() {
                ZoneType::Master | ZoneType::Slave => (),
                // TODO: Forward?
                _ => return Box::pin(future::err(LookupError::from(ResponseCode::NXDomain))),
            }
        }

        // perform the actual lookup
        match record_type {
            RecordType::SOA => {
                Box::pin(self.lookup(self.origin(), record_type, is_secure, supported_algorithms))
            }
            RecordType::AXFR => {
                // TODO: shouldn't these SOA's be secure? at least the first, perhaps not the last?
                let lookup = future::try_join3(
                    // TODO: maybe switch this to be an soa_inner type call?
                    self.soa_secure(is_secure, supported_algorithms),
                    self.soa(),
                    self.lookup(lookup_name, record_type, is_secure, supported_algorithms),
                )
                .map_ok(|(start_soa, end_soa, records)| match start_soa {
                    l @ AuthLookup::Empty => l,
                    start_soa => AuthLookup::AXFR {
                        start_soa: start_soa.unwrap_records(),
                        records: records.unwrap_records(),
                        end_soa: end_soa.unwrap_records(),
                    },
                });

                Box::pin(lookup)
            }
            // A standard Lookup path
            _ => Box::pin(self.lookup(lookup_name, record_type, is_secure, supported_algorithms)),
        }
    }

    /// Return the NSEC records based on the given name
    ///
    /// # Arguments
    ///
    /// * `name` - given this name (i.e. the lookup name), return the NSEC record that is less than
    ///            this
    /// * `is_secure` - if true then it will return RRSIG records as well
    #[cfg(feature = "dnssec")]
    fn get_nsec_records(
        &self,
        name: &LowerName,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        fn is_nsec_rrset(rr_set: &RecordSet) -> bool {
            rr_set.record_type() == RecordType::DNSSEC(DNSSECRecordType::NSEC)
        }

        // TODO: need a BorrowdRrKey
        let rr_key = RrKey::new(name.clone(), RecordType::DNSSEC(DNSSECRecordType::NSEC));
        let no_data = self
            .records
            .get(&rr_key)
            .map(|rr_set| LookupRecords::new(is_secure, supported_algorithms, rr_set.clone()));

        if let Some(no_data) = no_data {
            return Box::pin(future::ready(Ok(no_data.into())));
        }

        let get_closest_nsec = |name: &LowerName| -> Option<Arc<RecordSet>> {
            self.records
                .values()
                .rev()
                .filter(|rr_set| is_nsec_rrset(rr_set))
                // the name must be greater than the name in the nsec
                .filter(|rr_set| *name >= rr_set.name().into())
                // now find the next record where the covered name is greater
                .find(|rr_set| {
                    // there should only be one record
                    rr_set
                        .records(false, SupportedAlgorithms::default())
                        .next()
                        .and_then(|r| r.rdata().as_dnssec())
                        .and_then(DNSSECRData::as_nsec)
                        .map_or(false, |r| {
                            // the search name is less than the next NSEC record
                            *name < r.next_domain_name().into() ||
                            // this is the last record, and wraps to the beginning of the zone
                            r.next_domain_name() < rr_set.name()
                        })
                })
                .cloned()
        };

        let closest_proof = get_closest_nsec(name);

        // we need the wildcard proof, but make sure that it's still part of the zone.
        let wildcard = name.base_name();
        let wildcard = if self.origin().zone_of(&wildcard) {
            wildcard
        } else {
            self.origin().clone()
        };

        // don't duplicate the record...
        let wildcard_proof = if wildcard != *name {
            get_closest_nsec(&wildcard)
        } else {
            None
        };

        let proofs = match (closest_proof, wildcard_proof) {
            (Some(closest_proof), Some(wildcard_proof)) => {
                // dedup with the wildcard proof
                if wildcard_proof != closest_proof {
                    vec![wildcard_proof, closest_proof]
                } else {
                    vec![closest_proof]
                }
            }
            (None, Some(proof)) | (Some(proof), None) => vec![proof],
            (None, None) => vec![],
        };

        Box::pin(future::ready(Ok(LookupRecords::many(
            is_secure,
            supported_algorithms,
            proofs,
        )
        .into())))
    }

    #[cfg(not(feature = "dnssec"))]
    fn get_nsec_records(
        &self,
        _name: &LowerName,
        _is_secure: bool,
        _supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        Box::pin(future::ok(AuthLookup::default()))
    }

    #[cfg(feature = "dnssec")]
    fn add_update_auth_key(&mut self, name: Name, key: KEY) -> DnsSecResult<()> {
        let rdata = RData::DNSSEC(DNSSECRData::KEY(key));
        // TODO: what TTL?
        let record = Record::from_rdata(name, 86400, rdata);

        let serial = self.serial();
        if self.upsert(record, serial) {
            Ok(())
        } else {
            Err("failed to add auth key".into())
        }
    }

    #[cfg(not(feature = "dnssec"))]
    fn add_update_auth_key(&mut self, _name: Name, _key: KEY) -> DnsSecResult<()> {
        Err("DNSSEC was not enabled during compilation.".into())
    }

    /// By adding a secure key, this will implicitly enable dnssec for the zone.
    ///
    /// # Arguments
    ///
    /// * `signer` - Signer with associated private key
    #[cfg(feature = "dnssec")]
    fn add_zone_signing_key(&mut self, signer: Signer) -> DnsSecResult<()> {
        // also add the key to the zone
        let zone_ttl = self.minimum_ttl();
        let dnskey = signer.key().to_dnskey(signer.algorithm())?;
        let dnskey = Record::from_rdata(
            self.origin.clone().into(),
            zone_ttl,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
        );

        // TODO: also generate the CDS and CDNSKEY
        let serial = self.serial();
        self.upsert(dnskey, serial);
        self.secure_keys.push(signer);
        Ok(())
    }

    /// This will fail, the dnssec feature must be enabled
    #[cfg(not(feature = "dnssec"))]
    fn add_zone_signing_key(&mut self, _signer: Signer) -> DnsSecResult<()> {
        Err("DNSSEC was not enabled during compilation.".into())
    }

    /// (Re)generates the nsec records, increments the serial number and signs the zone
    #[cfg(feature = "dnssec")]
    fn secure_zone(&mut self) -> DnsSecResult<()> {
        // TODO: only call nsec_zone after adds/deletes
        // needs to be called before incrementing the soa serial, to make sure IXFR works properly
        self.nsec_zone();

        // need to resign any records at the current serial number and bump the number.
        // first bump the serial number on the SOA, so that it is resigned with the new serial.
        self.increment_soa_serial();

        // TODO: should we auto sign here? or maybe up a level...
        self.sign_zone()
    }

    /// (Re)generates the nsec records, increments the serial number and signs the zone
    #[cfg(not(feature = "dnssec"))]
    fn secure_zone(&mut self) -> DnsSecResult<()> {
        Err("DNSSEC was not enabled during compilation.".into())
    }
}
