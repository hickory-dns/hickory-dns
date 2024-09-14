// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! All authority related types

#[cfg(feature = "dnssec")]
use std::collections::{hash_map::Entry, HashMap};
#[cfg(all(feature = "dnssec", feature = "testing"))]
use std::ops::Deref;
use std::{
    collections::{BTreeMap, HashSet},
    ops::DerefMut,
    sync::Arc,
};

use cfg_if::cfg_if;
#[cfg(feature = "dnssec")]
use time::OffsetDateTime;
use tracing::{debug, error, warn};

use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

#[cfg(feature = "dnssec")]
use crate::{
    authority::{DnssecAuthority, Nsec3QueryInfo},
    config::dnssec::NxProofKind,
    proto::{
        error::ProtoResult,
        rr::dnssec::{
            rdata::{key::KEY, DNSSECRData, NSEC, NSEC3, NSEC3PARAM},
            DnsSecResult, Nsec3HashAlgorithm, SigSigner, SupportedAlgorithms,
        },
    },
};

use crate::{
    authority::{
        AnyRecords, AuthLookup, Authority, LookupControlFlow, LookupError, LookupOptions,
        LookupRecords, MessageRequest, UpdateResult, ZoneType,
    },
    proto::{
        op::ResponseCode,
        rr::{rdata::SOA, DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType, RrKey},
    },
    server::RequestInfo,
};

/// InMemoryAuthority is responsible for storing the resource records for a particular zone.
///
/// Authorities default to DNSClass IN. The ZoneType specifies if this should be treated as the
/// start of authority for the zone, is a Secondary, or a cached zone.
pub struct InMemoryAuthority {
    origin: LowerName,
    class: DNSClass,
    zone_type: ZoneType,
    allow_axfr: bool,
    inner: RwLock<InnerInMemory>,
    #[cfg(feature = "dnssec")]
    nx_proof_kind: Option<NxProofKind>,
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
    /// * `nx_proof_kind` - The kind of non-existence proof to be used by the server.
    ///
    /// # Return value
    ///
    /// The new `Authority`.
    pub fn new(
        origin: Name,
        records: BTreeMap<RrKey, RecordSet>,
        zone_type: ZoneType,
        allow_axfr: bool,
        #[cfg(feature = "dnssec")] nx_proof_kind: Option<NxProofKind>,
    ) -> Result<Self, String> {
        let mut this = Self::empty(
            origin.clone(),
            zone_type,
            allow_axfr,
            #[cfg(feature = "dnssec")]
            nx_proof_kind,
        );
        let inner = this.inner.get_mut();

        // SOA must be present
        let serial = records
            .iter()
            .find(|(key, _)| key.record_type == RecordType::SOA)
            .and_then(|(_, rrset)| rrset.records_without_rrsigs().next())
            .map(Record::data)
            .and_then(RData::as_soa)
            .map(SOA::serial)
            .ok_or_else(|| format!("SOA record must be present: {origin}"))?;

        let iter = records.into_values();

        // add soa to the records
        for rrset in iter {
            let name = rrset.name().clone();
            let rr_type = rrset.record_type();

            for record in rrset.records_without_rrsigs() {
                if !inner.upsert(record.clone(), serial, this.class) {
                    return Err(format!(
                        "Failed to insert {name} {rr_type} to zone: {origin}"
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
    pub fn empty(
        origin: Name,
        zone_type: ZoneType,
        allow_axfr: bool,
        #[cfg(feature = "dnssec")] nx_proof_kind: Option<NxProofKind>,
    ) -> Self {
        Self {
            origin: LowerName::new(&origin),
            class: DNSClass::IN,
            zone_type,
            allow_axfr,
            inner: RwLock::new(InnerInMemory::default()),

            #[cfg(feature = "dnssec")]
            nx_proof_kind,
        }
    }

    /// The DNSClass of this zone
    pub fn class(&self) -> DNSClass {
        self.class
    }

    /// Allow AXFR's (zone transfers)
    #[cfg(any(test, feature = "testing"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
    pub fn set_allow_axfr(&mut self, allow_axfr: bool) {
        self.allow_axfr = allow_axfr;
    }

    /// Clears all records (including SOA, etc)
    pub fn clear(&mut self) {
        self.inner.get_mut().records.clear()
    }

    /// Retrieve the Signer, which contains the private keys, for this zone
    #[cfg(all(feature = "dnssec", feature = "testing"))]
    pub async fn secure_keys(&self) -> impl Deref<Target = [SigSigner]> + '_ {
        RwLockWriteGuard::map(self.inner.write().await, |i| i.secure_keys.as_mut_slice())
    }

    /// Get all the records
    pub async fn records(&self) -> BTreeMap<RrKey, Arc<RecordSet>> {
        let records = RwLockReadGuard::map(self.inner.read().await, |i| &i.records);
        records.clone()
    }

    /// Get a mutable reference to the records
    pub async fn records_mut(
        &self,
    ) -> impl DerefMut<Target = BTreeMap<RrKey, Arc<RecordSet>>> + '_ {
        RwLockWriteGuard::map(self.inner.write().await, |i| &mut i.records)
    }

    /// Get a mutable reference to the records
    pub fn records_get_mut(&mut self) -> &mut BTreeMap<RrKey, Arc<RecordSet>> {
        &mut self.inner.get_mut().records
    }

    /// Returns the minimum ttl (as used in the SOA record)
    pub async fn minimum_ttl(&self) -> u32 {
        self.inner.read().await.minimum_ttl(self.origin())
    }

    /// get the current serial number for the zone.
    pub async fn serial(&self) -> u32 {
        self.inner.read().await.serial(self.origin())
    }

    #[cfg(any(feature = "dnssec", feature = "sqlite"))]
    #[allow(unused)]
    pub(crate) async fn increment_soa_serial(&self) -> u32 {
        self.inner
            .write()
            .await
            .increment_soa_serial(self.origin(), self.class)
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
    pub async fn upsert(&self, record: Record, serial: u32) -> bool {
        self.inner.write().await.upsert(record, serial, self.class)
    }

    /// Non-async version of upsert when behind a mutable reference.
    pub fn upsert_mut(&mut self, record: Record, serial: u32) -> bool {
        self.inner.get_mut().upsert(record, serial, self.class)
    }

    /// Add a (Sig0) key that is authorized to perform updates against this authority
    #[cfg(feature = "dnssec")]
    fn inner_add_update_auth_key(
        inner: &mut InnerInMemory,

        name: Name,
        key: KEY,
        origin: &LowerName,
        dns_class: DNSClass,
    ) -> DnsSecResult<()> {
        let rdata = RData::DNSSEC(DNSSECRData::KEY(key));
        // TODO: what TTL?
        let record = Record::from_rdata(name, 86400, rdata);

        let serial = inner.serial(origin);
        if inner.upsert(record, serial, dns_class) {
            Ok(())
        } else {
            Err("failed to add auth key".into())
        }
    }

    /// Non-async method of add_update_auth_key when behind a mutable reference
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    pub fn add_update_auth_key_mut(&mut self, name: Name, key: KEY) -> DnsSecResult<()> {
        let Self {
            ref origin,
            ref mut inner,
            class,
            ..
        } = self;

        Self::inner_add_update_auth_key(inner.get_mut(), name, key, origin, *class)
    }

    /// By adding a secure key, this will implicitly enable dnssec for the zone.
    ///
    /// # Arguments
    ///
    /// * `signer` - Signer with associated private key
    #[cfg(feature = "dnssec")]
    fn inner_add_zone_signing_key(
        inner: &mut InnerInMemory,
        signer: SigSigner,
        origin: &LowerName,
        dns_class: DNSClass,
    ) -> DnsSecResult<()> {
        // also add the key to the zone
        let zone_ttl = inner.minimum_ttl(origin);
        let dnskey = signer.key().to_dnskey(signer.algorithm())?;
        let dnskey = Record::from_rdata(
            origin.clone().into(),
            zone_ttl,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
        );

        // TODO: also generate the CDS and CDNSKEY
        let serial = inner.serial(origin);
        inner.upsert(dnskey, serial, dns_class);
        inner.secure_keys.push(signer);
        Ok(())
    }

    /// Non-async method of add_zone_signing_key when behind a mutable reference
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    pub fn add_zone_signing_key_mut(&mut self, signer: SigSigner) -> DnsSecResult<()> {
        let Self {
            ref origin,
            ref mut inner,
            class,
            ..
        } = self;

        Self::inner_add_zone_signing_key(inner.get_mut(), signer, origin, *class)
    }

    /// (Re)generates the nsec records, increments the serial number and signs the zone
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    pub fn secure_zone_mut(&mut self) -> DnsSecResult<()> {
        let Self {
            ref origin,
            ref mut inner,
            ..
        } = self;
        inner
            .get_mut()
            .secure_zone_mut(origin, self.class, self.nx_proof_kind.as_ref())
    }

    /// (Re)generates the nsec records, increments the serial number and signs the zone
    #[cfg(not(feature = "dnssec"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    pub fn secure_zone_mut(&mut self) -> Result<(), &str> {
        Err("DNSSEC was not enabled during compilation.")
    }
}

#[derive(Default)]
struct InnerInMemory {
    records: BTreeMap<RrKey, Arc<RecordSet>>,
    // Private key mapped to the Record of the DNSKey
    //  TODO: these private_keys should be stored securely. Ideally, we have keys only stored per
    //   server instance, but that requires requesting updates from the parent zone, which may or
    //   may not support dynamic updates to register the new key... Hickory DNS will provide support
    //   for this, in some form, perhaps alternate root zones...
    #[cfg(feature = "dnssec")]
    secure_keys: Vec<SigSigner>,
}

impl InnerInMemory {
    /// Retrieve the Signer, which contains the private keys, for this zone
    #[cfg(feature = "dnssec")]
    fn secure_keys(&self) -> &[SigSigner] {
        &self.secure_keys
    }

    // /// Get all the records
    // fn records(&self) -> &BTreeMap<RrKey, Arc<RecordSet>> {
    //     &self.records
    // }

    // /// Get a mutable reference to the records
    // fn records_mut(&mut self) -> &mut BTreeMap<RrKey, Arc<RecordSet>> {
    //     &mut self.records
    // }

    fn inner_soa(&self, origin: &LowerName) -> Option<&SOA> {
        // TODO: can't there be an RrKeyRef?
        let rr_key = RrKey::new(origin.clone(), RecordType::SOA);

        self.records
            .get(&rr_key)
            .and_then(|rrset| rrset.records_without_rrsigs().next())
            .map(Record::data)
            .and_then(RData::as_soa)
    }

    /// Returns the minimum ttl (as used in the SOA record)
    fn minimum_ttl(&self, origin: &LowerName) -> u32 {
        let soa = self.inner_soa(origin);

        let soa = match soa {
            Some(soa) => soa,
            None => {
                error!("could not lookup SOA for authority: {}", origin);
                return 0;
            }
        };

        soa.minimum()
    }

    /// get the current serial number for the zone.
    fn serial(&self, origin: &LowerName) -> u32 {
        let soa = self.inner_soa(origin);

        let soa = match soa {
            Some(soa) => soa,
            None => {
                error!("could not lookup SOA for authority: {}", origin);
                return 0;
            }
        };

        soa.serial()
    }

    fn inner_lookup(
        &self,
        name: &LowerName,
        record_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Option<Arc<RecordSet>> {
        // this range covers all the records for any of the RecordTypes at a given label.
        let start_range_key = RrKey::new(name.clone(), RecordType::Unknown(u16::MIN));
        let end_range_key = RrKey::new(name.clone(), RecordType::Unknown(u16::MAX));

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
            None => self.inner_lookup_wildcard(name, record_type, lookup_options),
            l => l.cloned(),
        }
    }

    fn inner_lookup_wildcard(
        &self,
        name: &LowerName,
        record_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Option<Arc<RecordSet>> {
        // if this is a wildcard or a root, both should break continued lookups
        let wildcard = if name.is_wildcard() || name.is_root() {
            return None;
        } else {
            name.clone().into_wildcard()
        };

        #[allow(clippy::needless_late_init)]
        self.inner_lookup(&wildcard, record_type, lookup_options)
            // we need to change the name to the query name in the result set since this was a wildcard
            .map(|rrset| {
                let mut new_answer =
                    RecordSet::with_ttl(Name::from(name), rrset.record_type(), rrset.ttl());

                let records;
                let _rrsigs: Vec<&Record>;
                cfg_if! {
                    if #[cfg(feature = "dnssec")] {
                        let (records_tmp, rrsigs_tmp) = rrset
                            .records(lookup_options.dnssec_ok(), lookup_options.supported_algorithms())
                            .partition(|r| r.record_type() != RecordType::RRSIG);
                        records = records_tmp;
                        _rrsigs = rrsigs_tmp;
                    } else {
                        let (records_tmp, rrsigs_tmp) = (rrset.records_without_rrsigs(), Vec::with_capacity(0));
                        records = records_tmp;
                        _rrsigs = rrsigs_tmp;
                    }
                };

                for record in records {
                    new_answer.add_rdata(record.data().clone());
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
    /// * original_name - the original name that was being looked up
    /// * query_type - original type in the request query
    /// * next_name - the name from the CNAME, ANAME, MX, etc. record that is being searched
    /// * search_type - the root search type, ANAME, CNAME, MX, i.e. the beginning of the chain
    fn additional_search(
        &self,
        original_name: &LowerName,
        original_query_type: RecordType,
        next_name: LowerName,
        _search_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Option<Vec<Arc<RecordSet>>> {
        let mut additionals: Vec<Arc<RecordSet>> = vec![];

        // if it's a CNAME or other forwarding record, we'll be adding additional records based on the query_type
        let mut query_types_arr = [original_query_type; 2];
        let query_types: &[RecordType] = match original_query_type {
            RecordType::ANAME | RecordType::NS | RecordType::MX | RecordType::SRV => {
                query_types_arr = [RecordType::A, RecordType::AAAA];
                &query_types_arr[..]
            }
            _ => &query_types_arr[..1],
        };

        for query_type in query_types {
            // loop and collect any additional records to send

            // Track the names we've looked up for this query type.
            let mut names = HashSet::new();

            // If we're just going to repeat the same query then bail out.
            if query_type == &original_query_type {
                names.insert(original_name.clone());
            }

            let mut next_name = Some(next_name.clone());
            while let Some(search) = next_name.take() {
                // If we've already looked up this name then bail out.
                if names.contains(&search) {
                    break;
                }

                let additional = self.inner_lookup(&search, *query_type, lookup_options);
                names.insert(search);

                if let Some(additional) = additional {
                    // assuming no crazy long chains...
                    if !additionals.contains(&additional) {
                        additionals.push(additional.clone());
                    }

                    next_name =
                        maybe_next_name(&additional, *query_type).map(|(name, _search_type)| name);
                }
            }
        }

        if !additionals.is_empty() {
            Some(additionals)
        } else {
            None
        }
    }

    #[cfg(any(feature = "dnssec", feature = "sqlite"))]
    fn increment_soa_serial(&mut self, origin: &LowerName, dns_class: DNSClass) -> u32 {
        // we'll remove the SOA and then replace it
        let rr_key = RrKey::new(origin.clone(), RecordType::SOA);
        let record = self
            .records
            .remove(&rr_key)
            // TODO: there should be an unwrap on rrset, but it's behind Arc
            .and_then(|rrset| rrset.records_without_rrsigs().next().cloned());

        let mut record = if let Some(record) = record {
            record
        } else {
            error!("could not lookup SOA for authority: {}", origin);
            return 0;
        };

        let serial = if let RData::SOA(ref mut soa_rdata) = record.data_mut() {
            soa_rdata.increment_serial();
            soa_rdata.serial()
        } else {
            panic!("This was not an SOA record"); // valid panic, never should happen
        };

        self.upsert(record, serial, dns_class);
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
    fn upsert(&mut self, record: Record, serial: u32, dns_class: DNSClass) -> bool {
        if dns_class != record.dns_class() {
            warn!(
                "mismatched dns_class on record insert, zone: {} record: {}",
                dns_class,
                record.dns_class()
            );
            return false;
        }

        #[cfg(feature = "dnssec")]
        fn is_nsec(upsert_type: RecordType, occupied_type: RecordType) -> bool {
            // NSEC is always allowed
            upsert_type == RecordType::NSEC
                || upsert_type == RecordType::NSEC3
                || occupied_type == RecordType::NSEC
                || occupied_type == RecordType::NSEC3
        }

        #[cfg(not(feature = "dnssec"))]
        fn is_nsec(_upsert_type: RecordType, _occupied_type: RecordType) -> bool {
            // TODO: we should make the DNSSEC RecordTypes always visible
            false
        }

        /// returns true if an only if the label can not co-occupy space with the checked type
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
        }

        // check that CNAME and ANAME is either not already present, or no other records are if it's a CNAME
        let start_range_key = RrKey::new(record.name().into(), RecordType::Unknown(u16::MIN));
        let end_range_key = RrKey::new(record.name().into(), RecordType::Unknown(u16::MAX));

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

        let rr_key = RrKey::new(record.name().into(), record.record_type());
        let records: &mut Arc<RecordSet> = self.records.entry(rr_key).or_insert_with(|| {
            Arc::new(RecordSet::new(record.name(), record.record_type(), serial))
        });

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
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    fn secure_zone_mut(
        &mut self,
        origin: &LowerName,
        dns_class: DNSClass,
        nx_proof_kind: Option<&NxProofKind>,
    ) -> DnsSecResult<()> {
        // TODO: only call nsec_zone after adds/deletes
        // needs to be called before incrementing the soa serial, to make sure IXFR works properly
        match nx_proof_kind {
            Some(NxProofKind::Nsec) => self.nsec_zone(origin, dns_class),
            Some(NxProofKind::Nsec3 {
                algorithm,
                salt,
                iterations,
            }) => self.nsec3_zone(origin, dns_class, *algorithm, salt, *iterations)?,
            None => (),
        }

        // need to resign any records at the current serial number and bump the number.
        // first bump the serial number on the SOA, so that it is resigned with the new serial.
        self.increment_soa_serial(origin, dns_class);

        // TODO: should we auto sign here? or maybe up a level...
        self.sign_zone(origin, dns_class)
    }

    /// Dummy implementation for when DNSSEC is disabled.
    #[cfg(feature = "dnssec")]
    fn nsec_zone(&mut self, origin: &LowerName, dns_class: DNSClass) {
        // only create nsec records for secure zones
        if self.secure_keys.is_empty() {
            return;
        }
        debug!("generating nsec records: {}", origin);

        // first remove all existing nsec records
        let delete_keys: Vec<RrKey> = self
            .records
            .keys()
            .filter(|k| k.record_type == RecordType::NSEC)
            .cloned()
            .collect();

        for key in delete_keys {
            self.records.remove(&key);
        }

        // now go through and generate the nsec records
        let ttl = self.minimum_ttl(origin);
        let serial = self.serial(origin);
        let mut records: Vec<Record> = vec![];

        {
            let mut nsec_info: Option<(&Name, Vec<RecordType>)> = None;
            for key in self.records.keys() {
                match nsec_info {
                    None => nsec_info = Some((&key.name, vec![key.record_type])),
                    Some((name, ref mut vec)) if LowerName::new(name) == key.name => {
                        vec.push(key.record_type)
                    }
                    Some((name, vec)) => {
                        // names aren't equal, create the NSEC record
                        let rdata = NSEC::new_cover_self(key.name.clone().into(), vec);
                        let record = Record::from_rdata(name.clone(), ttl, rdata);
                        records.push(record.into_record_of_rdata());

                        // new record...
                        nsec_info = Some((&key.name, vec![key.record_type]))
                    }
                }
            }

            // the last record
            if let Some((name, vec)) = nsec_info {
                // names aren't equal, create the NSEC record
                let rdata = NSEC::new_cover_self(origin.clone().into(), vec);
                let record = Record::from_rdata(name.clone(), ttl, rdata);
                records.push(record.into_record_of_rdata());
            }
        }

        // insert all the nsec records
        for record in records {
            let upserted = self.upsert(record, serial, dns_class);
            debug_assert!(upserted);
        }
    }
    #[cfg(feature = "dnssec")]
    fn nsec3_zone(
        &mut self,
        origin: &LowerName,
        dns_class: DNSClass,
        hash_alg: Nsec3HashAlgorithm,
        salt: &[u8],
        iterations: u16,
    ) -> DnsSecResult<()> {
        // FIXME: Implement collision detection.
        // only create nsec records for secure zones
        if self.secure_keys.is_empty() {
            return Ok(());
        }
        debug!("generating nsec3 records: {origin}");

        // first remove all existing nsec records
        let delete_keys = self
            .records
            .keys()
            .filter(|k| k.record_type == RecordType::NSEC3)
            .cloned()
            .collect::<Vec<_>>();

        for key in delete_keys {
            self.records.remove(&key);
        }

        // now go through and generate the nsec3 records
        let ttl = self.minimum_ttl(origin);
        let serial = self.serial(origin);
        // FIXME: Should be configurable
        let opt_out = false;

        // Store the record types of each domain name so we can generate NSEC3 records for each
        // domain name.
        let mut record_types = HashMap::new();

        for key in self.records.keys() {
            // Store the type of the current record under its domain name
            match record_types.entry(key.name.clone()) {
                Entry::Occupied(mut entry) => {
                    let (rtypes, exists): &mut (HashSet<RecordType>, bool) = entry.get_mut();
                    rtypes.insert(key.record_type);
                    *exists = true;
                }
                Entry::Vacant(entry) => {
                    entry.insert((HashSet::from([key.record_type]), true));
                }
            }

            // For every domain name between the current name and the origin, add it to
            // `record_types` without any record types. This covers all the empty non-terminals
            // that must have an NSEC3 record as well.
            let mut name = key.name.base_name();

            for _ in origin.num_labels()..name.num_labels() {
                if let Entry::Vacant(entry) = record_types.entry(name.clone()) {
                    entry.insert((HashSet::new(), false));
                }
                name = name.base_name();
            }
        }

        // Compute the hash of all the names.
        let mut record_types = record_types
            .into_iter()
            .map(|(name, (type_bit_maps, exists))| {
                let hashed_name = hash_alg.hash(salt, &name, iterations)?;
                Ok((hashed_name, (type_bit_maps, exists)))
            })
            .collect::<ProtoResult<Vec<_>>>()?;
        // Sort by hash.
        record_types.sort_by(|(a, _), (b, _)| a.as_ref().cmp(b.as_ref()));

        let mut records = vec![];

        // Generate an NSEC3 record for every name
        for (i, (hashed_name, (type_bit_maps, exists))) in record_types.iter().enumerate() {
            // Get the next hashed name following the hash order.
            let next_index = (i + 1) % record_types.len();
            let next_hashed_name = record_types[next_index].0.as_ref().to_vec();

            let rdata = NSEC3::new(
                hash_alg,
                opt_out,
                iterations,
                salt.to_vec(),
                next_hashed_name,
                type_bit_maps
                    .iter()
                    .copied()
                    .chain(exists.then_some(RecordType::RRSIG))
                    .collect(),
            );

            let name =
                origin.prepend_label(data_encoding::BASE32_DNSSEC.encode(hashed_name.as_ref()))?;

            let record = Record::from_rdata(name, ttl, rdata);
            records.push(record.into_record_of_rdata());
        }

        // Include the NSEC3PARAM record.
        let rdata = NSEC3PARAM::new(hash_alg, opt_out, iterations, salt.to_vec());
        let record = Record::from_rdata(origin.into(), ttl, rdata);
        records.push(record.into_record_of_rdata());

        // insert all the NSEC3 records.
        for record in records {
            let upserted = self.upsert(record, serial, dns_class);
            debug_assert!(upserted);
        }

        Ok(())
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
        secure_keys: &[SigSigner],
        zone_ttl: u32,
        zone_class: DNSClass,
    ) -> DnsSecResult<()> {
        use hickory_proto::rr::dnssec::TBS;

        use crate::proto::rr::dnssec::rdata::RRSIG;

        let inception = OffsetDateTime::now_utc();

        rr_set.clear_rrsigs();

        let rrsig_temp = Record::update0(rr_set.name().clone(), zone_ttl, RecordType::RRSIG);

        for signer in secure_keys {
            debug!(
                "signing rr_set: {}, {} with: {}",
                rr_set.name(),
                rr_set.record_type(),
                signer.algorithm(),
            );

            let expiration = inception + signer.sig_duration();
            let tbs = TBS::from_rrset(rr_set, zone_class, inception, expiration, signer);

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
            rrsig.set_data(RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::new(
                // type_covered: RecordType,
                rr_set.record_type(),
                // algorithm: Algorithm,
                signer.algorithm(),
                // num_labels: u8,
                rr_set.name().num_labels(),
                // original_ttl: u32,
                rr_set.ttl(),
                // sig_expiration: u32,
                expiration.unix_timestamp() as u32,
                // sig_inception: u32,
                inception.unix_timestamp() as u32,
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
    fn sign_zone(&mut self, origin: &LowerName, dns_class: DNSClass) -> DnsSecResult<()> {
        debug!("signing zone: {}", origin);

        let minimum_ttl = self.minimum_ttl(origin);
        let secure_keys = &self.secure_keys;
        let records = &mut self.records;

        // TODO: should this be an error?
        if secure_keys.is_empty() {
            warn!(
                "attempt to sign_zone {} for dnssec, but no keys available!",
                origin
            )
        }

        // sign all record_sets, as of 0.12.1 this includes DNSKEY
        for rr_set_orig in records.values_mut() {
            // because the rrset is an Arc, it must be cloned before mutated
            let rr_set = Arc::make_mut(rr_set_orig);
            Self::sign_rrset(rr_set, secure_keys, minimum_ttl, dns_class)?;
        }

        Ok(())
    }

    /// Find a record that covers the given name. This is, an NSEC3 record such that the hashed owner
    /// name of the given name falls between the record's owner name and its next hashed owner
    /// name.
    #[cfg(feature = "dnssec")]
    pub(crate) fn find_cover(
        &self,
        name: &LowerName,
        zone: &Name,
        info: &Nsec3QueryInfo<'_>,
    ) -> ProtoResult<Option<Arc<RecordSet>>> {
        let owner_name = info.get_hashed_owner_name(name, zone)?;
        let records = self
            .records
            .values()
            .filter(|rr_set| rr_set.record_type() == RecordType::NSEC3);

        // Find the record with the largest owner name such that its owner name is before the
        // hashed QNAME. If this record exist, it already covers QNAME. Otherwise, the QNAME
        // preceeds all the existing NSEC3 records' owner names, meaning that it is covered by
        // the NSEC3 record with the largest owner name.
        Ok(records
            .clone()
            .filter(|rr_set| rr_set.record_type() == RecordType::NSEC3)
            .filter(|rr_set| rr_set.name() < &*owner_name)
            .max_by_key(|rr_set| rr_set.name())
            .or_else(|| records.max_by_key(|rr_set| rr_set.name()))
            .cloned())
    }

    /// Return the next closer name and the record that matches the closest encloser of a given name.
    #[cfg(feature = "dnssec")]
    pub(crate) fn get_closest_encloser_proof(
        &self,
        name: &LowerName,
        zone: &Name,
        info: &Nsec3QueryInfo<'_>,
    ) -> ProtoResult<Option<(LowerName, Arc<RecordSet>)>> {
        let mut next_closer_name = name.clone();
        let mut closest_encloser = next_closer_name.base_name();

        while !closest_encloser.is_root() {
            let rr_key = RrKey::new(
                info.get_hashed_owner_name(&closest_encloser, zone)?,
                RecordType::NSEC3,
            );
            if let Some(rrs) = self.records.get(&rr_key) {
                return Ok(Some((next_closer_name, rrs.clone())));
            }

            next_closer_name = next_closer_name.base_name();
            closest_encloser = closest_encloser.base_name();
        }

        Ok(None)
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
            .map(Record::data)
            .and_then(RData::as_aname)
            .map(|aname| LowerName::from(&aname.0))
            .map(|name| (name, t)),
        (t @ RecordType::NS, RecordType::NS) => record_set
            .records_without_rrsigs()
            .next()
            .map(Record::data)
            .and_then(RData::as_ns)
            .map(|ns| LowerName::from(&ns.0))
            .map(|name| (name, t)),
        // CNAME will continue to additional processing for any query type
        (t @ RecordType::CNAME, _) => record_set
            .records_without_rrsigs()
            .next()
            .map(Record::data)
            .and_then(RData::as_cname)
            .map(|cname| LowerName::from(&cname.0))
            .map(|name| (name, t)),
        (t @ RecordType::MX, RecordType::MX) => record_set
            .records_without_rrsigs()
            .next()
            .map(Record::data)
            .and_then(RData::as_mx)
            .map(|mx| mx.exchange().clone())
            .map(LowerName::from)
            .map(|name| (name, t)),
        (t @ RecordType::SRV, RecordType::SRV) => record_set
            .records_without_rrsigs()
            .next()
            .map(Record::data)
            .and_then(RData::as_srv)
            .map(|srv| srv.target().clone())
            .map(LowerName::from)
            .map(|name| (name, t)),
        // other additional collectors can be added here can be added here
        _ => None,
    }
}

#[async_trait::async_trait]
impl Authority for InMemoryAuthority {
    type Lookup = AuthLookup;

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
    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
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
    async fn lookup(
        &self,
        name: &LowerName,
        query_type: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        let inner = self.inner.read().await;

        // Collect the records from each rr_set
        let (result, additionals): (LookupControlFlow<LookupRecords, _>, Option<LookupRecords>) =
            match query_type {
                RecordType::AXFR | RecordType::ANY => {
                    let result = AnyRecords::new(
                        lookup_options,
                        inner.records.values().cloned().collect(),
                        query_type,
                        name.clone(),
                    );
                    (
                        LookupControlFlow::Continue(Ok(LookupRecords::AnyRecords(result))),
                        None,
                    )
                }
                _ => {
                    // perform the lookup
                    let answer = inner.inner_lookup(name, query_type, lookup_options);

                    // evaluate any cnames for additional inclusion
                    let additionals_root_chain_type: Option<(_, _)> = answer
                        .as_ref()
                        .and_then(|a| maybe_next_name(a, query_type))
                        .and_then(|(search_name, search_type)| {
                            inner
                                .additional_search(
                                    name,
                                    query_type,
                                    search_name,
                                    search_type,
                                    lookup_options,
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
                                    let a_aaaa_ttl = last_record.map_or(u32::MAX, |r| r.ttl());

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
                                            records.map(Record::data).cloned().collect::<Vec<_>>()
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
                                    use tracing::warn;

                                    // ANAME's are constructed on demand, so need to be signed before return
                                    if lookup_options.dnssec_ok() {
                                        InnerInMemory::sign_rrset(
                                            &mut new_answer,
                                            inner.secure_keys(),
                                            inner.minimum_ttl(self.origin()),
                                            self.class(),
                                        )
                                        // rather than failing the request, we'll just warn
                                        .map_err(|e| warn!("failed to sign ANAME record: {}", e))
                                        .ok();
                                    }
                                }

                                // prepend answer to additionals here (answer is the ANAME record)
                                let additionals =
                                    std::iter::once(answer).chain(additionals).collect();

                                // return the new answer
                                //   because the searched set was an Arc, we need to arc too
                                (Some(additionals), Some(Arc::new(new_answer)))
                            }
                            (Some((additionals, _)), answer, _) => (Some(additionals), answer),
                            (None, answer, _) => (None, answer),
                        };

                    // map the answer to a result
                    let answer = answer.map_or(
                        LookupControlFlow::Continue(Err(LookupError::from(ResponseCode::NXDomain))),
                        |rr_set| {
                            LookupControlFlow::Continue(Ok(LookupRecords::new(
                                lookup_options,
                                rr_set,
                            )))
                        },
                    );

                    let additionals = additionals.map(|a| LookupRecords::many(lookup_options, a));

                    (answer, additionals)
                }
            };

        // This is annoying. The 1035 spec literally specifies that most DNS authorities would want to store
        //   records in a list except when there are a lot of records. But this makes indexed lookups by name+type
        //   always return empty sets. This is only important in the negative case, where other DNS authorities
        //   generally return NoError and no results when other types exist at the same name. bah.
        // TODO: can we get rid of this?
        use LookupControlFlow::*;
        let result = match result {
            Continue(Err(LookupError::ResponseCode(ResponseCode::NXDomain))) => {
                if inner
                    .records
                    .keys()
                    .any(|key| key.name() == name || name.zone_of(key.name()))
                {
                    return Continue(Err(LookupError::NameExists));
                } else {
                    let code = if self.origin().zone_of(name) {
                        ResponseCode::NXDomain
                    } else {
                        ResponseCode::Refused
                    };
                    return Continue(Err(LookupError::from(code)));
                }
            }
            Continue(Err(e)) => return Continue(Err(e)),
            o => o,
        };

        result.map(|answers| AuthLookup::answers(answers, additionals))
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        debug!("searching InMemoryAuthority for: {}", request_info.query);

        let lookup_name = request_info.query.name();
        let record_type: RecordType = request_info.query.query_type();

        // if this is an AXFR zone transfer, verify that this is either the Secondary or Primary
        //  for AXFR the first and last record must be the SOA
        if RecordType::AXFR == record_type {
            // TODO: support more advanced AXFR options
            if !self.is_axfr_allowed() {
                return LookupControlFlow::Continue(Err(LookupError::from(ResponseCode::Refused)));
            }

            #[allow(deprecated)]
            match self.zone_type() {
                ZoneType::Primary | ZoneType::Secondary | ZoneType::Master | ZoneType::Slave => (),
                // TODO: Forward?
                _ => {
                    return LookupControlFlow::Continue(Err(LookupError::from(
                        ResponseCode::NXDomain,
                    )))
                }
            }
        }

        // perform the actual lookup
        match record_type {
            RecordType::SOA => {
                self.lookup(self.origin(), record_type, lookup_options)
                    .await
            }
            RecordType::AXFR => {
                // TODO: shouldn't these SOA's be secure? at least the first, perhaps not the last?
                use LookupControlFlow::Continue;
                let start_soa = if let Continue(Ok(res)) = self.soa_secure(lookup_options).await {
                    res.unwrap_records()
                } else {
                    LookupRecords::Empty
                };
                let end_soa = if let Continue(Ok(res)) = self.soa().await {
                    res.unwrap_records()
                } else {
                    LookupRecords::Empty
                };

                let records = if let Continue(Ok(res)) =
                    self.lookup(lookup_name, record_type, lookup_options).await
                {
                    res.unwrap_records()
                } else {
                    LookupRecords::Empty
                };

                LookupControlFlow::Continue(Ok(AuthLookup::AXFR {
                    start_soa,
                    end_soa,
                    records,
                }))
            }
            // A standard Lookup path
            _ => self.lookup(lookup_name, record_type, lookup_options).await,
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
    async fn get_nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        let inner = self.inner.read().await;
        fn is_nsec_rrset(rr_set: &RecordSet) -> bool {
            rr_set.record_type() == RecordType::NSEC
        }

        // TODO: need a BorrowdRrKey
        let rr_key = RrKey::new(name.clone(), RecordType::NSEC);
        let no_data = inner
            .records
            .get(&rr_key)
            .map(|rr_set| LookupRecords::new(lookup_options, rr_set.clone()));

        if let Some(no_data) = no_data {
            return LookupControlFlow::Continue(Ok(no_data.into()));
        }

        let get_closest_nsec = |name: &LowerName| -> Option<Arc<RecordSet>> {
            inner
                .records
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
                        .map(Record::data)
                        .and_then(RData::as_dnssec)
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
        let origin = self.origin();
        let wildcard = if origin.zone_of(&wildcard) {
            wildcard
        } else {
            origin.clone()
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

        LookupControlFlow::Continue(Ok(LookupRecords::many(lookup_options, proofs).into()))
    }

    #[cfg(not(feature = "dnssec"))]
    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        LookupControlFlow::Continue(Ok(AuthLookup::default()))
    }

    #[cfg(feature = "dnssec")]
    async fn get_nsec3_records(
        &self,
        info: Nsec3QueryInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        let zone = self.origin();

        let inner = self.inner.read().await;

        let Nsec3QueryInfo {
            qname,
            qtype,
            has_wildcard_match,
            ..
        } = info;

        let compute_proof = || -> Result<Vec<Arc<RecordSet>>, LookupError> {
            let rr_key = RrKey::new(info.get_hashed_owner_name(qname, zone)?, RecordType::NSEC3);
            let qname_match = inner.records.get(&rr_key);

            if has_wildcard_match {
                // - Wildcard answer response.
                let closest_encloser_name = inner
                    .get_closest_encloser_proof(qname, zone, &info)?
                    .map(|(name, _)| name);

                let closest_encloser_cover = match closest_encloser_name {
                    Some(closest_encloser_name) => {
                        inner.find_cover(&closest_encloser_name, zone, &info)?
                    }
                    None => None,
                };

                Ok(closest_encloser_cover.into_iter().collect())
            } else {
                match qname_match {
                    Some(rr_set) => {
                        // - No data response if the QTYPE is not DS.
                        // - No data response if the QTYPE is DS and there is an NSEC3 record matching QNAME.
                        Ok(vec![rr_set.clone()])
                    }
                    None => {
                        // - Name error response.
                        // - No data response if QTYPE is DS and there is not an NSEC3 record matching QNAME.
                        // - Wildcard no data response.
                        let (next_closer_name, closest_encloser_match) = inner
                            .get_closest_encloser_proof(qname, zone, &info)?
                            .unzip();

                        let next_closer_name_cover = match &next_closer_name {
                            Some(name) => inner.find_cover(name, zone, &info)?,
                            None => None,
                        };

                        let wildcard_record = match next_closer_name {
                            Some(next_closer_name) => {
                                let wildcard_match = {
                                    let wildcard = qname.clone().into_wildcard();
                                    inner.records.keys().any(|rr_key| rr_key.name == wildcard)
                                };

                                if wildcard_match {
                                    let wildcard_at_closest_encloser =
                                        next_closer_name.into_wildcard();
                                    let rr_key = RrKey::new(
                                        info.get_hashed_owner_name(
                                            &wildcard_at_closest_encloser,
                                            zone,
                                        )?,
                                        RecordType::NSEC3,
                                    );
                                    inner.records.get(&rr_key).cloned()
                                } else if qtype != RecordType::DS {
                                    let wildcard_at_closest_encloser =
                                        next_closer_name.into_wildcard();
                                    inner.find_cover(&wildcard_at_closest_encloser, zone, &info)?
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        };

                        Ok(closest_encloser_match
                            .into_iter()
                            .chain(next_closer_name_cover)
                            .chain(wildcard_record)
                            .collect())
                    }
                }
            }
        };

        LookupControlFlow::Continue(
            compute_proof().map(|proof| LookupRecords::many(lookup_options, proof).into()),
        )
    }

    #[cfg(feature = "dnssec")]
    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        self.nx_proof_kind.as_ref()
    }
}

#[cfg(feature = "dnssec")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
#[async_trait::async_trait]
impl DnssecAuthority for InMemoryAuthority {
    /// Add a (Sig0) key that is authorized to perform updates against this authority
    async fn add_update_auth_key(&self, name: Name, key: KEY) -> DnsSecResult<()> {
        let mut inner = self.inner.write().await;

        Self::inner_add_update_auth_key(&mut inner, name, key, self.origin(), self.class)
    }

    /// By adding a secure key, this will implicitly enable dnssec for the zone.
    ///
    /// # Arguments
    ///
    /// * `signer` - Signer with associated private key
    async fn add_zone_signing_key(&self, signer: SigSigner) -> DnsSecResult<()> {
        let mut inner = self.inner.write().await;

        Self::inner_add_zone_signing_key(&mut inner, signer, self.origin(), self.class)
    }

    /// Sign the zone for DNSSEC
    async fn secure_zone(&self) -> DnsSecResult<()> {
        let mut inner = self.inner.write().await;

        inner.secure_zone_mut(self.origin(), self.class, self.nx_proof_kind.as_ref())
    }
}
