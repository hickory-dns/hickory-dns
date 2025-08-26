// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! In-memory zone data authority

use std::{collections::BTreeMap, sync::Arc};

#[cfg(feature = "sqlite")]
use crate::store::sqlite::Journal;
use crate::{
    authority::{AxfrPolicy, ZoneType},
    proto::{
        rr::{DNSClass, LowerName, Name, RecordSet, RecordType, RrKey},
        runtime::RuntimeProvider,
    },
    store::{StoreBackend, StoreBackendExt, authoritative::AuthoritativeAuthority},
};
#[cfg(feature = "__dnssec")]
use crate::{dnssec::NxProofKind, proto::dnssec::SigSigner};

/// In-memory storage for an authoritative zone.
pub struct InMemoryStore {
    origin: LowerName,
    class: DNSClass,

    records: BTreeMap<RrKey, Arc<RecordSet>>,

    /// DNSSEC private keys.
    #[cfg(feature = "__dnssec")]
    secure_keys: Vec<SigSigner>,
}

impl InMemoryStore {
    /// Creates a new in-memory backing store.
    pub fn new(origin: Name, records: BTreeMap<RrKey, RecordSet>) -> Result<Self, String> {
        let mut this = Self::empty(origin.clone());

        // SOA must be present
        let soa = records
            .get(&RrKey::new(origin.clone().into(), RecordType::SOA))
            .and_then(|rrset| rrset.records_without_rrsigs().next())
            .and_then(|record| record.data().as_soa())
            .ok_or_else(|| format!("SOA record must be present: {origin}"))?;
        let serial = soa.serial();

        for rrset in records.into_values() {
            for record in rrset.records_without_rrsigs() {
                if !this.upsert(record.clone(), serial, this.class) {
                    return Err(format!(
                        "Failed to insert {name} {rr_type} to zone: {origin}",
                        name = rrset.name(),
                        rr_type = rrset.record_type()
                    ));
                }
            }
        }

        Ok(this)
    }

    /// Creates an empty in-memory backing store.
    ///
    /// Note that this creates an invalid zone, as an SOA record must be added.
    pub fn empty(origin: Name) -> Self {
        Self {
            origin: origin.into(),
            class: DNSClass::IN,
            records: BTreeMap::new(),
            #[cfg(feature = "__dnssec")]
            secure_keys: Vec::new(),
        }
    }

    /// Gets the origin of the zone.
    pub fn origin(&self) -> &LowerName {
        &self.origin
    }

    /// Clears all records (including SOA, etc.)
    pub fn clear(&mut self) {
        self.records.clear();
    }
}

impl StoreBackend for InMemoryStore {
    fn get_rrset<'r>(
        &'r self,
        name: &LowerName,
        record_type: RecordType,
    ) -> Option<&'r Arc<RecordSet>> {
        self.records.get(&RrKey::new(name.clone(), record_type))
    }

    fn name_exists(&self, name: &LowerName) -> bool {
        // This range covers all RRsets at a given name, with any record type.
        let start_range_key = RrKey::new(name.clone(), RecordType::Unknown(u16::MIN));
        let end_range_key = RrKey::new(name.clone(), RecordType::Unknown(u16::MAX));
        self.records
            .range(&start_range_key..=&end_range_key)
            .next()
            .is_some()
    }

    fn records(&self) -> &BTreeMap<RrKey, Arc<RecordSet>> {
        &self.records
    }

    fn records_mut(&mut self) -> &mut BTreeMap<RrKey, Arc<RecordSet>> {
        &mut self.records
    }

    #[cfg(feature = "__dnssec")]
    fn secure_keys(&self) -> &[SigSigner] {
        &self.secure_keys
    }

    #[cfg(feature = "__dnssec")]
    fn secure_keys_mut(&mut self) -> &mut Vec<SigSigner> {
        &mut self.secure_keys
    }

    #[cfg(feature = "__dnssec")]
    fn as_mut_tuple(&mut self) -> (&mut BTreeMap<RrKey, Arc<RecordSet>>, &mut Vec<SigSigner>) {
        let Self {
            records,
            secure_keys,
            ..
        } = self;
        (records, secure_keys)
    }

    #[cfg(feature = "sqlite")]
    fn journal(&self) -> Option<&Journal> {
        None
    }

    #[cfg(feature = "metrics")]
    fn metrics_label(&self) -> &'static str {
        "in-memory"
    }
}

impl<P: RuntimeProvider> AuthoritativeAuthority<InMemoryStore, P> {
    /// Creates an empty Authority with in-memory storage.
    pub fn empty(
        origin: Name,
        zone_type: ZoneType,
        axfr_policy: AxfrPolicy,
        #[cfg(feature = "__dnssec")] nx_proof_kind: Option<NxProofKind>,
    ) -> Self {
        Self::new(
            origin.clone(),
            InMemoryStore::empty(origin),
            zone_type,
            axfr_policy,
            false,
            false,
            #[cfg(feature = "__dnssec")]
            nx_proof_kind,
        )
    }
}
