// Copyright 2015-2018 Benjamin Fry <benjaminfry -@- me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! SQLite serving with Dynamic DNS and journaling support

use std::collections::BTreeMap;
#[cfg(feature = "__dnssec")]
use std::fs;
#[cfg(feature = "__dnssec")]
use std::str::FromStr;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::Deserialize;
use tracing::info;

#[cfg(feature = "metrics")]
use crate::store::metrics::PersistentStoreMetrics;
use crate::{
    authority::{AxfrPolicy, ZoneType},
    error::{PersistenceError, PersistenceErrorKind},
    proto::{
        rr::{LowerName, Name, Record, RecordSet, RecordType, RrKey},
        runtime::RuntimeProvider,
    },
    store::{
        StoreBackend, StoreBackendExt,
        authoritative::AuthoritativeAuthority,
        file::{rooted, zone_from_path},
        in_memory::InMemoryStore,
    },
};
#[cfg(feature = "__dnssec")]
use crate::{
    dnssec::NxProofKind,
    proto::dnssec::{SigSigner, TSigner, rdata::tsig::TsigAlgorithm},
};

pub mod persistence;
pub use persistence::Journal;

/// SQLite database storage for an authoritative zone.
pub struct SqliteStore {
    in_memory: InMemoryStore,
    journal: Option<Journal>,
    #[cfg(feature = "metrics")]
    metrics: Option<PersistentStoreMetrics>,
}

impl SqliteStore {
    /// Constructs a new SQLite backing store.
    pub fn new(origin: Name, records: BTreeMap<RrKey, RecordSet>) -> Result<Self, String> {
        Ok(Self {
            in_memory: InMemoryStore::new(origin, records)?,
            journal: None,
            #[cfg(feature = "metrics")]
            metrics: None,
        })
    }

    /// Constructs an empty SQLite backing store.
    pub fn empty(origin: Name) -> Self {
        Self {
            in_memory: InMemoryStore::empty(origin),
            journal: None,
            #[cfg(feature = "metrics")]
            metrics: None,
        }
    }

    #[cfg(feature = "metrics")]
    pub(super) fn set_metrics(&mut self, metrics: PersistentStoreMetrics) {
        self.metrics = Some(metrics);
    }

    /// Associate a backing journal for this updatable zone.
    pub fn set_journal(&mut self, journal: Journal) {
        self.journal = Some(journal);
    }

    /// Recovers the zone from a Journal, returns an error on failure.
    ///
    /// # Arguments
    ///
    /// * `journal` - the journal from which to load the persisted zone.
    pub fn recover_with_journal(&mut self, journal: &Journal) -> Result<(), PersistenceError> {
        assert!(
            self.in_memory.records_mut().is_empty(),
            "records should be empty during a recovery"
        );

        let serial = self.serial(self.in_memory.origin());

        info!("recovering from journal");
        for record in journal.iter() {
            // AXFR is special, it is used to mark the dump of a full zone.
            //  when recovering, if an AXFR is encountered, we should remove all the records in the
            //  authority.
            if record.record_type() == RecordType::AXFR {
                self.in_memory.clear();
            } else if self.upsert(record.clone(), serial, record.dns_class()) {
                #[cfg(feature = "metrics")]
                if let Some(metrics) = &self.metrics {
                    metrics.zone_records.increment(1);
                }
            } else {
                return Err(PersistenceErrorKind::Recovery("record could not be inserted").into());
            }
        }

        Ok(())
    }

    /// Persist the current state of the zone to the journal, does nothing if there is no associated
    /// journal.
    ///
    /// Returns an error if there was an issue writing to the persistence layer.
    pub fn persist_to_journal(&self) -> Result<(), PersistenceError> {
        let Some(journal) = &self.journal else {
            return Ok(());
        };
        let serial = self.in_memory.serial(self.in_memory.origin());

        info!("persisting zone to journal at SOA.serial: {serial}");

        // TODO: THIS NEEDS TO BE IN A TRANSACTION!!!
        journal.insert_record(
            serial,
            &Record::update0(Name::new(), 0, RecordType::AXFR).into_record_of_rdata(),
        )?;

        for rr_set in self.in_memory.records().values() {
            // TODO: should we preserve rr_sets or not?
            for record in rr_set.records_without_rrsigs() {
                journal.insert_record(serial, record)?;

                #[cfg(feature = "metrics")]
                if let Some(metrics) = &self.metrics {
                    metrics.zone_records.increment(1);
                }
            }
        }

        // TODO: COMMIT THE TRANSACTION!!!
        Ok(())
    }
}

impl StoreBackend for SqliteStore {
    fn get_rrset<'r>(
        &'r self,
        name: &LowerName,
        record_type: RecordType,
    ) -> Option<&'r Arc<RecordSet>> {
        self.in_memory.get_rrset(name, record_type)
    }

    fn name_exists(&self, name: &LowerName) -> bool {
        self.in_memory.name_exists(name)
    }

    fn records(&self) -> &BTreeMap<RrKey, Arc<RecordSet>> {
        self.in_memory.records()
    }

    fn records_mut(&mut self) -> &mut BTreeMap<RrKey, Arc<RecordSet>> {
        self.in_memory.records_mut()
    }

    #[cfg(feature = "__dnssec")]
    fn secure_keys(&self) -> &[SigSigner] {
        self.in_memory.secure_keys()
    }

    #[cfg(feature = "__dnssec")]
    fn secure_keys_mut(&mut self) -> &mut Vec<SigSigner> {
        self.in_memory.secure_keys_mut()
    }

    #[cfg(feature = "__dnssec")]
    fn as_mut_tuple(&mut self) -> (&mut BTreeMap<RrKey, Arc<RecordSet>>, &mut Vec<SigSigner>) {
        self.in_memory.as_mut_tuple()
    }

    fn journal(&self) -> Option<&Journal> {
        self.journal.as_ref()
    }

    #[cfg(feature = "metrics")]
    fn metrics_label(&self) -> &'static str {
        "sqlite"
    }
}

/// Configuration for zone file for sqlite based zones
#[derive(Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct SqliteConfig {
    /// path to initial zone file
    pub zone_path: PathBuf,
    /// path to the sqlite journal file
    pub journal_path: PathBuf,
    /// Are updates allowed to this zone
    #[serde(default)]
    pub allow_update: bool,
    /// TSIG keys allowed to authenticate updates if `allow_update` is true
    #[cfg(feature = "__dnssec")]
    #[serde(default)]
    pub tsig_keys: Vec<TsigKeyConfig>,
}

/// Configuration for a TSIG authentication signer key
#[derive(Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
#[cfg(feature = "__dnssec")]
pub struct TsigKeyConfig {
    /// The key name
    pub name: String,
    /// A path to the unencoded symmetric HMAC key data
    pub key_file: PathBuf,
    /// The key algorithm
    pub algorithm: TsigAlgorithm,
    /// Allowed +/- difference (in seconds) between the time a TSIG request was signed
    /// and when it is verified.
    ///
    /// A fudge value that is too large may leave the server open to replay attacks.
    /// A fudge value that is too small may cause failures from latency and clock
    /// desynchronization.
    ///
    /// RFC 8945 recommends a fudge value of 300 seconds (the default if not specified).
    #[serde(default = "default_fudge")]
    pub fudge: u16,
}

#[cfg(feature = "__dnssec")]
impl TsigKeyConfig {
    fn to_signer(&self, zone_name: &Name) -> Result<TSigner, String> {
        let key_data = fs::read(&self.key_file).map_err(|e| {
            format!(
                "error reading TSIG key file: {}: {e}",
                self.key_file.display()
            )
        })?;
        let signer_name = Name::from_str(&self.name).unwrap_or(zone_name.clone());

        TSigner::new(key_data, self.algorithm.clone(), signer_name, self.fudge)
            .map_err(|e| format!("invalid TSIG key configuration: {e}"))
    }
}

/// Default TSIG fudge value (seconds).
///
/// Per RFC 8945 §10:
///   "The RECOMMENDED value in most situations is 300 seconds."
#[cfg(feature = "__dnssec")]
pub(crate) fn default_fudge() -> u16 {
    300
}

impl<P: RuntimeProvider> AuthoritativeAuthority<SqliteStore, P> {
    /// Read the Authority for the origin from the specified configuration.
    pub fn try_from_config(
        origin: Name,
        zone_type: ZoneType,
        axfr_policy: AxfrPolicy,
        enable_dnssec: bool,
        root_dir: Option<&Path>,
        config: &SqliteConfig,
        #[cfg(feature = "__dnssec")] nx_proof_kind: Option<NxProofKind>,
    ) -> Result<Self, String> {
        let zone_path = rooted(&config.zone_path, root_dir);
        let journal_path = rooted(&config.journal_path, root_dir);

        let authority = if journal_path.exists() {
            // Load the zone.
            info!("recovering zone from journal: {journal_path:?}");
            let journal = Journal::from_file(&journal_path)
                .map_err(|e| format!("error opening journal: {journal_path:?}: {e}"))?;

            let mut authority = Self::new(
                origin.clone(),
                SqliteStore::empty(origin.clone()),
                zone_type,
                axfr_policy,
                config.allow_update,
                enable_dnssec,
                #[cfg(feature = "__dnssec")]
                nx_proof_kind,
            );

            let backend = authority.backend.get_mut();
            #[cfg(feature = "metrics")]
            backend.set_metrics(authority.metrics.clone());
            backend
                .recover_with_journal(&journal)
                .map_err(|e| format!("error recovering from journal: {e}"))?;

            backend.set_journal(journal);
            info!("recovered zone: {origin}");

            authority
        } else if zone_path.exists() {
            // TODO: deprecate this portion of loading, instantiate the journal through a separate tool
            info!("loading zone file: {zone_path:?}");

            let records = zone_from_path(&zone_path, origin.clone())
                .map_err(|e| format!("failed to load zone file: {e}"))?;

            let mut authority = Self::new(
                origin.clone(),
                SqliteStore::new(origin.clone(), records)?,
                zone_type,
                axfr_policy,
                config.allow_update,
                enable_dnssec,
                #[cfg(feature = "__dnssec")]
                nx_proof_kind,
            );

            info!("creating new journal: {journal_path:?}");
            let journal = Journal::from_file(&journal_path)
                .map_err(|e| format!("error creating journal {journal_path:?}: {e}"))?;

            let backend = authority.backend.get_mut();
            backend.set_journal(journal);

            #[cfg(feature = "metrics")]
            backend.set_metrics(authority.metrics.clone());

            // preserve to the new journal, i.e. we just loaded the zone from disk, start the journal
            backend
                .persist_to_journal()
                .map_err(|e| format!("error persisting to journal {journal_path:?}: {e}"))?;

            info!("zone file loaded: {origin}");
            authority
        } else {
            return Err(format!("no zone file or journal defined at: {zone_path:?}"));
        };

        #[cfg(feature = "__dnssec")]
        let mut authority = authority;
        #[cfg(feature = "__dnssec")]
        for config in &config.tsig_keys {
            authority.tsig_signers.push(config.to_signer(&origin)?);
        }

        Ok(authority)
    }
}

#[cfg(test)]
mod tests {
    use crate::store::sqlite::SqliteStore;

    #[test]
    fn test_is_send_sync() {
        #[allow(clippy::extra_unused_type_parameters)]
        fn send_sync<T: Send + Sync>() -> bool {
            true
        }

        assert!(send_sync::<SqliteStore>());
    }
}
