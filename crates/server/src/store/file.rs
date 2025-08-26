// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Zone file based serving with Dynamic DNS and journaling support

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::Deserialize;
use tracing::{debug, info};

#[cfg(feature = "sqlite")]
use crate::store::sqlite::Journal;
use crate::{
    authority::{AxfrPolicy, ZoneType},
    proto::{
        rr::{LowerName, Name, RecordSet, RecordType, RrKey},
        runtime::RuntimeProvider,
        serialize::txt::Parser,
    },
    store::{StoreBackend, authoritative::AuthoritativeAuthority, in_memory::InMemoryStore},
};
#[cfg(feature = "__dnssec")]
use crate::{dnssec::NxProofKind, proto::dnssec::SigSigner};

/// Read-only file-backed storage for an authoritative zone.
pub struct FileStore {
    in_memory: InMemoryStore,
}

impl FileStore {
    /// Creates a new file-based backing store.
    pub fn new(origin: Name, records: BTreeMap<RrKey, RecordSet>) -> Result<Self, String> {
        Ok(Self {
            in_memory: InMemoryStore::new(origin, records)?,
        })
    }
}

impl StoreBackend for FileStore {
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

    #[cfg(feature = "sqlite")]
    fn journal(&self) -> Option<&Journal> {
        None
    }

    #[cfg(feature = "metrics")]
    fn metrics_label(&self) -> &'static str {
        "file"
    }
}

impl<P: RuntimeProvider> AuthoritativeAuthority<FileStore, P> {
    /// Read the Authority for the origin from the specified configuration.
    pub fn try_from_config(
        origin: Name,
        zone_type: ZoneType,
        axfr_policy: AxfrPolicy,
        root_dir: Option<&Path>,
        config: &FileConfig,
        #[cfg(feature = "__dnssec")] nx_proof_kind: Option<NxProofKind>,
    ) -> Result<Self, String> {
        let zone_path = rooted(&config.zone_path, root_dir);
        let records = zone_from_path(&zone_path, origin.clone())
            .map_err(|e| format!("failed to load zone file: {e}"))?;

        #[cfg(feature = "metrics")]
        let record_count = records.len();

        let authority = Self::new(
            origin.clone(),
            FileStore::new(origin, records)?,
            zone_type,
            axfr_policy,
            false,
            false,
            #[cfg(feature = "__dnssec")]
            nx_proof_kind,
        );

        #[cfg(feature = "metrics")]
        authority
            .metrics
            .zone_records
            .increment(record_count as f64);

        Ok(authority)
    }
}

/// Configuration for file based zones
#[derive(Clone, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// path to the zone file
    pub zone_path: PathBuf,
}

pub(crate) fn rooted(zone_file: &Path, root_dir: Option<&Path>) -> PathBuf {
    match root_dir {
        Some(root) => root.join(zone_file),
        None => zone_file.to_owned(),
    }
}

// internal load for e.g. sqlite db creation
pub(crate) fn zone_from_path(
    zone_path: &Path,
    origin: Name,
) -> Result<BTreeMap<RrKey, RecordSet>, String> {
    info!("loading zone file: {zone_path:?}");

    // TODO: this should really use something to read line by line or some other method to
    //  keep the usage down. and be a custom lexer...
    let buf = fs::read_to_string(zone_path)
        .map_err(|e| format!("failed to read {}: {e:?}", zone_path.display()))?;

    let (origin, records) = Parser::new(buf, Some(zone_path.to_owned()), Some(origin))
        .parse()
        .map_err(|e| format!("failed to parse {}: {e:?}", zone_path.display()))?;

    info!("zone file loaded: {origin} with {} records", records.len());
    debug!("zone: {records:#?}");
    Ok(records)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use futures_executor::block_on;
    use test_support::subscribe;

    use super::*;
    use crate::{
        authority::{Authority, LookupOptions, ZoneType},
        proto::{
            rr::{RData, rdata::A},
            runtime::TokioRuntimeProvider,
        },
    };

    #[test]
    fn test_load_zone() {
        subscribe();

        #[cfg(feature = "__dnssec")]
        let config = FileConfig {
            zone_path: PathBuf::from("../../tests/test-data/test_configs/dnssec/example.com.zone"),
        };
        #[cfg(not(feature = "__dnssec"))]
        let config = FileConfig {
            zone_path: PathBuf::from("../../tests/test-data/test_configs/example.com.zone"),
        };
        let authority = AuthoritativeAuthority::<FileStore, TokioRuntimeProvider>::try_from_config(
            Name::from_str("example.com.").unwrap(),
            ZoneType::Primary,
            AxfrPolicy::Deny,
            None,
            &config,
            #[cfg(feature = "__dnssec")]
            Some(NxProofKind::Nsec),
        )
        .expect("failed to load file");

        let lookup = block_on(Authority::lookup(
            &authority,
            &LowerName::from_str("www.example.com.").unwrap(),
            RecordType::A,
            None,
            LookupOptions::default(),
        ))
        .expect("lookup failed");

        match lookup
            .into_iter()
            .next()
            .expect("A record not found in authority")
            .data()
        {
            RData::A(ip) => assert_eq!(A::new(127, 0, 0, 1), *ip),
            _ => panic!("wrong rdata type returned"),
        }

        let include_lookup = block_on(Authority::lookup(
            &authority,
            &LowerName::from_str("include.alias.example.com.").unwrap(),
            RecordType::A,
            None,
            LookupOptions::default(),
        ))
        .expect("INCLUDE lookup failed");

        match include_lookup
            .into_iter()
            .next()
            .expect("A record not found in authority")
            .data()
        {
            RData::A(ip) => assert_eq!(A::new(127, 0, 0, 5), *ip),
            _ => panic!("wrong rdata type returned"),
        }
    }
}
