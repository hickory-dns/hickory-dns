// Copyright 2015-2018 Benjamin Fry <benjaminfry -@- me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! All persistent store implementations

use std::{collections::BTreeMap, sync::Arc};

#[cfg(feature = "__dnssec")]
use hickory_proto::dnssec::SigSigner;
use hickory_proto::rr::{LowerName, RecordSet, RecordType, RrKey};

pub mod blocklist;
pub mod file;
pub mod forwarder;
pub mod in_memory;
#[cfg(feature = "metrics")]
mod metrics;
pub mod recursor;
#[cfg(feature = "sqlite")]
pub mod sqlite;

/// Storage backend for a zone in an authoritative DNS server.
pub trait StoreBackend {
    /// Provides mutable access to both the records and the private keys for this zone at the same time.
    #[cfg(feature = "__dnssec")]
    fn as_mut_tuple(&mut self) -> (&mut BTreeMap<RrKey, Arc<RecordSet>>, &mut Vec<SigSigner>);

    /// Provides mutable access to the DNSSEC private keys used to sign the zone.
    #[cfg(feature = "__dnssec")]
    fn secure_keys_mut(&mut self) -> &mut Vec<SigSigner>;

    /// Returns the DNSSEC private keys used to sign the zone.
    #[cfg(feature = "__dnssec")]
    fn secure_keys(&self) -> &[SigSigner];

    /// Returns a mutable reference to the zone's records.
    fn records_mut(&mut self) -> &mut BTreeMap<RrKey, Arc<RecordSet>>;

    /// Gets one RRset.
    fn rrset<'r>(
        &'r self,
        name: &LowerName,
        record_type: RecordType,
    ) -> Option<&'r Arc<RecordSet>> {
        self.records().get(&RrKey::new(name.clone(), record_type))
    }

    /// Checks if any RRsets exist at a name.
    fn name_exists(&self, name: &LowerName) -> bool {
        // This range covers all RRsets at a given name, with any record type.
        let start_range_key = RrKey::new(name.clone(), RecordType::Unknown(u16::MIN));
        let end_range_key = RrKey::new(name.clone(), RecordType::Unknown(u16::MAX));
        self.records()
            .range(&start_range_key..=&end_range_key)
            .next()
            .is_some()
    }

    /// Returns a reference to the zone's records.
    fn records(&self) -> &BTreeMap<RrKey, Arc<RecordSet>>;

    /// Returns a label for use in metrics, indicating the type of storage backend.
    #[cfg(feature = "metrics")]
    fn metrics_label(&self) -> &'static str;
}
