// Copyright 2015-2018 Benjamin Fry <benjaminfry -@- me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! All persistent store implementations

use std::{collections::BTreeMap, sync::Arc};

#[cfg(feature = "__dnssec")]
use crate::proto::dnssec::SigSigner;
use crate::proto::rr::{LowerName, RecordSet, RecordType, RrKey};

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
    /// Gets one RRset.
    fn get_rrset<'r>(
        &'r self,
        name: &LowerName,
        record_type: RecordType,
    ) -> Option<&'r Arc<RecordSet>>;

    /// Checks if any RRsets exist at a name.
    fn name_exists(&self, name: &LowerName) -> bool;

    /// Returns a reference to the zone's records.
    fn records(&self) -> &BTreeMap<RrKey, Arc<RecordSet>>;

    /// Returns a mutable reference to the zone's records.
    fn records_mut(&mut self) -> &mut BTreeMap<RrKey, Arc<RecordSet>>;

    /// Returns the DNSSEC private keys used to sign the zone.
    #[cfg(feature = "__dnssec")]
    fn secure_keys(&self) -> &[SigSigner];

    /// Provides mutable access to the DNSSEC private keys used to sign the zone.
    #[cfg(feature = "__dnssec")]
    fn secure_keys_mut(&mut self) -> &mut Vec<SigSigner>;

    /// Provides mutable access to both the records and the private keys for this zone at the same
    /// time.
    #[cfg(feature = "__dnssec")]
    fn as_mut_tuple(&mut self) -> (&mut BTreeMap<RrKey, Arc<RecordSet>>, &mut Vec<SigSigner>);

    /// Returns a label for use in metrics, indicating the type of storage backend.
    #[cfg(feature = "metrics")]
    fn metrics_label(&self) -> &'static str;
}
