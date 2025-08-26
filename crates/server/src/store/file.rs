// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Zone file based serving with Dynamic DNS and journaling support

use std::{
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
};

use serde::Deserialize;

#[cfg(feature = "metrics")]
use crate::store::metrics::PersistentStoreMetrics;
use crate::{
    authority::{
        AuthLookup, AxfrPolicy, LookupControlFlow, LookupError, LookupOptions, ZoneHandler,
        ZoneTransfer, ZoneType,
    },
    proto::{
        op::message::ResponseSigner,
        rr::{LowerName, Name, RecordType},
    },
    server::{Request, RequestInfo},
    store::in_memory::{InMemoryAuthority, zone_from_path},
};
#[cfg(feature = "__dnssec")]
use crate::{
    authority::{DnssecAuthority, Nsec3QueryInfo},
    dnssec::NxProofKind,
    proto::dnssec::{DnsSecResult, SigSigner, rdata::key::KEY},
};

/// FileAuthority is responsible for storing the resource records for a particular zone.
///
/// Authorities default to DNSClass IN. The ZoneType specifies if this should be treated as the
/// start of authority for the zone, is a Secondary, or a cached zone.
pub struct FileAuthority {
    in_memory: InMemoryAuthority,
    #[cfg(feature = "metrics")]
    #[allow(unused)]
    metrics: PersistentStoreMetrics,
}

impl FileAuthority {
    /// Creates a new Authority.
    ///
    /// # Arguments
    ///
    /// * `origin` - The zone `Name` being created, this should match that of the `RecordType::SOA`
    ///   record.
    /// * `records` - The map of the initial set of records in the zone.
    /// * `zone_type` - The type of zone, i.e. is this authoritative?
    /// * `axfr_policy` - A policy for determining if AXFR is allowed.
    /// * `nx_proof_kind` - The kind of non-existence proof to be used by the server.
    ///
    /// # Return value
    ///
    /// The new `Authority`.
    pub async fn new(in_memory: InMemoryAuthority) -> Self {
        Self {
            #[cfg(feature = "metrics")]
            metrics: {
                let new = PersistentStoreMetrics::new("file");
                let records = in_memory.records().await;
                new.zone_records.increment(records.len() as f64);
                new
            },
            in_memory,
        }
    }

    /// Read the Authority for the origin from the specified configuration
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

        // Don't call `new()`, since it needs to be async to get the number of records to initialize metrics
        Ok(Self {
            #[cfg(feature = "metrics")]
            metrics: {
                let new = PersistentStoreMetrics::new("file");
                new.zone_records.increment(records.len() as f64);
                new
            },
            in_memory: InMemoryAuthority::new(
                origin,
                records,
                zone_type,
                axfr_policy,
                #[cfg(feature = "__dnssec")]
                nx_proof_kind,
            )?,
        })
    }
}

impl Deref for FileAuthority {
    type Target = InMemoryAuthority;

    fn deref(&self) -> &Self::Target {
        &self.in_memory
    }
}

impl DerefMut for FileAuthority {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.in_memory
    }
}

#[async_trait::async_trait]
impl ZoneHandler for FileAuthority {
    /// What type is this zone
    fn zone_type(&self) -> ZoneType {
        self.in_memory.zone_type()
    }

    /// Return the policy for determining if AXFR requests are allowed
    fn axfr_policy(&self) -> AxfrPolicy {
        self.in_memory.axfr_policy()
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName {
        self.in_memory.origin()
    }

    /// Looks up all Resource Records matching the given `Name` and `RecordType`.
    ///
    /// # Arguments
    ///
    /// * `name` - The name to look up.
    /// * `rtype` - The `RecordType` to look up. `RecordType::ANY` will return all records matching
    ///   `name`. `RecordType::AXFR` will return all record types except `RecordType::SOA`
    ///   due to the requirements that on zone transfers the `RecordType::SOA` must both
    ///   precede and follow all other records.
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///   algorithms, etc.)
    ///
    /// # Return value
    ///
    /// A LookupControlFlow containing the lookup that should be returned to the client.
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.in_memory
            .lookup(name, rtype, request_info, lookup_options)
            .await
    }

    /// Using the specified query, perform a lookup against this zone.
    ///
    /// # Arguments
    ///
    /// * `request` - the query to perform the lookup with.
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///   algorithms, etc.)
    ///
    /// # Return value
    ///
    /// A LookupControlFlow containing the lookup that should be returned to the client.
    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (
        LookupControlFlow<AuthLookup>,
        Option<Box<dyn ResponseSigner>>,
    ) {
        self.in_memory.search(request, lookup_options).await
    }

    async fn zone_transfer(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
        now: u64,
    ) -> Option<(
        Result<ZoneTransfer, LookupError>,
        Option<Box<dyn ResponseSigner>>,
    )> {
        self.in_memory
            .zone_transfer(request, lookup_options, now)
            .await
    }

    /// Get the NS, NameServer, record for the zone
    async fn ns(&self, lookup_options: LookupOptions) -> LookupControlFlow<AuthLookup> {
        self.in_memory.ns(lookup_options).await
    }

    /// Return the NSEC records based on the given name
    ///
    /// # Arguments
    ///
    /// * `name` - given this name (i.e. the lookup name), return the NSEC record that is less than
    ///   this
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///   algorithms, etc.)
    async fn nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.in_memory.nsec_records(name, lookup_options).await
    }

    #[cfg(feature = "__dnssec")]
    async fn nsec3_records(
        &self,
        info: Nsec3QueryInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.in_memory.nsec3_records(info, lookup_options).await
    }

    /// Returns the SOA of the authority.
    ///
    /// *Note*: This will only return the SOA, if this is fulfilling a request, a standard lookup
    ///  should be used, see `soa_secure()`, which will optionally return RRSIGs.
    async fn soa(&self) -> LookupControlFlow<AuthLookup> {
        self.in_memory.soa().await
    }

    /// Returns the SOA record for the zone
    async fn soa_secure(&self, lookup_options: LookupOptions) -> LookupControlFlow<AuthLookup> {
        self.in_memory.soa_secure(lookup_options).await
    }

    #[cfg(feature = "__dnssec")]
    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        self.in_memory.nx_proof_kind()
    }

    #[cfg(feature = "metrics")]
    fn metrics_label(&self) -> &'static str {
        "file"
    }
}

#[cfg(feature = "__dnssec")]
#[async_trait::async_trait]
impl DnssecAuthority for FileAuthority {
    /// Add a (Sig0) key that is authorized to perform updates against this authority
    async fn add_update_auth_key(&self, name: Name, key: KEY) -> DnsSecResult<()> {
        self.in_memory.add_update_auth_key(name, key).await
    }

    /// Add Signer
    async fn add_zone_signing_key(&self, signer: SigSigner) -> DnsSecResult<()> {
        self.in_memory.add_zone_signing_key(signer).await
    }

    /// Sign the zone for DNSSEC
    async fn secure_zone(&self) -> DnsSecResult<()> {
        DnssecAuthority::secure_zone(&self.in_memory).await
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::proto::rr::{RData, rdata::A};

    use futures_executor::block_on;
    use test_support::subscribe;

    use super::*;
    use crate::authority::ZoneType;

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
        let authority = FileAuthority::try_from_config(
            Name::from_str("example.com.").unwrap(),
            ZoneType::Primary,
            AxfrPolicy::Deny,
            None,
            &config,
            #[cfg(feature = "__dnssec")]
            Some(NxProofKind::Nsec),
        )
        .expect("failed to load file");

        let lookup = block_on(ZoneHandler::lookup(
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

        let include_lookup = block_on(ZoneHandler::lookup(
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
