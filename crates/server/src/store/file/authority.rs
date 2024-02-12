// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! All authority related types

use std::{
    collections::BTreeMap,
    fs,
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
};

use tracing::{debug, info};

#[cfg(feature = "dnssec")]
use crate::{
    authority::DnssecAuthority,
    proto::rr::dnssec::{rdata::key::KEY, DnsSecResult, SigSigner},
};
use crate::{
    authority::{Authority, LookupError, LookupOptions, MessageRequest, UpdateResult, ZoneType},
    proto::rr::{LowerName, Name, RecordSet, RecordType, RrKey},
    proto::serialize::txt::Parser,
    server::RequestInfo,
    store::{file::FileConfig, in_memory::InMemoryAuthority},
};

/// FileAuthority is responsible for storing the resource records for a particular zone.
///
/// Authorities default to DNSClass IN. The ZoneType specifies if this should be treated as the
/// start of authority for the zone, is a Secondary, or a cached zone.
pub struct FileAuthority(InMemoryAuthority);

impl FileAuthority {
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
        InMemoryAuthority::new(origin, records, zone_type, allow_axfr).map(Self)
    }

    /// Read the Authority for the origin from the specified configuration
    pub fn try_from_config(
        origin: Name,
        zone_type: ZoneType,
        allow_axfr: bool,
        root_dir: Option<&Path>,
        config: &FileConfig,
    ) -> Result<Self, String> {
        let root_dir_path = root_dir.map(PathBuf::from).unwrap_or_default();
        let zone_path = root_dir_path.join(&config.zone_file_path);

        info!("loading zone file: {:?}", zone_path);

        // TODO: this should really use something to read line by line or some other method to
        //  keep the usage down. and be a custom lexer...
        let buf = fs::read_to_string(&zone_path)
            .map_err(|e| format!("failed to read {}: {:?}", &config.zone_file_path, e))?;

        let (origin, records) = Parser::new(buf, Some(zone_path), Some(origin))
            .parse()
            .map_err(|e| format!("failed to parse {}: {:?}", config.zone_file_path, e))?;

        info!(
            "zone file loaded: {} with {} records",
            origin,
            records.len()
        );
        debug!("zone: {:#?}", records);

        Self::new(origin, records, zone_type, allow_axfr)
    }

    /// Unwrap the InMemoryAuthority
    pub fn unwrap(self) -> InMemoryAuthority {
        self.0
    }
}

impl Deref for FileAuthority {
    type Target = InMemoryAuthority;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FileAuthority {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[async_trait::async_trait]
impl Authority for FileAuthority {
    type Lookup = <InMemoryAuthority as Authority>::Lookup;

    /// What type is this zone
    fn zone_type(&self) -> ZoneType {
        self.0.zone_type()
    }

    /// Return true if AXFR is allowed
    fn is_axfr_allowed(&self) -> bool {
        self.0.is_axfr_allowed()
    }

    /// Perform a dynamic update of a zone
    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        use crate::proto::op::ResponseCode;
        Err(ResponseCode::NotImp)
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName {
        self.0.origin()
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
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> Result<Option<Self::Lookup>, LookupError> {
        self.0.lookup(name, rtype, lookup_options).await
    }

    /// Using the specified query, perform a lookup against this zone.
    ///
    /// # Arguments
    ///
    /// * `query` - the query to perform the lookup with.
    /// * `is_secure` - if true, then RRSIG records (if this is a secure zone) will be returned.
    ///
    /// # Return value
    ///
    /// Returns a vector containing the results of the query, it will be empty if not found. If
    ///  `is_secure` is true, in the case of no records found then NSEC records will be returned.
    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Option<Self::Lookup>, LookupError> {
        self.0.search(request_info, lookup_options).await
    }

    /// Get the NS, NameServer, record for the zone
    async fn ns(&self, lookup_options: LookupOptions) -> Result<Self::Lookup, LookupError> {
        self.0.ns(lookup_options).await
    }

    /// Return the NSEC records based on the given name
    ///
    /// # Arguments
    ///
    /// * `name` - given this name (i.e. the lookup name), return the NSEC record that is less than
    ///            this
    /// * `is_secure` - if true then it will return RRSIG records as well
    async fn get_nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        self.0.get_nsec_records(name, lookup_options).await
    }

    /// Returns the SOA of the authority.
    ///
    /// *Note*: This will only return the SOA, if this is fulfilling a request, a standard lookup
    ///  should be used, see `soa_secure()`, which will optionally return RRSIGs.
    async fn soa(&self) -> Result<Self::Lookup, LookupError> {
        self.0.soa().await
    }

    /// Returns the SOA record for the zone
    async fn soa_secure(&self, lookup_options: LookupOptions) -> Result<Self::Lookup, LookupError> {
        self.0.soa_secure(lookup_options).await
    }
}

#[cfg(feature = "dnssec")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
#[async_trait::async_trait]
impl DnssecAuthority for FileAuthority {
    /// Add a (Sig0) key that is authorized to perform updates against this authority
    async fn add_update_auth_key(&self, name: Name, key: KEY) -> DnsSecResult<()> {
        self.0.add_update_auth_key(name, key).await
    }

    /// Add Signer
    async fn add_zone_signing_key(&self, signer: SigSigner) -> DnsSecResult<()> {
        self.0.add_zone_signing_key(signer).await
    }

    /// Sign the zone for DNSSEC
    async fn secure_zone(&self) -> DnsSecResult<()> {
        DnssecAuthority::secure_zone(&self.0).await
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::proto::rr::{rdata::A, RData};
    use futures_executor::block_on;

    use super::*;
    use crate::authority::ZoneType;

    #[test]
    fn test_load_zone() {
        #[cfg(feature = "dnssec")]
        let config = FileConfig {
            zone_file_path: "../../tests/test-data/test_configs/dnssec/example.com.zone"
                .to_string(),
        };
        #[cfg(not(feature = "dnssec"))]
        let config = FileConfig {
            zone_file_path: "../../tests/test-data/test_configs/example.com.zone".to_string(),
        };
        let authority = FileAuthority::try_from_config(
            Name::from_str("example.com.").unwrap(),
            ZoneType::Primary,
            false,
            None,
            &config,
        )
        .expect("failed to load file");

        let lookup = block_on(Authority::lookup(
            &authority,
            &LowerName::from_str("www.example.com.").unwrap(),
            RecordType::A,
            LookupOptions::default(),
        ))
        .expect("lookup failed");

        match lookup
            .expect("Lookup returned None")
            .into_iter()
            .next()
            .expect("A record not found in authority")
            .data()
        {
            Some(RData::A(ip)) => assert_eq!(A::new(127, 0, 0, 1), *ip),
            _ => panic!("wrong rdata type returned"),
        }

        let include_lookup = block_on(Authority::lookup(
            &authority,
            &LowerName::from_str("include.alias.example.com.").unwrap(),
            RecordType::A,
            LookupOptions::default(),
        ))
        .expect("INCLUDE lookup failed");

        match include_lookup
            .expect("Lookup returned None")
            .into_iter()
            .next()
            .expect("A record not found in authority")
            .data()
        {
            Some(RData::A(ip)) => assert_eq!(A::new(127, 0, 0, 5), *ip),
            _ => panic!("wrong rdata type returned"),
        }
    }
}
