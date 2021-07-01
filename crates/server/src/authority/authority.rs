// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! All authority related types
use std::future::Future;
use std::pin::Pin;

use cfg_if::cfg_if;

use crate::authority::{LookupError, MessageRequest, UpdateResult, ZoneType};
use crate::client::op::LowerQuery;
use crate::client::rr::{LowerName, RecordSet, RecordType};
#[cfg(feature = "dnssec")]
use crate::client::{
    proto::rr::dnssec::rdata::key::KEY,
    rr::dnssec::{DnsSecResult, SigSigner, SupportedAlgorithms},
    rr::Name,
};
use crate::proto::rr::RrsetRecords;

/// LookupOptions that specify different options from the client to include or exclude various records in the response.
///
/// For example, `is_dnssec` will include `RRSIG` in the response, `supported_algorithms` will only include a subset of
///    `RRSIG` based on the algorithms supported by the request.
#[derive(Clone, Copy, Debug, Default)]
pub struct LookupOptions {
    is_dnssec: bool,
    #[cfg(feature = "dnssec")]
    supported_algorithms: SupportedAlgorithms,
}

/// Lookup Options for the request to the authority
impl LookupOptions {
    /// Return a new LookupOptions
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    pub fn for_dnssec(is_dnssec: bool, supported_algorithms: SupportedAlgorithms) -> Self {
        LookupOptions {
            is_dnssec,
            supported_algorithms,
        }
    }

    /// Specify that this lookup should return DNSSEC related records as well, e.g. RRSIG
    #[allow(clippy::needless_update)]
    pub fn set_is_dnssec(self, val: bool) -> Self {
        Self {
            is_dnssec: val,
            ..self
        }
    }

    /// If true this lookup should return DNSSEC related records as well, e.g. RRSIG
    pub fn is_dnssec(&self) -> bool {
        self.is_dnssec
    }

    /// Specify the algorithms for which DNSSEC records should be returned
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    pub fn set_supported_algorithms(self, val: SupportedAlgorithms) -> Self {
        Self {
            supported_algorithms: val,
            ..self
        }
    }

    /// The algorithms for which DNSSEC records should be returned
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    pub fn supported_algorithms(&self) -> SupportedAlgorithms {
        self.supported_algorithms
    }

    /// Returns the subset of the rrset limited to the supported_algorithms
    pub fn rrset_with_supported_algorithms<'r>(
        &self,
        record_set: &'r RecordSet,
    ) -> RrsetRecords<'r> {
        cfg_if! {
            if #[cfg(feature = "dnssec")] {
                record_set.records(
                    self.is_dnssec(),
                    self.supported_algorithms(),
                )
            } else {
                record_set.records_without_rrsigs()
            }
        }
    }
}

/// Authority implementations can be used with a `Catalog`
pub trait Authority: Send {
    /// Result of a lookup
    type Lookup: Send + Sized + 'static;
    /// The future type that will resolve to a Lookup
    type LookupFuture: Future<Output = Result<Self::Lookup, LookupError>> + Send;

    /// What type is this zone
    fn zone_type(&self) -> ZoneType;

    /// Return true if AXFR is allowed
    fn is_axfr_allowed(&self) -> bool;

    /// Perform a dynamic update of a zone
    fn update(&mut self, update: &MessageRequest) -> UpdateResult<bool>;

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName;

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
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>>;

    /// Using the specified query, perform a lookup against this zone.
    ///
    /// # Arguments
    ///
    /// * `query` - the query to perform the lookup with.
    /// * `is_secure` - if true, then RRSIG records (if this is a secure zone) will be returned.
    ///
    /// # Return value
    ///
    /// Returns a vectory containing the results of the query, it will be empty if not found. If
    ///  `is_secure` is true, in the case of no records found then NSEC records will be returned.
    fn search(
        &self,
        query: &LowerQuery,
        lookup_options: LookupOptions,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>>;

    /// Get the NS, NameServer, record for the zone
    fn ns(
        &self,
        lookup_options: LookupOptions,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        self.lookup(self.origin(), RecordType::NS, lookup_options)
    }

    /// Return the NSEC records based on the given name
    ///
    /// # Arguments
    ///
    /// * `name` - given this name (i.e. the lookup name), return the NSEC record that is less than
    ///            this
    /// * `is_secure` - if true then it will return RRSIG records as well
    fn get_nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>>;

    /// Returns the SOA of the authority.
    ///
    /// *Note*: This will only return the SOA, if this is fulfilling a request, a standard lookup
    ///  should be used, see `soa_secure()`, which will optionally return RRSIGs.
    fn soa(&self) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        // SOA should be origin|SOA
        self.lookup(self.origin(), RecordType::SOA, LookupOptions::default())
    }

    /// Returns the SOA record for the zone
    fn soa_secure(
        &self,
        lookup_options: LookupOptions,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        self.lookup(self.origin(), RecordType::SOA, lookup_options)
    }
}

/// Extension to Authority to allow for DNSSEC features
#[cfg(feature = "dnssec")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
pub trait DnssecAuthority: Authority {
    /// Add a (Sig0) key that is authorized to perform updates against this authority
    fn add_update_auth_key(&mut self, name: Name, key: KEY) -> DnsSecResult<()>;

    /// Add Signer
    fn add_zone_signing_key(&mut self, signer: SigSigner) -> DnsSecResult<()>;

    /// Sign the zone for DNSSEC
    fn secure_zone(&mut self) -> DnsSecResult<()>;
}
