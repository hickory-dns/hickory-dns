// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! All authority related types

use trust_dns::op::LowerQuery;
use trust_dns::rr::dnssec::SupportedAlgorithms;
use trust_dns::rr::LowerName;

use authority::{AuthLookup, MessageRequest, UpdateResult, ZoneType};
use store::sqlite::authority::LookupRecords;

/// Authority implementations can be used with a `Catalog`
pub trait Authority: Send {
    /// What type is this zone
    fn zone_type(&self) -> ZoneType;

    /// Perform a dynamic update of a zone
    fn update(&mut self, update: &MessageRequest) -> UpdateResult<bool>;

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName;

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
    fn search<'s, 'q>(
        &'s self,
        query: &'q LowerQuery,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> AuthLookup<'s, 'q>;

    /// Get the NS, NameServer, record for the zone
    fn ns(&self, is_secure: bool, supported_algorithms: SupportedAlgorithms) -> LookupRecords;

    /// Return the NSEC records based on the given name
    ///
    /// # Arguments
    ///
    /// * `name` - given this name (i.e. the lookup name), return the NSEC record that is less than
    ///            this
    /// * `is_secure` - if true then it will return RRSIG records as well
    fn get_nsec_records<'s, 'q>(
        &'s self,
        name: &'q LowerName,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> LookupRecords<'s, 'q>;

    /// Returns the SOA of the authority.
    ///
    /// *Note*: This will only return the SOA, if this is fullfilling a request, a standard lookup
    ///  should be used, see `soa_secure()`, which will optionally return RRSIGs.
    fn soa(&self) -> LookupRecords;

    /// Returns the SOA record for the zone
    fn soa_secure(
        &self,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> LookupRecords;
}
