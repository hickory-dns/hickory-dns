// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! All authority related types

use std::pin::Pin;
use std::task::Context;

use futures::{future, Future, Poll, TryFutureExt};

use trust_dns::op::LowerQuery;
use trust_dns::proto::rr::dnssec::rdata::key::KEY;
use trust_dns::rr::dnssec::{DnsSecError, DnsSecResult, Signer, SupportedAlgorithms};
use trust_dns::rr::{LowerName, Name, Record, RecordType};

use crate::authority::{Authority, LookupError, MessageRequest, UpdateResult, ZoneType};

/// An Object safe Authority
pub trait AuthorityObject: Send + Sync {
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
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> BoxedLookupFuture;

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
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> BoxedLookupFuture;

    /// Get the NS, NameServer, record for the zone
    fn ns(&self, is_secure: bool, supported_algorithms: SupportedAlgorithms) -> BoxedLookupFuture {
        self.lookup(
            self.origin(),
            RecordType::NS,
            is_secure,
            supported_algorithms,
        )
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
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> BoxedLookupFuture;

    /// Returns the SOA of the authority.
    ///
    /// *Note*: This will only return the SOA, if this is fulfilling a request, a standard lookup
    ///  should be used, see `soa_secure()`, which will optionally return RRSIGs.
    fn soa(&self) -> BoxedLookupFuture {
        // SOA should be origin|SOA
        self.lookup(
            self.origin(),
            RecordType::SOA,
            false,
            SupportedAlgorithms::new(),
        )
    }

    /// Returns the SOA record for the zone
    fn soa_secure(
        &self,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> BoxedLookupFuture {
        self.lookup(
            self.origin(),
            RecordType::SOA,
            is_secure,
            supported_algorithms,
        )
    }

    // TODO: this should probably be a general purpose higher level component?
    /// Add a (Sig0) key that is authorized to perform updates against this authority
    fn add_update_auth_key(&mut self, _name: Name, _key: KEY) -> DnsSecResult<()> {
        Err(DnsSecError::from(
            "dynamic update not supported by this Authority type",
        ))
    }

    /// Add Signer
    fn add_zone_signing_key(&mut self, _signer: Signer) -> DnsSecResult<()> {
        Err(DnsSecError::from(
            "zone signing not supported by this Authority type",
        ))
    }

    /// Sign the zone for DNSSEC
    fn secure_zone(&mut self) -> DnsSecResult<()> {
        Err(DnsSecError::from(
            "zone signing not supported by this Authority type",
        ))
    }
}

impl<A, L> AuthorityObject for A
where
    A: Authority<Lookup = L> + Send + Sync + 'static,
    A::LookupFuture: Send + 'static,
    L: LookupObject + Send + 'static,
{
    /// What type is this zone
    fn zone_type(&self) -> ZoneType {
        Authority::zone_type(self)
    }

    /// Return true if AXFR is allowed
    fn is_axfr_allowed(&self) -> bool {
        Authority::is_axfr_allowed(self)
    }

    /// Perform a dynamic update of a zone
    fn update(&mut self, update: &MessageRequest) -> UpdateResult<bool> {
        Authority::update(self, update)
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName {
        Authority::origin(self)
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
    fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> BoxedLookupFuture {
        let lookup = Authority::lookup(self, name, rtype, is_secure, supported_algorithms);
        BoxedLookupFuture::from(lookup.map_ok(|l| Box::new(l) as Box<dyn LookupObject>))
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
    /// Returns a vectory containing the results of the query, it will be empty if not found. If
    ///  `is_secure` is true, in the case of no records found then NSEC records will be returned.
    fn search(
        &self,
        query: &LowerQuery,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> BoxedLookupFuture {
        let lookup = Authority::search(self, query, is_secure, supported_algorithms);
        BoxedLookupFuture::from(lookup.map_ok(|l| Box::new(l) as Box<dyn LookupObject>))
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
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> BoxedLookupFuture {
        let lookup = Authority::get_nsec_records(self, name, is_secure, supported_algorithms);
        BoxedLookupFuture::from(lookup.map_ok(|l| Box::new(l) as Box<dyn LookupObject>))
    }

    fn add_update_auth_key(&mut self, name: Name, key: KEY) -> DnsSecResult<()> {
        Authority::add_update_auth_key(self, name, key)
    }

    fn add_zone_signing_key(&mut self, signer: Signer) -> DnsSecResult<()> {
        Authority::add_zone_signing_key(self, signer)
    }

    fn secure_zone(&mut self) -> DnsSecResult<()> {
        Authority::secure_zone(self)
    }
}

/// An Object Safe Lookup for Authority
pub trait LookupObject: Send {
    /// Returns true if either the associated Records are empty, or this is a NameExists or NxDomain
    fn is_empty(&self) -> bool;

    /// Conversion to an iterator
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Record> + Send + 'a>;

    /// For CNAME and similar records, this is an additional set of lookup records
    ///
    /// it is acceptable for this to return None after the first call.
    fn take_additionals(&mut self) -> Option<Box<dyn LookupObject>>;
}

struct EmptyLookup;

impl LookupObject for EmptyLookup {
    fn is_empty(&self) -> bool {
        true
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Record> + Send + 'a> {
        Box::new([].iter())
    }

    fn take_additionals(&mut self) -> Option<Box<dyn LookupObject>> {
        None
    }
}

/// A boxed lookup future
pub struct BoxedLookupFuture(
    Pin<Box<dyn Future<Output = Result<Box<dyn LookupObject>, LookupError>> + Send>>,
);

impl BoxedLookupFuture {
    /// Performs a conversion (boxes) into the future
    pub fn from<T>(future: T) -> Self
    where
        T: Future<Output = Result<Box<dyn LookupObject>, LookupError>> + Send + Sized + 'static,
    {
        BoxedLookupFuture(Box::pin(future))
    }

    /// Creates an empty (i.e. no records) lookup future
    pub fn empty() -> Self {
        BoxedLookupFuture(Box::pin(future::ok(
            Box::new(EmptyLookup) as Box<dyn LookupObject>
        )))
    }
}

impl Future for BoxedLookupFuture {
    type Output = Result<Box<dyn LookupObject>, LookupError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}
