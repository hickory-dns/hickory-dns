// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Object-safe authority and lookup traits

use tracing::debug;

#[cfg(feature = "__dnssec")]
use crate::{authority::Nsec3QueryInfo, dnssec::NxProofKind, proto::dnssec::Proof};
use crate::{
    authority::{
        Authority, AxfrPolicy, LookupControlFlow, LookupError, LookupOptions, UpdateResult,
        ZoneType,
    },
    proto::op::message::ResponseSigner,
    proto::rr::{LowerName, Record, RecordType},
    server::Request,
};

/// An Object safe Authority
#[async_trait::async_trait]
pub trait AuthorityObject: Send + Sync {
    /// What type is this zone
    fn zone_type(&self) -> ZoneType;

    /// Return the policy for determining if AXFR requests are allowed
    fn axfr_policy(&self) -> AxfrPolicy;

    /// Whether the authority can perform DNSSEC validation
    fn can_validate_dnssec(&self) -> bool;

    /// Perform a dynamic update of a zone
    async fn update(
        &self,
        update: &Request,
    ) -> (UpdateResult<bool>, Option<Box<dyn ResponseSigner>>);

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName;

    /// Looks up all Resource Records matching the given `Name` and `RecordType`.
    ///
    /// # Arguments
    ///
    /// * `name` - The name to look up.
    /// * `rtype` - The `RecordType` to look up. `RecordType::ANY` will return all records matching
    ///             `name`. `RecordType::AXFR` will return all record types except `RecordType::SOA`
    ///             due to the requirements that on zone transfers the `RecordType::SOA` must both
    ///             precede and follow all other records.
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///                      algorithms, etc.)
    ///
    /// # Return value
    ///
    /// A LookupControlFlow containing the lookup that should be returned to the client.
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Box<dyn LookupObject>>;

    /// Consulting lookup for all Resource Records matching the given `Name` and `RecordType`.
    /// This will be called in a chained authority configuration after an authority in the chain
    /// has returned a lookup with a LookupControlFlow::Continue action. Every other authority in
    /// the chain will be called via this consult method, until one either returns a
    /// LookupControlFlow::Break action, or all authorities have been consulted.  The authority that
    /// generated the primary lookup (the one returned via 'lookup') will not be consulted.
    ///
    /// # Arguments
    ///
    /// * `name` - The name to look up.
    /// * `rtype` - The `RecordType` to look up. `RecordType::ANY` will return all records matching
    ///             `name`. `RecordType::AXFR` will return all record types except `RecordType::SOA`
    ///             due to the requirements that on zone transfers the `RecordType::SOA` must both
    ///             precede and follow all other records.
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///                      algorithms, etc.)
    /// * `last_result` - The lookup returned by a previous authority in a chained configuration.
    ///                   If a subsequent authority does not modify this lookup, it will be returned
    ///                   to the client after consulting all authorities in the chain.
    ///
    /// # Return value
    ///
    /// A LookupControlFlow containing the lookup that should be returned to the client.  This can
    /// be the same last_result that was passed in, or a new lookup, depending on the logic of the
    /// authority in question.
    ///
    /// An optional `ResponseSigner` to use to sign the response returned to the client. If it is
    /// `None` and an earlier authority provided `Some`, it will be ignored. If it is `Some` it
    /// will be used to replace any previous `ResponseSigner`.
    async fn consult(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
        last_result: LookupControlFlow<Box<dyn LookupObject>>,
    ) -> (
        LookupControlFlow<Box<dyn LookupObject>>,
        Option<Box<dyn ResponseSigner>>,
    );

    /// Using the specified query, perform a lookup against this zone.
    ///
    /// # Arguments
    ///
    /// * `request` - the query to perform the lookup with.
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///                      algorithms, etc.)
    ///
    /// # Return value
    ///
    /// A LookupControlFlow containing the lookup that should be returned to the client.
    ///
    /// An optional `ResponseSigner` to use to sign the response returned to the client.
    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (
        LookupControlFlow<Box<dyn LookupObject>>,
        Option<Box<dyn ResponseSigner>>,
    );

    /// Get the NS, NameServer, record for the zone
    async fn ns(&self, lookup_options: LookupOptions) -> LookupControlFlow<Box<dyn LookupObject>> {
        self.lookup(self.origin(), RecordType::NS, lookup_options)
            .await
    }

    /// Return the NSEC records based on the given name
    ///
    /// # Arguments
    ///
    /// * `name` - given this name (i.e. the lookup name), return the NSEC record that is less than
    ///            this
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///                      algorithms, etc.)
    async fn get_nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Box<dyn LookupObject>>;

    /// Return the NSEC3 records based on the given query information.
    #[cfg(feature = "__dnssec")]
    async fn get_nsec3_records(
        &self,
        info: Nsec3QueryInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Box<dyn LookupObject>>;

    /// Returns the SOA of the authority.
    ///
    /// *Note*: This will only return the SOA, if this is fulfilling a request, a standard lookup
    ///  should be used, see `soa_secure()`, which will optionally return RRSIGs.
    async fn soa(&self) -> LookupControlFlow<Box<dyn LookupObject>> {
        // SOA should be origin|SOA
        self.lookup(self.origin(), RecordType::SOA, LookupOptions::default())
            .await
    }

    /// Returns the SOA record for the zone
    async fn soa_secure(
        &self,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        self.lookup(self.origin(), RecordType::SOA, lookup_options)
            .await
    }

    /// Returns the kind of non-existence proof used for this zone.
    #[cfg(feature = "__dnssec")]
    fn nx_proof_kind(&self) -> Option<&NxProofKind>;
}

#[async_trait::async_trait]
impl<A, L> AuthorityObject for A
where
    A: Authority<Lookup = L> + Send + Sync + 'static,
    L: LookupObject + Send + Sync + 'static,
{
    /// What type is this zone
    fn zone_type(&self) -> ZoneType {
        Authority::zone_type(self)
    }

    /// Return the policy for determining if AXFR requests are allowed
    fn axfr_policy(&self) -> AxfrPolicy {
        Authority::axfr_policy(self)
    }

    /// Whether the authority can perform DNSSEC validation
    fn can_validate_dnssec(&self) -> bool {
        Authority::can_validate_dnssec(self)
    }

    /// Perform a dynamic update of a zone
    async fn update(
        &self,
        update: &Request,
    ) -> (UpdateResult<bool>, Option<Box<dyn ResponseSigner>>) {
        Authority::update(self, update).await
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName {
        Authority::origin(self)
    }

    /// Looks up all Resource Records matching the given `Name` and `RecordType`.
    ///
    /// # Arguments
    ///
    /// * `name` - The name to look up.
    /// * `rtype` - The `RecordType` to look up. `RecordType::ANY` will return all records matching
    ///             `name`. `RecordType::AXFR` will return all record types except `RecordType::SOA`
    ///             due to the requirements that on zone transfers the `RecordType::SOA` must both
    ///             precede and follow all other records.
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///                      algorithms, etc.)
    ///
    /// # Return value
    ///
    /// A LookupControlFlow containing the lookup that should be returned to the client.
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        Authority::lookup(self, name, rtype, lookup_options)
            .await
            .map_dyn()
    }

    /// Consulting lookup for all Resource Records matching the given `Name` and `RecordType`.
    /// This will be called in a chained authority configuration after an authority in the chain
    /// has returned a lookup with a LookupControlFlow::Continue action. Every other authority in
    /// the chain will be called via this consult method, until one either returns a
    /// LookupControlFlow::Break action, or all authorities have been consulted.  The authority that
    /// generated the primary lookup (the one returned via 'lookup') will not be consulted.
    ///
    /// # Arguments
    ///
    /// * `name` - The name to look up.
    /// * `rtype` - The `RecordType` to look up. `RecordType::ANY` will return all records matching
    ///             `name`. `RecordType::AXFR` will return all record types except `RecordType::SOA`
    ///             due to the requirements that on zone transfers the `RecordType::SOA` must both
    ///             precede and follow all other records.
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///                      algorithms, etc.)
    /// * `last_result` - The lookup returned by a previous authority in a chained configuration.
    ///                   If a subsequent authority does not modify this lookup, it will be returned
    ///                   to the client after consulting all authorities in the chain.
    ///
    /// # Return value
    ///
    /// A LookupControlFlow containing the lookup that should be returned to the client.  This can
    /// be the same last_result that was passed in, or a new lookup, depending on the logic of the
    /// authority in question.
    ///
    /// An optional `ResponseSigner` to use to sign the response returned to the client. If it is
    /// `None` and an earlier authority provided `Some`, it will be ignored. If it is `Some` it
    /// will be used to replace any previous `ResponseSigner`.
    async fn consult(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
        last_result: LookupControlFlow<Box<dyn LookupObject>>,
    ) -> (
        LookupControlFlow<Box<dyn LookupObject>>,
        Option<Box<dyn ResponseSigner>>,
    ) {
        Authority::consult(self, name, rtype, lookup_options, last_result).await
    }

    /// Using the specified query, perform a lookup against this zone.
    ///
    /// # Arguments
    ///
    /// * `request` - the query to perform the lookup with.
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///                      algorithms, etc.)
    ///
    /// # Return value
    ///
    /// A LookupControlFlow containing the lookup that should be returned to the client.
    ///
    /// An optional `ResponseSigner` to use to sign the response returned to the client.
    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (
        LookupControlFlow<Box<dyn LookupObject>>,
        Option<Box<dyn ResponseSigner>>,
    ) {
        let request_info = match request.request_info() {
            Ok(info) => info,
            Err(e) => return (LookupControlFlow::Break(Err(LookupError::from(e))), None),
        };
        debug!("performing {} on {}", request_info.query, self.origin());
        let (res, signer) = Authority::search(self, request, lookup_options).await;
        (res.map_dyn(), signer)
    }

    /// Return the NSEC records based on the given name
    ///
    /// # Arguments
    ///
    /// * `name` - given this name (i.e. the lookup name), return the NSEC record that is less than
    ///            this
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///                      algorithms, etc.)
    async fn get_nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        Authority::get_nsec_records(self, name, lookup_options)
            .await
            .map_dyn()
    }

    /// Return the NSEC3 records based on the given query information.
    #[cfg(feature = "__dnssec")]
    async fn get_nsec3_records(
        &self,
        info: Nsec3QueryInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        Authority::get_nsec3_records(self, info, lookup_options)
            .await
            .map_dyn()
    }

    /// Returns the kind of non-existence proof used for this zone.
    #[cfg(feature = "__dnssec")]
    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        Authority::nx_proof_kind(self)
    }
}

/// DNSSEC status of an answer
#[derive(Clone, Copy, Debug)]
pub enum DnssecSummary {
    /// All records have been DNSSEC validated
    Secure,
    /// At least one record is in the Bogus state
    Bogus,
    /// Insecure / Indeterminate (e.g. "Island of security")
    Insecure,
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

    /// Whether the records have been DNSSEC validated or not
    #[cfg(feature = "__dnssec")]
    fn dnssec_summary(&self) -> DnssecSummary {
        let mut all_secure = None;
        for record in self.iter() {
            match record.proof() {
                Proof::Secure => {
                    all_secure.get_or_insert(true);
                }
                Proof::Bogus => return DnssecSummary::Bogus,
                _ => all_secure = Some(false),
            }
        }

        if all_secure.unwrap_or(false) {
            DnssecSummary::Secure
        } else {
            DnssecSummary::Insecure
        }
    }

    /// Whether the records have been DNSSEC validated or not
    #[cfg(not(feature = "__dnssec"))]
    fn dnssec_summary(&self) -> DnssecSummary {
        DnssecSummary::Insecure
    }
}

/// A lookup that returns no records
#[derive(Clone, Copy, Debug)]
pub struct EmptyLookup;

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
