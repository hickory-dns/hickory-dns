// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! All authority related types

use cfg_if::cfg_if;
use serde::Deserialize;
use std::fmt;

use crate::{
    authority::{LookupError, LookupObject, UpdateResult, ZoneType},
    proto::rr::{LowerName, RecordSet, RecordType, RrsetRecords},
    server::{Request, RequestInfo},
};
#[cfg(feature = "__dnssec")]
use crate::{
    dnssec::NxProofKind,
    proto::{
        ProtoError,
        dnssec::{DnsSecResult, Nsec3HashAlgorithm, SigSigner, crypto::Digest, rdata::key::KEY},
        rr::Name,
    },
};

/// LookupOptions that specify different options from the client to include or exclude various records in the response.
///
/// For example, `dnssec_ok` (DO) will include `RRSIG` in the response.
#[derive(Clone, Copy, Debug, Default)]
pub struct LookupOptions {
    dnssec_ok: bool,
}

/// Lookup Options for the request to the authority
impl LookupOptions {
    /// Return a new LookupOptions
    #[cfg(feature = "__dnssec")]
    pub fn for_dnssec(dnssec_ok: bool) -> Self {
        Self { dnssec_ok }
    }

    /// Specify that this lookup should return DNSSEC related records as well, e.g. RRSIG
    #[allow(clippy::needless_update)]
    pub fn set_dnssec_ok(self, val: bool) -> Self {
        Self {
            dnssec_ok: val,
            ..self
        }
    }

    /// If true this lookup should return DNSSEC related records as well, e.g. RRSIG
    pub fn dnssec_ok(&self) -> bool {
        self.dnssec_ok
    }

    /// Returns the rrset's records with or without RRSIGs, depending on the DO flag.
    pub fn rrset_with_rrigs<'r>(&self, record_set: &'r RecordSet) -> RrsetRecords<'r> {
        cfg_if! {
            if #[cfg(feature = "__dnssec")] {
                record_set.records(self.dnssec_ok())
            } else {
                record_set.records_without_rrsigs()
            }
        }
    }
}

/// Authority implementations can be used with a `Catalog`
#[async_trait::async_trait]
pub trait Authority: Send + Sync {
    /// Result of a lookup
    type Lookup: Send + Sync + Sized + 'static;

    /// What type is this zone
    fn zone_type(&self) -> ZoneType;

    /// Return the policy for determining if AXFR requests are allowed
    fn axfr_policy(&self) -> AxfrPolicy;

    /// Whether the authority can perform DNSSEC validation
    fn can_validate_dnssec(&self) -> bool {
        false
    }

    /// Perform a dynamic update of a zone
    async fn update(&self, update: &Request) -> UpdateResult<bool>;

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
    ) -> LookupControlFlow<Self::Lookup>;

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
    async fn consult(
        &self,
        _name: &LowerName,
        _rtype: RecordType,
        _lookup_options: LookupOptions,
        last_result: LookupControlFlow<Box<dyn LookupObject>>,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        last_result
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
    async fn search(
        &self,
        request: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup>;

    /// Get the NS, NameServer, record for the zone
    async fn ns(&self, lookup_options: LookupOptions) -> LookupControlFlow<Self::Lookup> {
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
    ) -> LookupControlFlow<Self::Lookup>;

    /// Return the NSEC3 records based on the information available for a query.
    #[cfg(feature = "__dnssec")]
    async fn get_nsec3_records(
        &self,
        info: Nsec3QueryInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup>;

    /// Returns the SOA of the authority.
    ///
    /// *Note*: This will only return the SOA, if this is fulfilling a request, a standard lookup
    ///  should be used, see `soa_secure()`, which will optionally return RRSIGs.
    async fn soa(&self) -> LookupControlFlow<Self::Lookup> {
        // SOA should be origin|SOA
        self.lookup(self.origin(), RecordType::SOA, LookupOptions::default())
            .await
    }

    /// Returns the SOA record for the zone
    async fn soa_secure(&self, lookup_options: LookupOptions) -> LookupControlFlow<Self::Lookup> {
        self.lookup(self.origin(), RecordType::SOA, lookup_options)
            .await
    }

    /// Returns the kind of non-existence proof used for this zone.
    #[cfg(feature = "__dnssec")]
    fn nx_proof_kind(&self) -> Option<&NxProofKind>;
}

/// Extension to Authority to allow for DNSSEC features
#[cfg(feature = "__dnssec")]
#[async_trait::async_trait]
pub trait DnssecAuthority: Authority {
    /// Add a (Sig0) key that is authorized to perform updates against this authority
    async fn add_update_auth_key(&self, name: Name, key: KEY) -> DnsSecResult<()>;

    /// Add Signer
    async fn add_zone_signing_key(&self, signer: SigSigner) -> DnsSecResult<()>;

    /// Sign the zone for DNSSEC
    async fn secure_zone(&self) -> DnsSecResult<()>;
}

/// AxfrPolicy describes how to handle AXFR requests
///
/// By default, all AXFR requests are denied.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Deserialize)]
pub enum AxfrPolicy {
    /// Deny all AXFR requests.
    #[default]
    Deny,
    /// Allow all AXFR requests, regardless of whether they are signed.
    AllowAll,
}

/// Result of a Lookup in the Catalog and Authority
///
/// * **All authorities should default to using LookupControlFlow::Continue to wrap their responses.**
///   These responses may be passed to other authorities for analysis or requery purposes.
/// * Authorities may use LookupControlFlow::Break to indicate the response must be returned
///   immediately to the client, without consulting any other authorities.  For example, if the
///   user configures a blocklist authority, it would not be appropriate to pass the query to
///   any additional authorities to try to resolve, as that might be used to leak information to a
///   hostile party, and so a blocklist (or similar) authority should wrap responses for any
///   blocklist hits in LookupControlFlow::Break.
/// * Authorities may use LookupControlFlow::Skip to indicate the authority did not attempt to
///   process a particular query.  This might be used, for example, in a block list authority for
///   any queries that **did not** match the blocklist, to allow the recursor or forwarder to
///   resolve the query. Skip must not be used to represent an empty lookup; (use
///   Continue(EmptyLookup) or Break(EmptyLookup) for that.)
pub enum LookupControlFlow<T, E = LookupError> {
    /// A lookup response that may be passed to one or more additional authorities before
    /// being returned to the client.
    Continue(Result<T, E>),
    /// A lookup response that must be immediately returned to the client without consulting
    /// any other authorities.
    Break(Result<T, E>),
    /// The authority did not answer the query and the next authority in the chain should
    /// be consulted.
    Skip,
}

impl<T, E> fmt::Display for LookupControlFlow<T, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Continue(cont) => match cont {
                Ok(_) => write!(f, "LookupControlFlow::Continue(Ok)"),
                Err(_) => write!(f, "LookupControlFlow::Continue(Err)"),
            },
            Self::Break(b) => match b {
                Ok(_) => write!(f, "LookupControlFlow::Break(Ok)"),
                Err(_) => write!(f, "LookupControlFlow::Break(Err)"),
            },
            Self::Skip => write!(f, "LookupControlFlow::Skip"),
        }
    }
}

/// The following are a minimal set of methods typically used with Result or Option, and that
/// were used in the server code or test suite prior to when the LookupControlFlow type was created
/// (authority lookup functions previously returned a Result over a Lookup or LookupError type.)
impl<T, E> LookupControlFlow<T, E> {
    /// Return true if self is LookupControlFlow::Continue
    pub fn is_continue(&self) -> bool {
        matches!(self, Self::Continue(_))
    }

    /// Return true if self is LookupControlFlow::Break
    pub fn is_break(&self) -> bool {
        matches!(self, Self::Break(_))
    }

    /// Maps inner Ok(T) and Err(E) to Some(Result<T,E>) and Skip to None
    pub fn map_result(self) -> Option<Result<T, E>> {
        match self {
            Self::Continue(Ok(lookup)) | Self::Break(Ok(lookup)) => Some(Ok(lookup)),
            Self::Continue(Err(e)) | Self::Break(Err(e)) => Some(Err(e)),
            Self::Skip => None,
        }
    }
}

impl<T: LookupObject + 'static, E: std::fmt::Display> LookupControlFlow<T, E> {
    /// Return inner Ok variant or panic with a custom error message.
    pub fn expect(self, msg: &str) -> T {
        match self {
            Self::Continue(Ok(ok)) | Self::Break(Ok(ok)) => ok,
            _ => {
                panic!("lookupcontrolflow::expect() called on unexpected variant {self}: {msg}");
            }
        }
    }

    /// Return inner Err variant or panic with a custom error message.
    pub fn expect_err(self, msg: &str) -> E {
        match self {
            Self::Continue(Err(e)) | Self::Break(Err(e)) => e,
            _ => {
                panic!(
                    "lookupcontrolflow::expect_err() called on unexpected variant {self}: {msg}"
                );
            }
        }
    }

    /// Return inner Ok variant or panic
    pub fn unwrap(self) -> T {
        match self {
            Self::Continue(Ok(ok)) | Self::Break(Ok(ok)) => ok,
            Self::Continue(Err(e)) | Self::Break(Err(e)) => {
                panic!("lookupcontrolflow::unwrap() called on unexpected variant _(Err(_)): {e}");
            }
            _ => {
                panic!("lookupcontrolflow::unwrap() called on unexpected variant: {self}");
            }
        }
    }

    /// Return inner Err variant or panic
    pub fn unwrap_err(self) -> E {
        match self {
            Self::Continue(Err(e)) | Self::Break(Err(e)) => e,
            _ => {
                panic!("lookupcontrolflow::unwrap_err() called on unexpected variant: {self}");
            }
        }
    }

    /// Return inner Ok Variant or default value
    pub fn unwrap_or_default(self) -> T
    where
        T: Default,
    {
        match self {
            Self::Continue(Ok(ok)) | Self::Break(Ok(ok)) => ok,
            _ => T::default(),
        }
    }

    /// Maps inner Ok(T) to Ok(U), passing inner Err and Skip values unchanged.
    pub fn map<U, F: FnOnce(T) -> U>(self, op: F) -> LookupControlFlow<U, E> {
        match self {
            Self::Continue(cont) => match cont {
                Ok(t) => LookupControlFlow::Continue(Ok(op(t))),
                Err(e) => LookupControlFlow::Continue(Err(e)),
            },
            Self::Break(b) => match b {
                Ok(t) => LookupControlFlow::Break(Ok(op(t))),
                Err(e) => LookupControlFlow::Break(Err(e)),
            },
            Self::Skip => LookupControlFlow::<U, E>::Skip,
        }
    }

    /// Maps inner Ok(T) to Ok(Box&lt;dyn LookupObject&gt;), passing inner Err and Skip values unchanged.
    pub fn map_dyn(self) -> LookupControlFlow<Box<dyn LookupObject>, E> {
        match self {
            Self::Continue(cont) => match cont {
                Ok(lookup) => {
                    LookupControlFlow::Continue(Ok(Box::new(lookup) as Box<dyn LookupObject>))
                }
                Err(e) => LookupControlFlow::Continue(Err(e)),
            },
            Self::Break(b) => match b {
                Ok(lookup) => {
                    LookupControlFlow::Break(Ok(Box::new(lookup) as Box<dyn LookupObject>))
                }
                Err(e) => LookupControlFlow::Break(Err(e)),
            },

            Self::Skip => LookupControlFlow::<Box<dyn LookupObject>, E>::Skip,
        }
    }

    /// Maps inner Err(T) to Err(U), passing Ok and Skip values unchanged.
    pub fn map_err<U, F: FnOnce(E) -> U>(self, op: F) -> LookupControlFlow<T, U> {
        match self {
            Self::Continue(cont) => match cont {
                Ok(lookup) => LookupControlFlow::Continue(Ok(lookup)),
                Err(e) => LookupControlFlow::Continue(Err(op(e))),
            },
            Self::Break(b) => match b {
                Ok(lookup) => LookupControlFlow::Break(Ok(lookup)),
                Err(e) => LookupControlFlow::Break(Err(op(e))),
            },
            Self::Skip => LookupControlFlow::Skip,
        }
    }
}

/// Information required to compute the NSEC3 records that should be sent for a query.
#[cfg(feature = "__dnssec")]
pub struct Nsec3QueryInfo<'q> {
    /// The queried name.
    pub qname: &'q LowerName,
    /// The queried record type.
    pub qtype: RecordType,
    /// Whether there was a wildcard match for `qname` regardless of `qtype`.
    pub has_wildcard_match: bool,
    /// The algorithm used to hash the names.
    pub algorithm: Nsec3HashAlgorithm,
    /// The salt used for hashing.
    pub salt: &'q [u8],
    /// The number of hashing iterations.
    pub iterations: u16,
}

#[cfg(feature = "__dnssec")]
impl Nsec3QueryInfo<'_> {
    /// Computes the hash of a given name.
    pub(crate) fn hash_name(&self, name: &Name) -> Result<Digest, ProtoError> {
        self.algorithm.hash(self.salt, name, self.iterations)
    }

    /// Computes the hashed owner name from a given name. That is, the hash of the given name,
    /// followed by the zone name.
    pub(crate) fn get_hashed_owner_name(
        &self,
        name: &LowerName,
        zone: &Name,
    ) -> Result<LowerName, ProtoError> {
        let hash = self.hash_name(name)?;
        let label = data_encoding::BASE32_DNSSEC.encode(hash.as_ref());
        Ok(LowerName::new(&zone.prepend_label(label)?))
    }
}
