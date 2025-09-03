// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Module for `Catalog` of `ZoneHandler` zones which are responsible for storing `RRSet` records.

use std::{fmt, io, sync::Arc};

use cfg_if::cfg_if;
use enum_as_inner::EnumAsInner;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "__dnssec")]
use crate::dnssec::NxProofKind;
#[cfg(feature = "__dnssec")]
use crate::proto::dnssec::crypto::Digest;
#[cfg(feature = "__dnssec")]
use crate::proto::dnssec::rdata::KEY;
#[cfg(feature = "__dnssec")]
use crate::proto::dnssec::{DnsSecResult, Nsec3HashAlgorithm, SigSigner};
use crate::proto::op::{Edns, ResponseCode, ResponseSigner};
#[cfg(feature = "__dnssec")]
use crate::proto::rr::Name;
use crate::proto::rr::{LowerName, Record, RecordSet, RecordType, RrsetRecords, rdata::SOA};
use crate::proto::{DnsError, NoRecords, ProtoError, ProtoErrorKind};
#[cfg(feature = "recursor")]
use crate::recursor::ErrorKind;
use crate::server::{Request, RequestInfo};

mod auth_lookup;
mod catalog;
pub(crate) mod message_request;
mod message_response;
#[cfg(feature = "metrics")]
pub(crate) mod metrics;

pub use self::auth_lookup::{
    AuthLookup, AuthLookupIter, AxfrRecords, LookupRecords, LookupRecordsIter, ZoneTransfer,
};
pub use self::catalog::Catalog;
pub use self::message_request::{MessageRequest, Queries, UpdateRequest};
pub use self::message_response::{MessageResponse, MessageResponseBuilder};

/// ZoneHandler implementations can be used with a `Catalog`
#[async_trait::async_trait]
pub trait ZoneHandler: Send + Sync {
    /// What type is this zone
    fn zone_type(&self) -> ZoneType;

    /// Return the policy for determining if AXFR requests are allowed
    fn axfr_policy(&self) -> AxfrPolicy;

    /// Whether the zone handler can perform DNSSEC validation
    fn can_validate_dnssec(&self) -> bool {
        false
    }

    /// Perform a dynamic update of a zone
    async fn update(
        &self,
        _update: &Request,
        _now: u64,
    ) -> (Result<bool, ResponseCode>, Option<Box<dyn ResponseSigner>>) {
        (Err(ResponseCode::NotImp), None)
    }

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
    /// * `request_info` - The `RequestInfo` structure for the request, if it is available.
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
        request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup>;

    /// Consulting lookup for all Resource Records matching the given `Name` and `RecordType`. This
    /// will be called in a chained zone handler configuration after a zone handler in the chain has
    /// returned a lookup with a LookupControlFlow::Continue action. Every other zone handler in the
    /// chain will be called via this consult method, until one either returns a
    /// LookupControlFlow::Break action, or all zone handlers have been consulted.  The zone handler
    /// that generated the primary lookup (the one returned via 'lookup') will not be consulted.
    ///
    /// # Arguments
    ///
    /// * `name` - The name to look up.
    /// * `rtype` - The `RecordType` to look up. `RecordType::ANY` will return all records matching
    ///             `name`. `RecordType::AXFR` will return all record types except `RecordType::SOA`
    ///             due to the requirements that on zone transfers the `RecordType::SOA` must both
    ///             precede and follow all other records.
    /// * `request_info` - The `RequestInfo` structure for the request, if it is available.
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///                      algorithms, etc.)
    /// * `last_result` - The lookup returned by a previous zone handler in a chained configuration.
    ///                   If a subsequent zone handler does not modify this lookup, it will be
    ///                   returned to the client after consulting all zone handlers in the chain.
    ///
    /// # Return value
    ///
    /// A LookupControlFlow containing the lookup that should be returned to the client.  This can
    /// be the same last_result that was passed in, or a new lookup, depending on the logic of the
    /// zone handler in question.
    ///
    /// An optional `ResponseSigner` to use to sign the response returned to the client. If it is
    /// `None` and an earlier zone handler provided `Some`, it will be ignored. If it is `Some` it
    /// will be used to replace any previous `ResponseSigner`.
    async fn consult(
        &self,
        _name: &LowerName,
        _rtype: RecordType,
        _request_info: Option<&RequestInfo<'_>>,
        _lookup_options: LookupOptions,
        last_result: LookupControlFlow<AuthLookup>,
    ) -> (
        LookupControlFlow<AuthLookup>,
        Option<Box<dyn ResponseSigner>>,
    ) {
        (last_result, None)
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
        LookupControlFlow<AuthLookup>,
        Option<Box<dyn ResponseSigner>>,
    );

    /// Return the NSEC records based on the given name
    ///
    /// # Arguments
    ///
    /// * `name` - given this name (i.e. the lookup name), return the NSEC record that is less than
    ///            this
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///                      algorithms, etc.)
    async fn nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup>;

    /// Return the NSEC3 records based on the information available for a query.
    #[cfg(feature = "__dnssec")]
    async fn nsec3_records(
        &self,
        info: Nsec3QueryInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup>;

    /// Returns all records in the zone.
    ///
    /// This will return `None` if the next zone handler in the zone handler chain should be used instead.
    async fn zone_transfer(
        &self,
        _request: &Request,
        _lookup_options: LookupOptions,
        _now: u64,
    ) -> Option<(
        Result<ZoneTransfer, LookupError>,
        Option<Box<dyn ResponseSigner>>,
    )> {
        Some((Err(LookupError::from(ResponseCode::NotImp)), None))
    }

    /// Returns the kind of non-existence proof used for this zone.
    #[cfg(feature = "__dnssec")]
    fn nx_proof_kind(&self) -> Option<&NxProofKind>;

    /// Returns the zone handler metrics label.
    #[cfg(feature = "metrics")]
    fn metrics_label(&self) -> &'static str;
}

/// Extension to ZoneHandler to allow for DNSSEC features
#[cfg(feature = "__dnssec")]
#[async_trait::async_trait]
pub trait DnssecZoneHandler: ZoneHandler {
    /// Add a (Sig0) key that is authorized to perform updates against this zone
    async fn add_update_auth_key(&self, name: Name, key: KEY) -> DnsSecResult<()>;

    /// Add Signer
    async fn add_zone_signing_key(&self, signer: SigSigner) -> DnsSecResult<()>;

    /// Sign the zone for DNSSEC
    async fn secure_zone(&self) -> DnsSecResult<()>;
}

/// Result of a Lookup in the Catalog and ZoneHandler
///
/// * **All zone handlers should default to using LookupControlFlow::Continue to wrap their
///   responses.** These responses may be passed to other zone handlers for analysis or requery
///   purposes.
/// * Zone handlers may use LookupControlFlow::Break to indicate the response must be returned
///   immediately to the client, without consulting any other zone handlers.  For example, if the
///   user configures a blocklist zone handler, it would not be appropriate to pass the query to any
///   additional zone handlers to try to resolve, as that might be used to leak information to a
///   hostile party, and so a blocklist (or similar) zone handler should wrap responses for any
///   blocklist hits in LookupControlFlow::Break.
/// * Zone handlers may use LookupControlFlow::Skip to indicate the zone handler did not attempt to
///   process a particular query.  This might be used, for example, in a block list zone handler for
///   any queries that **did not** match the blocklist, to allow the recursor or forwarder to
///   resolve the query. Skip must not be used to represent an empty lookup; (use
///   Continue(EmptyLookup) or Break(EmptyLookup) for that.)
pub enum LookupControlFlow<T, E = LookupError> {
    /// A lookup response that may be passed to one or more additional zone handlers before
    /// being returned to the client.
    Continue(Result<T, E>),
    /// A lookup response that must be immediately returned to the client without consulting
    /// any other zone handlers.
    Break(Result<T, E>),
    /// The zone handler did not answer the query and the next zone handler in the chain should
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
/// (zone handler lookup functions previously returned a Result over a Lookup or LookupError type.)
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

impl<E: std::fmt::Display> LookupControlFlow<AuthLookup, E> {
    /// Return inner Ok variant or panic with a custom error message.
    pub fn expect(self, msg: &str) -> AuthLookup {
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
    pub fn unwrap(self) -> AuthLookup {
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
    pub fn unwrap_or_default(self) -> AuthLookup {
        match self {
            Self::Continue(Ok(ok)) | Self::Break(Ok(ok)) => ok,
            _ => AuthLookup::default(),
        }
    }

    /// Maps inner Ok(T) to Ok(U), passing inner Err and Skip values unchanged.
    pub fn map<U, F: FnOnce(AuthLookup) -> U>(self, op: F) -> LookupControlFlow<U, E> {
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

    /// Maps inner Err(T) to Err(U), passing Ok and Skip values unchanged.
    pub fn map_err<U, F: FnOnce(E) -> U>(self, op: F) -> LookupControlFlow<AuthLookup, U> {
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

/// A query could not be fulfilled
#[derive(Debug, EnumAsInner, Error)]
#[non_exhaustive]
pub enum LookupError {
    /// The query had an invalid number of queries
    #[error("there should only be one query per request, got {0}")]
    BadQueryCount(usize),
    /// A record at the same Name as the query exists, but not of the queried RecordType
    #[error("The name exists, but not for the record requested")]
    NameExists,
    /// There was an error performing the lookup
    #[error("Error performing lookup: {0}")]
    ResponseCode(ResponseCode),
    /// Proto error
    #[error("Proto error: {0}")]
    ProtoError(#[from] ProtoError),
    /// Recursive Resolver Error
    #[cfg(feature = "recursor")]
    #[error("Recursive resolution error: {0}")]
    RecursiveError(#[from] hickory_recursor::Error),
    /// An underlying IO error occurred
    #[error("io error: {0}")]
    Io(io::Error),
}

impl LookupError {
    /// Create a lookup error, specifying that a name exists at the location, but no matching RecordType
    pub fn for_name_exists() -> Self {
        Self::NameExists
    }

    /// This is a non-existent domain name
    pub fn is_nx_domain(&self) -> bool {
        match self {
            Self::ProtoError(e) => e.is_nx_domain(),
            Self::ResponseCode(ResponseCode::NXDomain) => true,
            #[cfg(feature = "recursor")]
            Self::RecursiveError(e) if e.is_nx_domain() => true,
            _ => false,
        }
    }

    /// Returns true if no records were returned
    pub fn is_no_records_found(&self) -> bool {
        match self {
            Self::ProtoError(e) => e.is_no_records_found(),
            #[cfg(feature = "recursor")]
            Self::RecursiveError(e) if e.is_no_records_found() => true,
            _ => false,
        }
    }

    /// Returns the SOA record, if the error contains one
    pub fn into_soa(self) -> Option<Box<Record<SOA>>> {
        match self {
            Self::ProtoError(e) => e.into_soa(),
            #[cfg(feature = "recursor")]
            Self::RecursiveError(e) => e.into_soa(),
            _ => None,
        }
    }

    /// Return authority records
    pub fn authorities(&self) -> Option<Arc<[Record]>> {
        match self {
            Self::ProtoError(e) => match e.kind() {
                ProtoErrorKind::Dns(DnsError::NoRecordsFound(NoRecords {
                    authorities, ..
                })) => authorities.clone(),
                _ => None,
            },
            #[cfg(feature = "recursor")]
            Self::RecursiveError(e) => match e.kind() {
                ErrorKind::Negative(fwd) => fwd.authorities.clone(),
                ErrorKind::Proto(proto) => match proto.kind() {
                    ProtoErrorKind::Dns(DnsError::NoRecordsFound(NoRecords {
                        authorities,
                        ..
                    })) => authorities.clone(),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        }
    }
}

impl From<ResponseCode> for LookupError {
    fn from(code: ResponseCode) -> Self {
        // this should never be a NoError
        debug_assert!(code != ResponseCode::NoError);
        Self::ResponseCode(code)
    }
}

impl From<io::Error> for LookupError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<LookupError> for io::Error {
    fn from(e: LookupError) -> Self {
        Self::other(Box::new(e))
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
    pub(crate) fn hashed_owner_name(
        &self,
        name: &LowerName,
        zone: &Name,
    ) -> Result<LowerName, ProtoError> {
        let hash = self.hash_name(name)?;
        let label = data_encoding::BASE32_DNSSEC.encode(hash.as_ref());
        Ok(LowerName::new(&zone.prepend_label(label)?))
    }
}

/// Options from the client to include or exclude various records in the response.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default)]
pub struct LookupOptions {
    /// Whether the client is interested in `RRSIG` records (DNSSEC DO bit).
    pub dnssec_ok: bool,
}

impl LookupOptions {
    /// Create [`LookupOptions`] from the given EDNS options.
    #[cfg_attr(not(feature = "__dnssec"), allow(unused_variables))]
    pub fn from_edns(edns: Option<&Edns>) -> Self {
        #[cfg_attr(not(feature = "__dnssec"), allow(unused_mut))]
        let mut new = Self::default();
        #[cfg(feature = "__dnssec")]
        if let Some(edns) = edns {
            new.dnssec_ok = edns.flags().dnssec_ok;
        }
        new
    }

    /// Create [`LookupOptions`] with `dnssec_ok` enabled.
    #[cfg(feature = "__dnssec")]
    pub fn for_dnssec() -> Self {
        Self { dnssec_ok: true }
    }

    /// Returns the rrset's records with or without RRSIGs, depending on the DO flag.
    pub fn rrset_with_rrigs<'r>(&self, record_set: &'r RecordSet) -> RrsetRecords<'r> {
        cfg_if! {
            if #[cfg(feature = "__dnssec")] {
                record_set.records(self.dnssec_ok)
            } else {
                record_set.records_without_rrsigs()
            }
        }
    }
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
    /// Allow all AXFR requests that have a valid SIG(0) or TSIG signature.
    #[cfg(feature = "__dnssec")]
    AllowSigned,
}

/// The type of zone stored in a Catalog
#[derive(Serialize, Deserialize, Hash, PartialEq, Eq, Debug, Clone, Copy)]
pub enum ZoneType {
    /// This authority for a zone
    Primary,
    /// A secondary, i.e. replicated from the Primary
    Secondary,
    /// A cached zone that queries other nameservers
    External,
}
