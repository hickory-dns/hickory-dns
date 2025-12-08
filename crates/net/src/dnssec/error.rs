use core::fmt;

use thiserror::Error;

use crate::{
    error::NetError,
    proto::{
        ProtoError,
        dnssec::{Algorithm, Proof},
        op::Query,
        rr::{Name, RecordType},
    },
};

/// The error kind for dnssec errors that get returned in the crate
#[allow(unreachable_pub)]
#[derive(Debug, Error, Clone)]
#[non_exhaustive]
pub enum ProofErrorKind {
    /// An error with an arbitrary message, stored as String
    #[error("{0}")]
    Msg(String),

    /// Algorithm mismatch between rrsig and dnskey
    #[error("algorithm mismatch rrsig: {rrsig} dnskey: {dnskey}")]
    AlgorithmMismatch {
        /// Algorithm specified in the RRSIG
        rrsig: Algorithm,
        /// Algorithm supported in the DNSKEY
        dnskey: Algorithm,
    },

    /// A DnsKey verification of rrset and rrsig failed
    #[error("dnskey and rrset failed to verify: {name} key_tag: {key_tag}")]
    DnsKeyVerifyRrsig {
        /// The name/label of the DNSKEY
        name: Name,
        /// The key tag derived from the DNSKEY
        key_tag: u16,
        /// The Error that occurred during validation
        error: ProtoError,
    },

    /// There was no DNSKEY found for verifying the DNSSEC of the zone
    #[error("no dnskey was found: {name}")]
    DnskeyNotFound {
        /// The name of the missing DNSKEY
        name: Name,
    },

    /// A DnsKey was revoked and could not be used for validation
    #[error("dnskey revoked: {name}, key_tag: {key_tag}")]
    DnsKeyRevoked {
        /// The name of the DNSKEY that was revoked
        name: Name,
        /// The key tag derived from the DNSKEY
        key_tag: u16,
    },

    /// The DNSKEY is not covered by a DS record
    #[error("dnskey has no ds: {name}")]
    DnsKeyHasNoDs {
        /// The name of the DNSKEY
        name: Name,
    },

    /// DS record exists but not a DNSKEY that matches
    #[error("ds record exists, but no dnskey: {name}")]
    DsRecordsButNoDnskey {
        /// Name of the missing DNSKEY
        name: Name,
    },

    /// DS record parent exists, but child does not
    #[error("ds record should exist: {name}")]
    DsRecordShouldExist {
        /// Name fo the missing DS key
        name: Name,
    },

    /// DS record does not exist, and this was proven with an NSEC
    #[error("ds record does not exist: {name}")]
    DsResponseNsec {
        /// The name of the DS record
        name: Name,
    },

    /// An error ocurred while calculating the DNSKEY key tag
    #[error("internal error computing the key tag for: {name}")]
    ErrorComputingKeyTag {
        /// The name of the DNSKEY record
        name: Name,
    },

    /// The DNSKEY used was not verified as secure
    #[error("dnskey insecure: {name}, key_tag: {key_tag}")]
    InsecureDnsKey {
        /// The name of the DNSKEY
        name: Name,
        /// The key tag derived from the DNSKEY
        key_tag: u16,
    },

    /// The DnsKey is not marked as a zone key
    #[error("not a zone signing key: {name} key_tag: {key_tag}")]
    NotZoneDnsKey {
        /// Name of the DNSKEY
        name: Name,
        /// The key tag derived from the DNSKEY
        key_tag: u16,
    },

    /// There was a protocol error when looking up DNSSEC records
    #[error("communication failure for query: {query}: {net}")]
    Net {
        /// Query that failed
        query: Query,
        /// Reasons fo the failure
        net: NetError,
    },

    /// The RRSIGs for the rrset are not present.
    ///    It's indeterminate if DS records can't be found
    ///    It's bogus if the DS records are present
    #[error("rrsigs are not present for: {name} record_type: {record_type}")]
    RrsigsNotPresent {
        /// Name that RRSIGS are missing for
        name: Name,
        /// The record type in question
        record_type: RecordType,
    },

    /// The RRSIGs could not be verified or failed validation
    #[error("rrsigs were not able to be verified: {name}, type: {record_type}")]
    RrsigsUnverified {
        /// Name that RRSIGS failed for
        name: Name,
        /// The record type in question
        record_type: RecordType,
    },

    /// Unknown or reserved key algorithm
    #[error("unknown or reserved key algorithm")]
    UnknownKeyAlgorithm,

    /// Unsupported key algorithms
    #[error("unsupported key algorithms")]
    UnsupportedKeyAlgorithm,
}

/// The error type for dnssec errors that get returned in the crate
#[non_exhaustive]
#[derive(Debug, Clone, Error)]
pub struct ProofError {
    /// The proof derived from the failed state
    pub proof: Proof,
    /// The kind of error
    pub kind: Box<ProofErrorKind>,
}

impl ProofError {
    /// Create an error with the given Proof and Associated Error
    pub fn new(proof: Proof, kind: ProofErrorKind) -> Self {
        Self {
            proof,
            kind: Box::new(kind),
        }
    }

    /// Get the kind of the error
    pub fn kind(&self) -> &ProofErrorKind {
        &self.kind
    }

    /// Returns an error related to the absence of a DS record
    pub fn ds_should_exist(name: Name) -> Self {
        Self {
            proof: Proof::Bogus,
            kind: Box::new(ProofErrorKind::DsRecordShouldExist { name }),
        }
    }
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.proof, self.kind)
    }
}
