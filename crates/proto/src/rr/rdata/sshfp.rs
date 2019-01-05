// TODO license

//! SSHFP records for SSH public key fingerprints

use error::*;
use serialize::binary::*;

/// [RFC 4255](https://tools.ietf.org/html/rfc4255#section-3.1)
///
/// ```text
/// 3.1.  The SSHFP RDATA Format
///
///    The RDATA for a SSHFP RR consists of an algorithm number, fingerprint
///    type and the fingerprint of the public host key.
///
///        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |   algorithm   |    fp type    |                               /
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
///        /                                                               /
///        /                          fingerprint                          /
///        /                                                               /
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// 3.1.3.  Fingerprint
///
///    The fingerprint is calculated over the public key blob as described
///    in [7].
///
///    The message-digest algorithm is presumed to produce an opaque octet
///    string output, which is placed as-is in the RDATA fingerprint field.
/// ```
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SSHFP {
    algorithm: Algorithm,
    fingerprint_type: FingerprintType,
    fingerprint: Vec<u8>,
}

impl SSHFP {
    /// Creates a new SSHFP record data.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - the SSH public key algorithm.
    /// * `fingerprint_type` - the fingerprint type to use.
    /// * `fingerprint` - the fingerprint of the public key.
    pub fn new(
        algorithm: Algorithm,
        fingerprint_type: FingerprintType,
        fingerprint: Vec<u8>,
    ) -> Self {
        SSHFP {
            algorithm,
            fingerprint_type,
            fingerprint,
        }
    }

    /// The SSH public key algorithm.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The fingerprint type to use.
    pub fn fingerprint_type(&self) -> FingerprintType {
        self.fingerprint_type
    }

    /// The fingerprint of the public key.
    pub fn fingerprint(&self) -> &[u8] {
        &self.fingerprint
    }
}

/// ```text
/// 3.1.1.  Algorithm Number Specification
///
///    This algorithm number octet describes the algorithm of the public
///    key.  The following values are assigned:
///
///           Value    Algorithm name
///           -----    --------------
///           0        reserved
///           1        RSA
///           2        DSS
///
///    Reserving other types requires IETF consensus [4].
/// ```text
///
/// The algorithm values have been updated in
/// [RFC 6594](https://tools.ietf.org/html/rfc6594) and
/// [RFC 7479](https://tools.ietf.org/html/rfc7479).
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Algorithm {
    /// Reserved value
    Reserved,

    /// RSA
    RSA,

    /// DSS/DSA
    DSA,

    /// ECDSA
    ECDSA,

    /// Ed25519
    Ed25519,

    /// Unassigned value
    Unassigned(u8),
}

impl From<u8> for Algorithm {
    fn from(alg: u8) -> Self {
        match alg {
            0 => Algorithm::Reserved,
            1 => Algorithm::RSA,
            2 => Algorithm::DSA,
            3 => Algorithm::ECDSA,
            4 => Algorithm::Ed25519, // TODO more (XMSS)
            _ => Algorithm::Unassigned(alg),
        }
    }
}

impl Into<u8> for Algorithm {
    fn into(self) -> u8 {
        match self {
            Algorithm::Reserved => 0,
            Algorithm::RSA => 1,
            Algorithm::DSA => 2,
            Algorithm::ECDSA => 3,
            Algorithm::Ed25519 => 4,
            Algorithm::Unassigned(alg) => alg,
        }
    }
}

/// ```text
/// 3.1.2.  Fingerprint Type Specification
///
///    The fingerprint type octet describes the message-digest algorithm
///    used to calculate the fingerprint of the public key.  The following
///    values are assigned:
///
///           Value    Fingerprint type
///           -----    ----------------
///           0        reserved
///           1        SHA-1
///
///    Reserving other types requires IETF consensus [4].
///
///    For interoperability reasons, as few fingerprint types as possible
///    should be reserved.  The only reason to reserve additional types is
///    to increase security.
/// ```
///
/// The fingerprint type values have been updated in
/// [RFC 6594](https://tools.ietf.org/html/rfc6594).
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum FingerprintType {
    /// Reserved value
    Reserved,

    /// SHA-1
    SHA1,

    /// SHA-256
    SHA256,

    /// Unassigned value
    Unassigned(u8),
}

impl From<u8> for FingerprintType {
    fn from(ft: u8) -> Self {
        match ft {
            0 => FingerprintType::Reserved,
            1 => FingerprintType::SHA1,
            2 => FingerprintType::SHA256,
            _ => FingerprintType::Unassigned(ft),
        }
    }
}

impl Into<u8> for FingerprintType {
    fn into(self) -> u8 {
        match self {
            FingerprintType::Reserved => 0,
            FingerprintType::SHA1 => 1,
            FingerprintType::SHA256 => 2,
            FingerprintType::Unassigned(ft) => ft,
        }
    }
}

/// Read the RData from the given decoder.
pub fn read(decoder: &mut BinDecoder, rdata_length: Restrict<u16>) -> ProtoResult<SSHFP> {
    let algorithm = decoder.read_u8()?.unverified().into();
    let fingerprint_type = decoder.read_u8()?.unverified().into();
    let fingerprint_len = rdata_length
        .map(|l| l as usize)
        .checked_sub(2)
        .map_err(|_| ProtoError::from("invalid rdata length in SSHFP"))?
        .unverified();
    let fingerprint = decoder.read_vec(fingerprint_len)?.unverified();
    Ok(SSHFP::new(algorithm, fingerprint_type, fingerprint))
}

/// Write the RData using the given encoder.
pub fn emit(encoder: &mut BinEncoder, sshfp: &SSHFP) -> ProtoResult<()> {
    encoder.emit_u8(sshfp.algorithm().into())?;
    encoder.emit_u8(sshfp.fingerprint_type().into())?;
    encoder.emit_vec(sshfp.fingerprint())
}

// TODO test
