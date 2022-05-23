// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TSIG for secret key authentication of transaction
#![allow(clippy::use_self)]

use std::convert::TryInto;
use std::fmt;

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use crate::rr::rdata::sshfp;

use crate::error::*;
use crate::op::{Header, Message, Query};
use crate::rr::dns_class::DNSClass;
use crate::rr::dnssec::rdata::DNSSECRData;
use crate::rr::record_data::RData;
use crate::rr::record_type::RecordType;
use crate::rr::{Name, Record};
use crate::serialize::binary::*;

/// [RFC 8945, Secret Key Transaction Authentication for DNS](https://tools.ietf.org/html/rfc8945#section-4.2)
///
/// ```text
///   4.2.  TSIG Record Format
///
///   The fields of the TSIG RR are described below.  All multi-octet
///   integers in the record are sent in network byte order (see
///   Section 2.3.2 of [RFC1035]).
///
///   NAME:  The name of the key used, in domain name syntax.  The name
///      should reflect the names of the hosts and uniquely identify the
///      key among a set of keys these two hosts may share at any given
///      time.  For example, if hosts A.site.example and B.example.net
///      share a key, possibilities for the key name include
///      <id>.A.site.example, <id>.B.example.net, and
///      <id>.A.site.example.B.example.net.  It should be possible for more
///      than one key to be in simultaneous use among a set of interacting
///      hosts.  This allows for periodic key rotation as per best
///      operational practices, as well as algorithm agility as indicated
///      by [RFC7696].
///
///      The name may be used as a local index to the key involved, but it
///      is recommended that it be globally unique.  Where a key is just
///      shared between two hosts, its name actually need only be
///      meaningful to them, but it is recommended that the key name be
///      mnemonic and incorporate the names of participating agents or
///      resources as suggested above.
///
///   TYPE:  This MUST be TSIG (250: Transaction SIGnature).
///
///   CLASS:  This MUST be ANY.
///
///   TTL:  This MUST be 0.
///
///   RDLENGTH:  (variable)
///
///   RDATA:  The RDATA for a TSIG RR consists of a number of fields,
///      described below:
///
///                            1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       /                         Algorithm Name                        /
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |                                                               |
///       |          Time Signed          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |                               |            Fudge              |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |          MAC Size             |                               /
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+             MAC               /
///       /                                                               /
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |          Original ID          |            Error              |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |          Other Len            |                               /
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+           Other Data          /
///       /                                                               /
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
///   The contents of the RDATA fields are:
///
///   Algorithm Name:
///      an octet sequence identifying the TSIG algorithm in the domain
///      name syntax.  (Allowed names are listed in Table 3.)  The name is
///      stored in the DNS name wire format as described in [RFC1034].  As
///      per [RFC3597], this name MUST NOT be compressed.
///
///   Time Signed:
///      an unsigned 48-bit integer containing the time the message was
///      signed as seconds since 00:00 on 1970-01-01 UTC, ignoring leap
///      seconds.
///
///   Fudge:
///      an unsigned 16-bit integer specifying the allowed time difference
///      in seconds permitted in the Time Signed field.
///
///   MAC Size:
///      an unsigned 16-bit integer giving the length of the MAC field in
///      octets.  Truncation is indicated by a MAC Size less than the size
///      of the keyed hash produced by the algorithm specified by the
///      Algorithm Name.
///
///   MAC:
///      a sequence of octets whose contents are defined by the TSIG
///      algorithm used, possibly truncated as specified by the MAC Size.
///      The length of this field is given by the MAC Size.  Calculation of
///      the MAC is detailed in Section 4.3.
///
///   Original ID:
///      an unsigned 16-bit integer holding the message ID of the original
///      request message.  For a TSIG RR on a request, it is set equal to
///      the DNS message ID.  In a TSIG attached to a response -- or in
///      cases such as the forwarding of a dynamic update request -- the
///      field contains the ID of the original DNS request.
///
///   Error:
///      in responses, an unsigned 16-bit integer containing the extended
///      RCODE covering TSIG processing.  In requests, this MUST be zero.
///
///   Other Len:
///      an unsigned 16-bit integer specifying the length of the Other Data
///      field in octets.
///
///   Other Data:
///      additional data relevant to the TSIG record.  In responses, this
///      will be empty (i.e., Other Len will be zero) unless the content of
///      the Error field is BADTIME, in which case it will be a 48-bit
///      unsigned integer containing the server's current time as the
///      number of seconds since 00:00 on 1970-01-01 UTC, ignoring leap
///      seconds (see Section 5.2.3).  This document assigns no meaning to
///      its contents in requests.
/// ```
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct TSIG {
    algorithm: TsigAlgorithm,
    time: u64,
    fudge: u16,
    mac: Vec<u8>,
    oid: u16,
    error: u16,
    other: Vec<u8>,
}

/// Algorithm used to authenticate communication
///
/// [RFC8945 Secret Key Transaction Authentication for DNS](https://tools.ietf.org/html/rfc8945#section-6)
/// ```text
///      +==========================+================+=================+
///      | Algorithm Name           | Implementation | Use             |
///      +==========================+================+=================+
///      | HMAC-MD5.SIG-ALG.REG.INT | MAY            | MUST NOT        |
///      +--------------------------+----------------+-----------------+
///      | gss-tsig                 | MAY            | MAY             |
///      +--------------------------+----------------+-----------------+
///      | hmac-sha1                | MUST           | NOT RECOMMENDED |
///      +--------------------------+----------------+-----------------+
///      | hmac-sha224              | MAY            | MAY             |
///      +--------------------------+----------------+-----------------+
///      | hmac-sha256              | MUST           | RECOMMENDED     |
///      +--------------------------+----------------+-----------------+
///      | hmac-sha256-128          | MAY            | MAY             |
///      +--------------------------+----------------+-----------------+
///      | hmac-sha384              | MAY            | MAY             |
///      +--------------------------+----------------+-----------------+
///      | hmac-sha384-192          | MAY            | MAY             |
///      +--------------------------+----------------+-----------------+
///      | hmac-sha512              | MAY            | MAY             |
///      +--------------------------+----------------+-----------------+
///      | hmac-sha512-256          | MAY            | MAY             |
///      +--------------------------+----------------+-----------------+
/// ```
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum TsigAlgorithm {
    /// HMAC-MD5.SIG-ALG.REG.INT (not supported for cryptographic operations)
    HmacMd5,
    /// gss-tsig (not supported for cryptographic operations)
    Gss,
    /// hmac-sha1 (not supported for cryptographic operations)
    HmacSha1,
    /// hmac-sha224 (not supported for cryptographic operations)
    HmacSha224,
    /// hmac-sha256
    HmacSha256,
    /// hmac-sha256-128 (not supported for cryptographic operations)
    HmacSha256_128,
    /// hmac-sha384
    HmacSha384,
    /// hmac-sha384-192 (not supported for cryptographic operations)
    HmacSha384_192,
    /// hmac-sha512
    HmacSha512,
    /// hmac-sha512-256 (not supported for cryptographic operations)
    HmacSha512_256,
    /// Unkown algorithm
    Unknown(Name),
}

impl TSIG {
    /// Constructs a new TSIG
    ///
    /// [RFC 8945, Secret Key Transaction Authentication for DNS](https://tools.ietf.org/html/rfc8945#section-4.1)
    ///
    /// ```text
    /// 4.1.  TSIG RR Type
    ///
    ///   To provide secret key authentication, we use an RR type whose
    ///   mnemonic is TSIG and whose type code is 250.  TSIG is a meta-RR and
    ///   MUST NOT be cached.  TSIG RRs are used for authentication between DNS
    ///   entities that have established a shared secret key.  TSIG RRs are
    ///   dynamically computed to cover a particular DNS transaction and are
    ///   not DNS RRs in the usual sense.
    ///
    ///   As the TSIG RRs are related to one DNS request/response, there is no
    ///   value in storing or retransmitting them; thus, the TSIG RR is
    ///   discarded once it has been used to authenticate a DNS message.
    /// ```
    pub fn new(
        algorithm: TsigAlgorithm,
        time: u64,
        fudge: u16,
        mac: Vec<u8>,
        oid: u16,
        error: u16,
        other: Vec<u8>,
    ) -> Self {
        Self {
            algorithm,
            time,
            fudge,
            mac,
            oid,
            error,
            other,
        }
    }

    /// Returns the Mac in this TSIG
    pub fn mac(&self) -> &[u8] {
        &self.mac
    }

    /// Returns the time this TSIG was generated at
    pub fn time(&self) -> u64 {
        self.time
    }

    /// Returns the max delta from `time` for remote to accept the signature
    pub fn fudge(&self) -> u16 {
        self.fudge
    }

    /// Returns the algorithm used for the authentication code
    pub fn algorithm(&self) -> &TsigAlgorithm {
        &self.algorithm
    }

    /// Emit TSIG RR and RDATA as used for computing MAC
    ///
    /// ```text
    /// 4.3.3.  TSIG Variables
    ///
    ///    Also included in the digest is certain information present in the
    ///    TSIG RR.  Adding this data provides further protection against an
    ///    attempt to interfere with the message.
    ///
    ///    +============+================+====================================+
    ///    | Source     | Field Name     | Notes                              |
    ///    +============+================+====================================+
    ///    | TSIG RR    | NAME           | Key name, in canonical wire format |
    ///    +------------+----------------+------------------------------------+
    ///    | TSIG RR    | CLASS          | MUST be ANY                        |
    ///    +------------+----------------+------------------------------------+
    ///    | TSIG RR    | TTL            | MUST be 0                          |
    ///    +------------+----------------+------------------------------------+
    ///    | TSIG RDATA | Algorithm Name | in canonical wire format           |
    ///    +------------+----------------+------------------------------------+
    ///    | TSIG RDATA | Time Signed    | in network byte order              |
    ///    +------------+----------------+------------------------------------+
    ///    | TSIG RDATA | Fudge          | in network byte order              |
    ///    +------------+----------------+------------------------------------+
    ///    | TSIG RDATA | Error          | in network byte order              |
    ///    +------------+----------------+------------------------------------+
    ///    | TSIG RDATA | Other Len      | in network byte order              |
    ///    +------------+----------------+------------------------------------+
    ///    | TSIG RDATA | Other Data     | exactly as transmitted             |
    ///    +------------+----------------+------------------------------------+
    /// ```
    pub fn emit_tsig_for_mac(
        &self,
        encoder: &mut BinEncoder<'_>,
        key_name: &Name,
    ) -> ProtoResult<()> {
        key_name.emit_as_canonical(encoder, true)?;
        DNSClass::ANY.emit(encoder)?;
        encoder.emit_u32(0)?; // TTL
        self.algorithm.emit(encoder)?;
        encoder.emit_u16((self.time >> 32) as u16)?;
        encoder.emit_u32(self.time as u32)?;
        encoder.emit_u16(self.fudge)?;
        encoder.emit_u16(self.error)?;
        encoder.emit_u16(self.other.len() as u16)?;
        encoder.emit_vec(&self.other)?;
        Ok(())
    }

    /// Add actual MAC value to existing TSIG record data.
    ///
    /// # Arguments
    ///
    /// * `mac` - mac to be stored in this record.
    pub fn set_mac(self, mac: Vec<u8>) -> Self {
        Self { mac, ..self }
    }
}

/// Read the RData from the given Decoder
///
/// ```text
///                       1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  /                         Algorithm Name                        /
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                                                               |
///  |          Time Signed          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                               |            Fudge              |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |          MAC Size             |                               /
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+             MAC               /
///  /                                                               /
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |          Original ID          |            Error              |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |          Other Len            |                               /
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+           Other Data          /
///  /                                                               /
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub fn read(decoder: &mut BinDecoder<'_>, rdata_length: Restrict<u16>) -> ProtoResult<TSIG> {
    let end_idx = rdata_length.map(|rdl| rdl as usize)
        .checked_add(decoder.index())
        .map_err(|_| ProtoError::from("rdata end position overflow"))? // no legal message is long enough to trigger that
        .unverified(/*used only as length safely*/);

    let algorithm = TsigAlgorithm::read(decoder)?;
    let time_high = decoder.read_u16()?.unverified(/*valid as any u16*/) as u64;
    let time_low = decoder.read_u32()?.unverified(/*valid as any u32*/) as u64;
    let time = (time_high << 32) | time_low;
    let fudge = decoder.read_u16()?.unverified(/*valid as any u16*/);
    let mac_size = decoder
        .read_u16()?
        .verify_unwrap(|&size| decoder.index() + size as usize + 6 /* 3 u16 */ <= end_idx)
        .map_err(|_| ProtoError::from("invalid mac length in TSIG"))?;
    let mac =
        decoder.read_vec(mac_size as usize)?.unverified(/*valid as any vec of the right size*/);
    let oid = decoder.read_u16()?.unverified(/*valid as any u16*/);
    let error = decoder.read_u16()?.unverified(/*valid as any u16*/);
    let other_len = decoder
        .read_u16()?
        .verify_unwrap(|&size| decoder.index() + size as usize == end_idx)
        .map_err(|_| ProtoError::from("invalid other length in TSIG"))?;
    let other =
        decoder.read_vec(other_len as usize)?.unverified(/*valid as any vec of the right size*/);

    Ok(TSIG {
        algorithm,
        time,
        fudge,
        mac,
        oid,
        error,
        other,
    })
}

/// Write the RData from the given Encoder
///
/// ```text
///                       1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  /                         Algorithm Name                        /
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                                                               |
///  |          Time Signed          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                               |            Fudge              |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |          MAC Size             |                               /
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+             MAC               /
///  /                                                               /
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |          Original ID          |            Error              |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |          Other Len            |                               /
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+           Other Data          /
///  /                                                               /
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub fn emit(encoder: &mut BinEncoder<'_>, tsig: &TSIG) -> ProtoResult<()> {
    tsig.algorithm.emit(encoder)?;
    encoder.emit_u16(
        (tsig.time >> 32)
            .try_into()
            .map_err(|_| ProtoError::from("invalid time, overflow 48 bit counter in TSIG"))?,
    )?;
    encoder.emit_u32(tsig.time as u32)?; // this cast is supposed to truncate
    encoder.emit_u16(tsig.fudge)?;
    encoder.emit_u16(
        tsig.mac
            .len()
            .try_into()
            .map_err(|_| ProtoError::from("invalid mac, longer than 65535 B in TSIG"))?,
    )?;
    encoder.emit_vec(&tsig.mac)?;
    encoder.emit_u16(tsig.oid)?;
    encoder.emit_u16(tsig.error)?;
    encoder.emit_u16(
        tsig.other
            .len()
            .try_into()
            .map_err(|_| ProtoError::from("invalid other_buffer, longer than 65535 B in TSIG"))?,
    )?;
    encoder.emit_vec(&tsig.other)?;
    Ok(())
}

// Does not appear to have a normalized text representation
impl fmt::Display for TSIG {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{algorithm} {time} {fudge} {mac} {oid} {error} {other}",
            algorithm = self.algorithm,
            time = self.time,
            fudge = self.fudge,
            mac = sshfp::HEX.encode(&self.mac),
            oid = self.oid,
            error = self.error,
            other = sshfp::HEX.encode(&self.other),
        )
    }
}

impl TsigAlgorithm {
    /// Return DNS name for the algorithm
    pub fn to_name(&self) -> Name {
        use TsigAlgorithm::*;
        match self {
            HmacMd5 => Name::from_ascii("HMAC-MD5.SIG-ALG.REG.INT"),
            Gss => Name::from_ascii("gss-tsig"),
            HmacSha1 => Name::from_ascii("hmac-sha1"),
            HmacSha224 => Name::from_ascii("hmac-sha224"),
            HmacSha256 => Name::from_ascii("hmac-sha256"),
            HmacSha256_128 => Name::from_ascii("hmac-sha256-128"),
            HmacSha384 => Name::from_ascii("hmac-sha384"),
            HmacSha384_192 => Name::from_ascii("hmac-sha384-192"),
            HmacSha512 => Name::from_ascii("hmac-sha512"),
            HmacSha512_256 => Name::from_ascii("hmac-sha512-256"),
            Unknown(name) => Ok(name.clone()),
        }.unwrap(/* should not fail with static strings*/)
    }

    /// Write the Algorithm to the given encoder
    pub fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        self.to_name().emit_as_canonical(encoder, true)?;
        Ok(())
    }

    /// Read the Algorithm from the given Encoder
    pub fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<Self> {
        let mut name = Name::read(decoder)?;
        name.set_fqdn(false);
        Ok(Self::from_name(name))
    }

    /// Convert a DNS name to an Algorithm
    pub fn from_name(name: Name) -> Self {
        use TsigAlgorithm::*;
        match name.to_ascii().as_str() {
            "HMAC-MD5.SIG-ALG.REG.INT" => HmacMd5,
            "gss-tsig" => Gss,
            "hmac-sha1" => HmacSha1,
            "hmac-sha224" => HmacSha224,
            "hmac-sha256" => HmacSha256,
            "hmac-sha256-128" => HmacSha256_128,
            "hmac-sha384" => HmacSha384,
            "hmac-sha384-192" => HmacSha384_192,
            "hmac-sha512" => HmacSha512,
            "hmac-sha512-256" => HmacSha512_256,
            _ => Unknown(name),
        }
    }

    // TODO: remove this once trust-dns-client no longer has dnssec feature enabled by default
    #[cfg(not(any(feature = "ring", feature = "openssl")))]
    #[doc(hidden)]
    #[allow(clippy::unimplemented)]
    pub fn mac_data(&self, _key: &[u8], _message: &[u8]) -> ProtoResult<Vec<u8>> {
        unimplemented!("one of dnssec-ring or dnssec-openssl features must be enabled")
    }

    /// Compute the Message Authentication Code using key and algorithm
    ///
    /// Supported algorithm are HmacSha256, HmacSha384, HmacSha512 and HmacSha512_256
    /// Other algorithm return an error.
    #[cfg(feature = "ring")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ring")))]
    pub fn mac_data(&self, key: &[u8], message: &[u8]) -> ProtoResult<Vec<u8>> {
        use ring::hmac;
        use TsigAlgorithm::*;

        let key = match self {
            HmacSha256 => hmac::Key::new(hmac::HMAC_SHA256, key),
            HmacSha384 => hmac::Key::new(hmac::HMAC_SHA384, key),
            HmacSha512 => hmac::Key::new(hmac::HMAC_SHA512, key),
            _ => return Err(ProtoError::from("unsupported mac algorithm")),
        };

        let mac = hmac::sign(&key, message);
        let res = mac.as_ref().to_vec();

        Ok(res)
    }

    /// Compute the Message Authentication Code using key and algorithm
    ///
    /// Supported algorithm are HmacSha256, HmacSha384, HmacSha512 and HmacSha512_256
    /// Other algorithm return an error.
    #[cfg(all(not(feature = "ring"), feature = "openssl"))]
    #[cfg_attr(docsrs, doc(cfg(all(not(feature = "ring"), feature = "openssl"))))]
    pub fn mac_data(&self, key: &[u8], message: &[u8]) -> ProtoResult<Vec<u8>> {
        use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
        use TsigAlgorithm::*;

        let key = PKey::hmac(key)?;

        let mut signer = match self {
            HmacSha256 => Signer::new(MessageDigest::sha256(), &key)?,
            HmacSha384 => Signer::new(MessageDigest::sha384(), &key)?,
            HmacSha512 => Signer::new(MessageDigest::sha512(), &key)?,
            _ => return Err(ProtoError::from("unsupported mac algorithm")),
        };

        signer.update(message)?;
        signer.sign_to_vec().map_err(|e| e.into())
    }

    // TODO: remove this once trust-dns-client no longer has dnssec feature enabled by default
    #[cfg(not(any(feature = "ring", feature = "openssl")))]
    #[doc(hidden)]
    #[allow(clippy::unimplemented)]
    pub fn verify_mac(&self, _key: &[u8], _message: &[u8], _tag: &[u8]) -> ProtoResult<()> {
        unimplemented!("one of dnssec-ring or dnssec-openssl features must be enabled")
    }

    /// Verifies the hmac tag against the given key and this algorithm.
    ///
    /// This is both faster than independently creating the MAC and also constant time preventing timing attacks
    #[cfg(feature = "ring")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ring")))]
    pub fn verify_mac(&self, key: &[u8], message: &[u8], tag: &[u8]) -> ProtoResult<()> {
        use ring::hmac;
        use TsigAlgorithm::*;

        let key = match self {
            HmacSha256 => hmac::Key::new(hmac::HMAC_SHA256, key),
            HmacSha384 => hmac::Key::new(hmac::HMAC_SHA384, key),
            HmacSha512 => hmac::Key::new(hmac::HMAC_SHA512, key),
            _ => return Err(ProtoError::from("unsupported mac algorithm")),
        };

        hmac::verify(&key, message, tag).map_err(|_| ProtoErrorKind::HmacInvalid().into())
    }

    /// Verifies the hmac tag against the given key and this algorithm.
    ///
    /// This is constant time preventing timing attacks
    #[cfg(all(not(feature = "ring"), feature = "openssl"))]
    #[cfg_attr(docsrs, doc(cfg(all(not(feature = "ring"), feature = "openssl"))))]
    pub fn verify_mac(&self, key: &[u8], message: &[u8], tag: &[u8]) -> ProtoResult<()> {
        use openssl::memcmp;

        let hmac = self.mac_data(key, message)?;
        if memcmp::eq(&hmac, tag) {
            Ok(())
        } else {
            Err(ProtoErrorKind::HmacInvalid().into())
        }
    }

    // TODO: remove this once trust-dns-client no longer has dnssec feature enabled by default
    #[cfg(not(any(feature = "ring", feature = "openssl")))]
    #[doc(hidden)]
    #[allow(clippy::unimplemented)]
    pub fn output_len(&self) -> ProtoResult<usize> {
        unimplemented!("one of dnssec-ring or dnssec-openssl features must be enabled")
    }

    /// Return length in bytes of the algorithms output
    #[cfg(feature = "ring")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ring")))]
    pub fn output_len(&self) -> ProtoResult<usize> {
        use ring::hmac;
        use TsigAlgorithm::*;

        let len = match self {
            HmacSha256 => hmac::HMAC_SHA256.digest_algorithm().output_len,
            HmacSha384 => hmac::HMAC_SHA384.digest_algorithm().output_len,
            HmacSha512 => hmac::HMAC_SHA512.digest_algorithm().output_len,
            _ => return Err(ProtoError::from("unsupported mac algorithm")),
        };

        Ok(len)
    }

    /// Return length in bytes of the algorithms output
    #[cfg(all(not(feature = "ring"), feature = "openssl"))]
    #[cfg_attr(docsrs, doc(cfg(all(not(feature = "ring"), feature = "openssl"))))]
    pub fn output_len(&self) -> ProtoResult<usize> {
        use openssl::hash::MessageDigest;
        use TsigAlgorithm::*;

        let len = match self {
            HmacSha256 => MessageDigest::sha256().size(),
            HmacSha384 => MessageDigest::sha384().size(),
            HmacSha512 => MessageDigest::sha512().size(),
            _ => return Err(ProtoError::from("unsupported mac algorithm")),
        };

        Ok(len)
    }

    /// Return true if cryptographic operations needed for using this algorithm are supported,
    /// false otherwise
    pub fn supported(&self) -> bool {
        use TsigAlgorithm::*;
        matches!(self, HmacSha256 | HmacSha384 | HmacSha512)
    }
}

impl fmt::Display for TsigAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.to_name())
    }
}

/// Return the byte-message to be authenticated with a TSIG
///
/// # Arguments
///
/// * `previous_hash` - hash of previous message in case of message chaining, or of query in case
/// of response. Should be None for query
/// * `message` - the message to authenticate. Should not be modified after calling message_tbs
/// except for adding the TSIG record
/// * `pre_tsig` - TSIG rrdata, possibly with missing mac. Should not be modified in any other way
/// after callin message_tbs
/// * `key_name` - name of they key, should be the same as the name known by the remove
/// server/client
pub fn message_tbs<M: BinEncodable>(
    previous_hash: Option<&[u8]>,
    message: &M,
    pre_tsig: &TSIG,
    key_name: &Name,
) -> ProtoResult<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut encoder: BinEncoder<'_> = BinEncoder::with_mode(&mut buf, EncodeMode::Normal);

    if let Some(previous_hash) = previous_hash {
        encoder.emit_u16(previous_hash.len() as u16)?;
        encoder.emit_vec(previous_hash)?;
    };
    message.emit(&mut encoder)?;
    pre_tsig.emit_tsig_for_mac(&mut encoder, key_name)?;
    Ok(buf)
}

/// Return the byte-message that would have been used to generate a TSIG
///
/// # Arguments
///
/// * `previous_hash` - hash of previous message in case of message chaining, or of query in case
/// of response. Should be None for query
/// * `message` - the byte-message to authenticate, with included TSIG
pub fn signed_bitmessage_to_buf(
    previous_hash: Option<&[u8]>,
    message: &[u8],
    first_message: bool,
) -> ProtoResult<(Vec<u8>, Record)> {
    let mut decoder = BinDecoder::new(message);

    // remove the tsig from Additional count
    let mut header = Header::read(&mut decoder)?;
    let adc = header.additional_count();
    if adc > 0 {
        header.set_additional_count(adc - 1);
    } else {
        return Err(ProtoError::from(
            "missing tsig from response that must be authenticated",
        ));
    }

    // keep position of data start
    let start_data = message.len() - decoder.len();

    let count = header.query_count();
    for _ in 0..count {
        Query::read(&mut decoder)?;
    }

    // read all records except for the last one (tsig)
    let record_count = header.answer_count() as usize
        + header.name_server_count() as usize
        + header.additional_count() as usize;
    Message::read_records(&mut decoder, record_count, false)?;

    // keep position of data end
    let end_data = message.len() - decoder.len();

    // parse a tsig record
    let sig = Record::read(&mut decoder)?;
    let tsig = if let (RecordType::TSIG, Some(RData::DNSSEC(DNSSECRData::TSIG(tsig_data)))) =
        (sig.rr_type(), sig.data())
    {
        tsig_data
    } else {
        return Err(ProtoError::from("signature is not tsig"));
    };
    header.set_id(tsig.oid);

    let mut buf = Vec::with_capacity(message.len());
    let mut encoder = BinEncoder::new(&mut buf);

    // prepend previous Mac if it exists
    if let Some(previous_hash) = previous_hash {
        encoder.emit_u16(previous_hash.len() as u16)?;
        encoder.emit_vec(previous_hash)?;
    }

    // emit header without tsig
    header.emit(&mut encoder)?;
    // copy all records verbatim, without decompressing it
    encoder.emit_vec(&message[start_data..end_data])?;
    if first_message {
        // emit the tsig pseudo-record for first message
        tsig.emit_tsig_for_mac(&mut encoder, sig.name())?;
    } else {
        // emit only time and fudge for followings
        encoder.emit_u16((tsig.time >> 32) as u16)?;
        encoder.emit_u32(tsig.time as u32)?;
        encoder.emit_u16(tsig.fudge)?;
    }

    Ok((buf, sig))
}

/// Helper function to make a TSIG record from the name of the key, and the TSIG RData
pub fn make_tsig_record(name: Name, rdata: TSIG) -> Record {
    // https://tools.ietf.org/html/rfc8945#section-4.2

    let mut tsig = Record::new();

    //   NAME:  The name of the key used, in domain name syntax
    tsig.set_name(name)
        //   TYPE:  This MUST be TSIG (250: Transaction SIGnature).
        .set_record_type(RecordType::TSIG)
        //   CLASS:  This MUST be ANY.
        .set_dns_class(DNSClass::ANY)
        //   TTL:  This MUST be 0.
        .set_ttl(0)
        .set_data(Some(DNSSECRData::TSIG(rdata).into()));
    tsig
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;
    use crate::rr::Record;

    fn test_encode_decode(rdata: TSIG) {
        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        emit(&mut encoder, &rdata).expect("failed to emit tsig");
        let bytes = encoder.into_bytes();

        println!("bytes: {:?}", bytes);

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let read_rdata =
            read(&mut decoder, Restrict::new(bytes.len() as u16)).expect("failed to read back");
        assert_eq!(rdata, read_rdata);
    }

    #[test]
    fn test_encode_decode_tsig() {
        test_encode_decode(TSIG::new(
            TsigAlgorithm::HmacSha256,
            0,
            300,
            vec![0, 1, 2, 3],
            0,
            0,
            vec![4, 5, 6, 7],
        ));
        test_encode_decode(TSIG::new(
            TsigAlgorithm::HmacSha384,
            123456789,
            60,
            vec![9, 8, 7, 6, 5, 4],
            1,
            2,
            vec![],
        ));
        test_encode_decode(TSIG::new(
            TsigAlgorithm::Unknown(Name::from_ascii("unkown_algorithm").unwrap()),
            123456789,
            60,
            vec![],
            1,
            2,
            vec![0, 1, 2, 3, 4, 5, 6],
        ));
    }

    #[test]
    fn test_sign_encode() {
        let mut message = Message::new();
        message.add_answer(Record::new());

        let key_name = Name::from_ascii("some.name").unwrap();

        let pre_tsig = TSIG::new(
            TsigAlgorithm::HmacSha256,
            12345,
            60,
            vec![],
            message.id(),
            0,
            vec![],
        );

        let tbs = message_tbs(None, &message, &pre_tsig, &key_name).unwrap();

        let pre_tsig = pre_tsig.set_mac(b"some signature".to_vec());

        let tsig = make_tsig_record(key_name, pre_tsig);

        message.add_tsig(tsig);

        let message_byte = message.to_bytes().unwrap();

        let tbv = signed_bitmessage_to_buf(None, &message_byte, true)
            .unwrap()
            .0;

        assert_eq!(tbs, tbv);
    }

    #[test]
    fn test_sign_encode_id_changed() {
        let mut message = Message::new();
        message.set_id(123).add_answer(Record::new());

        let key_name = Name::from_ascii("some.name").unwrap();

        let pre_tsig = TSIG::new(
            TsigAlgorithm::HmacSha256,
            12345,
            60,
            vec![],
            message.id(),
            0,
            vec![],
        );

        let tbs = message_tbs(None, &message, &pre_tsig, &key_name).unwrap();

        let pre_tsig = pre_tsig.set_mac(b"some signature".to_vec());

        let tsig = make_tsig_record(key_name, pre_tsig);

        message.add_tsig(tsig);

        let message_byte = message.to_bytes().unwrap();
        let mut message = Message::from_bytes(&message_byte).unwrap();

        message.set_id(456); // simulate the request id being changed due to request forwarding

        let message_byte = message.to_bytes().unwrap();

        let tbv = signed_bitmessage_to_buf(None, &message_byte, true)
            .unwrap()
            .0;

        assert_eq!(tbs, tbv);

        // sign and verify
        let key = &[0, 1, 2, 3, 4];

        let tag = TsigAlgorithm::HmacSha256.mac_data(key, &tbv).unwrap();

        TsigAlgorithm::HmacSha256
            .verify_mac(key, &tbv, &tag)
            .expect("did not verify")
    }
}
