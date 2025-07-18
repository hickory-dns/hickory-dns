// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TSIG for secret key authentication of transaction
#![allow(clippy::use_self)]

use alloc::vec::Vec;
use core::{convert::TryInto, fmt};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::DNSSECRData;
use crate::dnssec::tsig::TSigner;
use crate::op::MessageSignature;
use crate::{
    dnssec::{DnsSecError, DnsSecErrorKind, ring_like::hmac},
    error::{ProtoError, ProtoResult},
    op::{Header, Message, Query},
    rr::{
        Name, Record, RecordData, RecordDataDecodable, dns_class::DNSClass, rdata::sshfp,
        record_data::RData, record_type::RecordType,
    },
    serialize::binary::{
        BinDecodable, BinDecoder, BinEncodable, BinEncoder, EncodeMode, NameEncoding,
        RDataEncoding, Restrict, RestrictedMath,
    },
};

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
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct TSIG {
    algorithm: TsigAlgorithm,
    time: u64,
    fudge: u16,
    mac: Vec<u8>,
    oid: u16,
    error: Option<TsigError>,
    other: Vec<u8>,
}

impl TSIG {
    pub(crate) fn stub(oid: u16, time: u64, signer: &TSigner) -> Self {
        TSIG::new(
            signer.algorithm().clone(),
            time,
            signer.fudge(),
            Vec::new(),
            oid,
            None,
            Vec::new(),
        )
    }

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
        error: Option<TsigError>,
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

    /// Returns the TSIG error RCODE
    ///
    /// This is separate from the top-level error RCODE of a response
    /// See <https://www.rfc-editor.org/rfc/rfc8945.html#section-3>
    pub fn error(&self) -> &Option<TsigError> {
        &self.error
    }

    /// Set the TSIG error RCODE
    ///
    /// This is separate from the top-level error RCODE of a response
    /// See <https://www.rfc-editor.org/rfc/rfc8945.html#section-3>
    pub fn set_error(&mut self, error: TsigError) {
        self.error = Some(error)
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
        let mut encoder = encoder.with_name_encoding(NameEncoding::UncompressedLowercase);

        key_name.emit(&mut encoder)?;
        DNSClass::ANY.emit(&mut encoder)?;
        encoder.emit_u32(0)?; // TTL
        self.algorithm.emit(&mut encoder)?;
        encoder.emit_u16((self.time >> 32) as u16)?;
        encoder.emit_u32(self.time as u32)?;
        encoder.emit_u16(self.fudge)?;
        encoder.emit_u16(match self.error {
            None => 0,
            Some(err) => u16::from(err),
        })?;
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

impl BinEncodable for TSIG {
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
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        let mut encoder = encoder.with_rdata_behavior(RDataEncoding::Other);
        self.algorithm.emit(&mut encoder)?;
        encoder.emit_u16(
            (self.time >> 32)
                .try_into()
                .map_err(|_| ProtoError::from("invalid time, overflow 48 bit counter in TSIG"))?,
        )?;
        encoder.emit_u32(self.time as u32)?; // this cast is supposed to truncate
        encoder.emit_u16(self.fudge)?;
        encoder.emit_u16(
            self.mac
                .len()
                .try_into()
                .map_err(|_| ProtoError::from("invalid mac, longer than 65535 B in TSIG"))?,
        )?;
        encoder.emit_vec(&self.mac)?;
        encoder.emit_u16(self.oid)?;
        encoder.emit_u16(match self.error {
            None => 0,
            Some(err) => u16::from(err),
        })?;
        encoder.emit_u16(self.other.len().try_into().map_err(|_| {
            ProtoError::from("invalid other_buffer, longer than 65535 B in TSIG")
        })?)?;
        encoder.emit_vec(&self.other)?;
        Ok(())
    }
}

impl<'r> RecordDataDecodable<'r> for TSIG {
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
    fn read_data(decoder: &mut BinDecoder<'r>, length: Restrict<u16>) -> ProtoResult<Self> {
        let end_idx = length.map(|rdl| rdl as usize)
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
        let error = match decoder.read_u16()?.unverified(/*valid as any u16*/) {
            0 => None,
            code => Some(TsigError::from(code)),
        };
        let other_len = decoder
            .read_u16()?
            .verify_unwrap(|&size| decoder.index() + size as usize == end_idx)
            .map_err(|_| ProtoError::from("invalid other length in TSIG"))?;
        let other = decoder.read_vec(other_len as usize)?.unverified(/*valid as any vec of the right size*/);

        Ok(Self {
            algorithm,
            time,
            fudge,
            mac,
            oid,
            error,
            other,
        })
    }
}

impl RecordData for TSIG {
    fn try_borrow(data: &RData) -> Option<&Self> {
        match data {
            RData::DNSSEC(DNSSECRData::TSIG(csync)) => Some(csync),
            _ => None,
        }
    }

    fn record_type(&self) -> RecordType {
        RecordType::TSIG
    }

    fn into_rdata(self) -> RData {
        RData::DNSSEC(DNSSECRData::TSIG(self))
    }
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
            error = self.error.map(Into::into).unwrap_or(0),
            other = sshfp::HEX.encode(&self.other),
        )
    }
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
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum TsigAlgorithm {
    /// HMAC-MD5.SIG-ALG.REG.INT (not supported for cryptographic operations)
    #[cfg_attr(feature = "serde", serde(rename = "HMAC-MD5.SIG-ALG.REG.INT"))]
    HmacMd5,
    /// gss-tsig (not supported for cryptographic operations)
    #[cfg_attr(feature = "serde", serde(rename = "gss-tsig"))]
    Gss,
    /// hmac-sha1 (not supported for cryptographic operations)
    #[cfg_attr(feature = "serde", serde(rename = "hmac-sha1"))]
    HmacSha1,
    /// hmac-sha224 (not supported for cryptographic operations)
    #[cfg_attr(feature = "serde", serde(rename = "hmac-sha224"))]
    HmacSha224,
    /// hmac-sha256
    #[cfg_attr(feature = "serde", serde(rename = "hmac-sha256"))]
    HmacSha256,
    /// hmac-sha256-128 (not supported for cryptographic operations)
    #[cfg_attr(feature = "serde", serde(rename = "hmac-sha256-128"))]
    HmacSha256_128,
    /// hmac-sha384
    #[cfg_attr(feature = "serde", serde(rename = "hmac-sha384"))]
    HmacSha384,
    /// hmac-sha384-192 (not supported for cryptographic operations)
    #[cfg_attr(feature = "serde", serde(rename = "hmac-sha384-192"))]
    HmacSha384_192,
    /// hmac-sha512
    #[cfg_attr(feature = "serde", serde(rename = "hmac-sha512"))]
    HmacSha512,
    /// hmac-sha512-256 (not supported for cryptographic operations)
    #[cfg_attr(feature = "serde", serde(rename = "hmac-sha512-256"))]
    HmacSha512_256,
    /// Unknown algorithm
    Unknown(Name),
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

    /// Compute the Message Authentication Code using key and algorithm
    ///
    /// Supported algorithm are HmacSha256, HmacSha384, HmacSha512 and HmacSha512_256
    /// Other algorithm return an error.
    pub fn mac_data(&self, key: &[u8], message: &[u8]) -> Result<Vec<u8>, DnsSecError> {
        use TsigAlgorithm::*;

        let key = match self {
            HmacSha256 => hmac::Key::new(hmac::HMAC_SHA256, key),
            HmacSha384 => hmac::Key::new(hmac::HMAC_SHA384, key),
            HmacSha512 => hmac::Key::new(hmac::HMAC_SHA512, key),
            _ => return Err(DnsSecErrorKind::TsigUnsupportedMacAlgorithm(self.clone()).into()),
        };

        let mac = hmac::sign(&key, message);
        let res = mac.as_ref().to_vec();

        Ok(res)
    }

    /// Verifies the hmac tag against the given key and this algorithm.
    ///
    /// This is both faster than independently creating the MAC and also constant time preventing timing attacks
    pub fn verify_mac(&self, key: &[u8], message: &[u8], tag: &[u8]) -> Result<(), DnsSecError> {
        use TsigAlgorithm::*;

        let key = match self {
            HmacSha256 => hmac::Key::new(hmac::HMAC_SHA256, key),
            HmacSha384 => hmac::Key::new(hmac::HMAC_SHA384, key),
            HmacSha512 => hmac::Key::new(hmac::HMAC_SHA512, key),
            _ => return Err(DnsSecErrorKind::TsigUnsupportedMacAlgorithm(self.clone()).into()),
        };

        hmac::verify(&key, message, tag).map_err(|_| DnsSecErrorKind::HmacInvalid.into())
    }

    /// Return length in bytes of the algorithms output
    pub fn output_len(&self) -> Result<usize, DnsSecError> {
        use TsigAlgorithm::*;

        let len = match self {
            HmacSha256 => hmac::HMAC_SHA256.digest_algorithm().output_len(),
            HmacSha384 => hmac::HMAC_SHA384.digest_algorithm().output_len(),
            HmacSha512 => hmac::HMAC_SHA512.digest_algorithm().output_len(),
            _ => return Err(DnsSecErrorKind::TsigUnsupportedMacAlgorithm(self.clone()).into()),
        };

        Ok(len)
    }

    /// Return `true` if cryptographic operations needed for using this algorithm are supported,
    /// `false` otherwise
    ///
    /// ## Supported
    ///
    /// - HmacSha256
    /// - HmacSha384
    /// - HmacSha512
    /// - HmacSha512_256
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

impl BinEncodable for TsigAlgorithm {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        self.to_name().emit(encoder)
    }
}

impl BinDecodable<'_> for TsigAlgorithm {
    fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<Self> {
        let mut name = Name::read(decoder)?;
        name.set_fqdn(false);
        Ok(Self::from_name(name))
    }
}

/// A TSIG RR error rcode
///
/// See <https://www.rfc-editor.org/rfc/rfc8945.html#section-3>
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, Eq, PartialEq, PartialOrd, Copy, Clone, Hash)]
pub enum TsigError {
    /// Bad signature
    BadSig,
    /// Bad key
    BadKey,
    /// Bad signature time
    BadTime,
    /// Bad truncated request MAC
    BadTrunc,
    /// An unknown error
    Unknown(u16),
}

impl From<u16> for TsigError {
    fn from(value: u16) -> Self {
        match value {
            16 => Self::BadSig,
            17 => Self::BadKey,
            18 => Self::BadTime,
            22 => Self::BadTrunc,
            code => Self::Unknown(code),
        }
    }
}

impl From<TsigError> for u16 {
    fn from(value: TsigError) -> Self {
        match value {
            TsigError::BadSig => 16,
            TsigError::BadKey => 17,
            TsigError::BadTime => 18,
            TsigError::BadTrunc => 22,
            TsigError::Unknown(code) => code,
        }
    }
}

/// Return the to-be-signed data for authenticating the message with TSIG.
///
/// # Arguments
///
/// * `message` - the message to authenticate. Should not be modified after calling this function
///   except to add the final TSIG record
/// * `pre_tsig` - TSIG rrdata, possibly with missing MAC. Should not be modified in any other way
///   after calling this function.
/// * `key_name` - the name of the TSIG key, should be the same as the name known by the remote
///   peer.
pub fn message_tbs<M: BinEncodable>(
    message: &M,
    pre_tsig: &TSIG,
    key_name: &Name,
) -> ProtoResult<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    let mut encoder = BinEncoder::with_mode(&mut buf, EncodeMode::Normal);
    message.emit(&mut encoder)?;
    pre_tsig.emit_tsig_for_mac(&mut encoder, key_name)?;
    Ok(buf)
}

/// Return the byte-message that would have been used to generate a TSIG
///
/// # Arguments
///
/// * `previous_hash` - hash of previous message in case of message chaining, or of query in case
///   of response. Should be None for query
/// * `message` - the byte-message to authenticate, with included TSIG
/// * `first_message` - whether to emit the tsig pseudo-record for a first message
pub fn signed_bitmessage_to_buf(
    message: &[u8],
    previous_hash: Option<&[u8]>,
    first_message: bool,
) -> ProtoResult<(Vec<u8>, Record)> {
    let mut decoder = BinDecoder::new(message);
    let mut header = Header::read(&mut decoder)?;

    // Adjust the header additional count down by one - this separates out the final
    // additional data TSIG record.
    let adc = header.additional_count();
    if adc > 0 {
        header.set_additional_count(adc - 1);
    } else {
        return Err(ProtoError::from(
            "missing tsig from response that must be authenticated",
        ));
    }

    // Note the position of the decoder in the message, past the header, before reading any data.
    let start_data = message.len() - decoder.len();

    // Advance past the queries.
    let count = header.query_count();
    for _ in 0..count {
        Query::read(&mut decoder)?;
    }

    // Advance past answer and authority records together.
    let answer_authority_count = header.answer_count() as usize + header.authority_count() as usize;
    let (_, _, sig) = Message::read_records(&mut decoder, answer_authority_count, false)?;
    debug_assert_eq!(sig, MessageSignature::Unsigned);

    // Advance past additional records, up to the final TSIG record.
    let additional_count = header.additional_count() as usize;
    let (_, _, sig) = Message::read_records(&mut decoder, additional_count, true)?;
    debug_assert_eq!(sig, MessageSignature::Unsigned);

    // Note the position of the decoder ahead of the final additional data TSIG record.
    let end_data = message.len() - decoder.len();

    // Read the TSIG signature record.
    let (_, _, sig) = Message::read_records(&mut decoder, 1, true)?;
    let MessageSignature::Tsig(tsig_rr) = sig else {
        return Err(ProtoError::from("TSIG signature record not found"));
    };
    let Some(tsig) = tsig_rr.data().as_dnssec().and_then(DNSSECRData::as_tsig) else {
        return Err(ProtoError::from(
            "TSIG signature record invalid record data",
        ));
    };
    header.set_id(tsig.oid);

    // Construct the TBS data.
    let mut buf = Vec::with_capacity(message.len());
    let mut encoder = BinEncoder::new(&mut buf);

    // Prepend the previous hash if provided.
    if let Some(previous_hash) = previous_hash {
        encoder.emit_u16(previous_hash.len() as u16)?;
        encoder.emit_vec(previous_hash)?;
    }

    // Emit the header we modified to remove the TSIG additional record.
    header.emit(&mut encoder)?;

    // Emit all the message data between the header and the TSIG record.
    encoder.emit_vec(&message[start_data..end_data])?;

    if first_message {
        // Emit the TSIG pseudo-record when this is the first message.
        tsig.emit_tsig_for_mac(&mut encoder, tsig_rr.name())?;
    } else {
        // Emit only time and fudge data for later messages.
        encoder.emit_u16((tsig.time >> 32) as u16)?;
        encoder.emit_u32(tsig.time as u32)?;
        encoder.emit_u16(tsig.fudge)?;
    }

    Ok((buf, tsig_rr))
}

/// Helper function to make a TSIG record from the name of the key, and the TSIG RData
pub fn make_tsig_record(name: Name, rdata: TSIG) -> Record {
    // https://tools.ietf.org/html/rfc8945#section-4.2

    let mut tsig = Record::from_rdata(
        //   NAME:  The name of the key used, in domain name syntax
        name,
        //   TTL:  This MUST be 0.
        0,
        //   TYPE:  This MUST be TSIG (250: Transaction SIGnature).
        DNSSECRData::TSIG(rdata).into(),
    );

    //   CLASS:  This MUST be ANY.
    tsig.set_dns_class(DNSClass::ANY);
    tsig
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use std::println;

    use super::*;
    use crate::op::MessageSignature;
    use crate::rr::Record;

    fn test_encode_decode(rdata: TSIG) {
        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        rdata.emit(&mut encoder).expect("failed to emit tsig");
        let bytes = encoder.into_bytes();

        println!("bytes: {bytes:?}");

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let read_rdata = TSIG::read_data(&mut decoder, Restrict::new(bytes.len() as u16))
            .expect("failed to read back");
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
            None,
            vec![4, 5, 6, 7],
        ));
        test_encode_decode(TSIG::new(
            TsigAlgorithm::HmacSha384,
            123456789,
            60,
            vec![9, 8, 7, 6, 5, 4],
            1,
            Some(TsigError::BadKey),
            vec![],
        ));
        test_encode_decode(TSIG::new(
            TsigAlgorithm::Unknown(Name::from_ascii("unknown_algorithm").unwrap()),
            123456789,
            60,
            vec![],
            1,
            Some(TsigError::BadTime),
            vec![0, 1, 2, 3, 4, 5, 6],
        ));
        test_encode_decode(TSIG::new(
            TsigAlgorithm::Unknown(Name::from_ascii("unknown_algorithm").unwrap()),
            123456789,
            60,
            vec![],
            1,
            Some(TsigError::Unknown(420)),
            vec![0, 1, 2, 3, 4, 5, 6],
        ));
    }

    #[test]
    fn test_sign_encode() {
        let mut message = Message::query();
        message.add_answer(Record::stub());

        let key_name = Name::from_ascii("some.name").unwrap();

        let pre_tsig = TSIG::new(
            TsigAlgorithm::HmacSha256,
            12345,
            60,
            vec![],
            message.id(),
            None,
            vec![],
        );

        let tbs = message_tbs(&message, &pre_tsig, &key_name).unwrap();

        let pre_tsig = pre_tsig.set_mac(b"some signature".to_vec());

        message.set_signature(MessageSignature::Tsig(make_tsig_record(key_name, pre_tsig)));

        let message_byte = message.to_bytes().unwrap();

        let tbv = signed_bitmessage_to_buf(&message_byte, None, true)
            .unwrap()
            .0;

        assert_eq!(tbs, tbv);
    }

    #[test]
    fn test_sign_encode_id_changed() {
        let mut message = Message::query();
        message.set_id(123).add_answer(Record::stub());

        let key_name = Name::from_ascii("some.name").unwrap();

        let pre_tsig = TSIG::new(
            TsigAlgorithm::HmacSha256,
            12345,
            60,
            vec![],
            message.id(),
            None,
            vec![],
        );

        let tbs = message_tbs(&message, &pre_tsig, &key_name).unwrap();

        let pre_tsig = pre_tsig.set_mac(b"some signature".to_vec());

        message.set_signature(MessageSignature::Tsig(make_tsig_record(key_name, pre_tsig)));

        let message_byte = message.to_bytes().unwrap();
        let mut message = Message::from_bytes(&message_byte).unwrap();

        message.set_id(456); // simulate the request id being changed due to request forwarding

        let message_byte = message.to_bytes().unwrap();

        let tbv = signed_bitmessage_to_buf(&message_byte, None, true)
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
