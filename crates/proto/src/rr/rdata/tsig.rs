// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TSIG for secret key authentication of transaction
use std::fmt;

use super::sshfp;

use crate::error::*;
use crate::rr::dns_class::DNSClass;
use crate::rr::Name;
use crate::serialize::binary::*;

/// [RFC 2845, Secret Key Transaction Authentication for DNS](https://tools.ietf.org/html/rfc2845)
///
/// ```text
///   2.3. Record Format
///
///   NAME The name of the key used in domain name syntax.  The name
///        should reflect the names of the hosts and uniquely identify
///        the key among a set of keys these two hosts may share at any
///        given time.  If hosts A.site.example and B.example.net share a
///        key, possibilities for the key name include
///        <id>.A.site.example, <id>.B.example.net, and
///        <id>.A.site.example.B.example.net.  It should be possible for
///        more than one key to be in simultaneous use among a set of
///        interacting hosts.  The name only needs to be meaningful to
///        the communicating hosts but a meaningful mnemonic name as
///        above is strongly recommended.
///
///        The name may be used as a local index to the key involved and
///        it is recommended that it be globally unique.  Where a key is
///        just shared between two hosts, its name actually only need
///        only be meaningful to them but it is recommended that the key
///        name be mnemonic and incorporate the resolver and server host
///        names in that order.
///
///   TYPE TSIG (250: Transaction SIGnature)
///
///   CLASS ANY
///
///   TTL  0
///
///   RdLen (variable)
///
///   RDATA
///
///     Field Name       Data Type      Notes
///     --------------------------------------------------------------
///     Algorithm Name   domain-name    Name of the algorithm
///                                     in domain name syntax.
///     Time Signed      u_int48_t      seconds since 1-Jan-70 UTC.
///     Fudge            u_int16_t      seconds of error permitted
///                                     in Time Signed.
///     MAC Size         u_int16_t      number of octets in MAC.
///     MAC              octet stream   defined by Algorithm Name.
///     Original ID      u_int16_t      original message ID
///     Error            u_int16_t      expanded RCODE covering
///                                     TSIG processing.
///     Other Len        u_int16_t      length, in octets, of
///                                     Other Data.
///     Other Data       octet stream   empty unless Error == BADTIME
/// ```
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct TSIG {
    algorithm: Algorithm,
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
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Algorithm {
    /// HMAC-MD5.SIG-ALG.REG.INT
    HmacMd5,
    /// gss-tsig
    Gss,
    /// hmac-sha1
    HmacSha1,
    /// hmac-sha224
    HmacSha224,
    /// hmac-sha256
    HmacSha256,
    /// hmac-sha256-128
    HmacSha256_128,
    /// hmac-sha384
    HmacSha384,
    /// hmac-sha384-192
    HmacSha384_192,
    /// hmac-sha512
    HmacSha512,
    /// hmac-sha512-256
    HmacSha512_256,
    /// Unkown algorithm
    Unknown(Name),
}

impl TSIG {
    /// Constructs a new TSIG
    ///
    /// [RFC 2845, Secret Key Transaction Authentication for DNS](https://tools.ietf.org/html/rfc2845)
    ///
    /// ```text
    /// 2.1 TSIG RR Type
    ///
    ///   To provide secret key authentication, we use a new RR type whose
    ///   mnemonic is TSIG and whose type code is 250.  TSIG is a meta-RR and
    ///   MUST not be cached.  TSIG RRs are used for authentication between DNS
    ///   entities that have established a shared secret key.  TSIG RRs are
    ///   dynamically computed to cover a particular DNS transaction and are
    ///   not DNS RRs in the usual sense.
    /// ```
    pub fn new(
        algorithm: Algorithm,
        time: u64,
        fudge: u16,
        mac: Vec<u8>,
        oid: u16,
        error: u16,
        other: Vec<u8>,
    ) -> Self {
        // Should maybe not be a panic but return a Result::Err?
        assert!(time < (1 << 48));
        assert!(mac.len() < (1 << 16));
        assert!(other.len() < (1 << 16));
        TSIG {
            algorithm,
            time,
            fudge,
            mac,
            oid,
            error,
            other,
        }
    }

    /// Emit TSIG RR and RDATA as used for computing MAC
    ///
    /// ```text
    ///       3.4.2. TSIG Variables
    ///
    ///   Source       Field Name       Notes
    ///   -----------------------------------------------------------------------
    ///   TSIG RR      NAME             Key name, in canonical wire format
    ///   TSIG RR      CLASS            (Always ANY in the current specification)
    ///   TSIG RR      TTL              (Always 0 in the current specification)
    ///   TSIG RDATA   Algorithm Name   in canonical wire format
    ///   TSIG RDATA   Time Signed      in network byte order
    ///   TSIG RDATA   Fudge            in network byte order
    ///   TSIG RDATA   Error            in network byte order
    ///   TSIG RDATA   Other Len        in network byte order
    ///   TSIG RDATA   Other Data       exactly as transmitted
    ///
    ///      The RR RDLEN and RDATA MAC Length are not included in the hash since
    ///      they are not guaranteed to be knowable before the MAC is generated.
    ///
    ///      The Original ID field is not included in this section, as it has
    ///      already been substituted for the message ID in the DNS header and
    ///      hashed.
    ///
    ///      For each label type, there must be a defined "Canonical wire format"
    ///      that specifies how to express a label in an unambiguous way.  For
    ///      label type 00, this is defined in [RFC2535], for label type 01, this
    ///      is defined in [RFC2673].  The use of label types other than 00 and 01
    ///      is not defined for this specification.
    /// ```
    pub fn emit_tsig_for_mac(
        &self,
        encoder: &mut BinEncoder<'_>,
        key_name: Name,
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
        TSIG { mac, ..self }
    }
}

/// Read the RData from the given Decoder
///
/// ```text
///    Field Name       Data Type      Notes
///    --------------------------------------------------------------
///    Algorithm Name   domain-name    Name of the algorithm
///                                    in domain name syntax.
///    Time Signed      u_int48_t      seconds since 1-Jan-70 UTC.
///    Fudge            u_int16_t      seconds of error permitted
///                                    in Time Signed.
///    MAC Size         u_int16_t      number of octets in MAC.
///    MAC              octet stream   defined by Algorithm Name.
///    Original ID      u_int16_t      original message ID
///    Error            u_int16_t      expanded RCODE covering
///                                    TSIG processing.
///    Other Len        u_int16_t      length, in octets, of
///                                    Other Data.
///    Other Data       octet stream   empty unless Error == BADTIME
/// ```
pub fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<TSIG> {
    let algorithm = Algorithm::read(decoder)?;
    let time_high = decoder.read_u16()?.unverified(/*valid as any u16*/) as u64;
    let time_low = decoder.read_u32()?.unverified(/*valid as any u32*/) as u64;
    let time = (time_high << 32) + time_low;
    let fudge = decoder.read_u16()?.unverified(/*valid as any u16*/);
    let mac_size = decoder.read_u16()?.unverified(/* TODO maybe compare to alg out size, but we don't know that value yet? */);
    let mac =
        decoder.read_vec(mac_size as usize)?.unverified(/*valid as any vec of the right size*/);
    let oid = decoder.read_u16()?.unverified(/*valid as any u16*/);
    let error = decoder.read_u16()?.unverified(/*valid as any u16*/);
    let other_len = decoder.read_u16()?.unverified(/*valid as any u16*/);
    let other =
        decoder.read_vec(other_len as usize)?.unverified(/*valid as any vec ot the right size*/);

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
pub fn emit(encoder: &mut BinEncoder<'_>, tsig: &TSIG) -> ProtoResult<()> {
    tsig.algorithm.emit(encoder)?;
    encoder.emit_u16((tsig.time >> 32) as u16)?;
    encoder.emit_u32(tsig.time as u32)?;
    encoder.emit_u16(tsig.fudge)?;
    encoder.emit_u16(tsig.mac.len() as u16)?;
    encoder.emit_vec(&tsig.mac)?;
    encoder.emit_u16(tsig.oid)?;
    encoder.emit_u16(tsig.error)?;
    encoder.emit_u16(tsig.other.len() as u16)?;
    encoder.emit_vec(&tsig.other)?;
    Ok(())
}

// Does not appear to have a normed text representation
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

impl Algorithm {
    /// Return DNS name for the algorithm
    pub fn to_name(&self) -> Name {
        use Algorithm::*;
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
        Ok(Algorithm::from_name(name))
    }

    /// Convert a DNS name to an Algorithm
    pub fn from_name(name: Name) -> Self {
        use Algorithm::*;
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
}
impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.to_name())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;

    fn test_encode_decode(rdata: TSIG) {
        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        emit(&mut encoder, &rdata).expect("failed to emit tsig");
        let bytes = encoder.into_bytes();

        println!("bytes: {:?}", bytes);

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let read_rdata = read(&mut decoder).expect("failed to read back");
        assert_eq!(rdata, read_rdata);
    }

    #[test]
    fn test_encode_decode_tsig() {
        test_encode_decode(TSIG::new(
            Algorithm::HmacSha256,
            0,
            300,
            vec![0, 1, 2, 3],
            0,
            0,
            vec![4, 5, 6, 7],
        ));
        test_encode_decode(TSIG::new(
            Algorithm::HmacSha384,
            123456789,
            60,
            vec![9, 8, 7, 6, 5, 4],
            1,
            2,
            vec![],
        ));
        test_encode_decode(TSIG::new(
            Algorithm::HmacSha512_256,
            123456789,
            60,
            vec![],
            1,
            2,
            vec![0, 1, 2, 3, 4, 5, 6],
        ));
    }
}
