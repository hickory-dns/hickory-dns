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
use crate::op::{Header, Message, Query};
use crate::rr::dns_class::DNSClass;
use crate::rr::record_data::RData;
use crate::rr::record_type::RecordType;
use crate::rr::{Name, Record};
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
        // Should maybe not be a panic but return a Result::Err, or be ignored?
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
    pub fn algorithm(&self) -> &Algorithm {
        &self.algorithm
    }

    /// Emit TSIG RR and RDATA as used for computing MAC
    ///
    /// ```text
    ///
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
        assert!(mac.len() < (1 << 16));
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
    let mac_size = decoder.read_u16()?.unverified(/* TODO maybe compare to alg out size, but we don't actually know that value? */);
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

    /// Compute the Message Authentication Code using key and algorithm
    ///
    /// Supported algorithm are HmacSha256, HmacSha384, HmacSha512 and HmacSha512_256
    /// Other algorithm return an error.
    pub fn mac_data(&self, key: &[u8], message: &[u8]) -> ProtoResult<Vec<u8>> {
        use hmac::{Hmac, Mac, NewMac};
        use Algorithm::*;

        let res = match self {
            HmacSha256 => {
                let mut mac = Hmac::<sha2::Sha256>::new_varkey(key).unwrap(/* all keysize are allowed for Hmac */);
                mac.update(message);
                mac.finalize().into_bytes().to_vec()
            }
            HmacSha384 => {
                let mut mac = Hmac::<sha2::Sha384>::new_varkey(key).unwrap(/* all keysize are allowed for Hmac */);
                mac.update(message);
                mac.finalize().into_bytes().to_vec()
            }
            HmacSha512 => {
                let mut mac = Hmac::<sha2::Sha512>::new_varkey(key).unwrap(/* all keysize are allowed for Hmac */);
                mac.update(message);
                mac.finalize().into_bytes().to_vec()
            }
            HmacSha512_256 => {
                let mut mac = Hmac::<sha2::Sha512Trunc256>::new_varkey(key).unwrap(/* all keysize are allowed for Hmac */);
                mac.update(message);
                mac.finalize().into_bytes().to_vec()
            }
            _ => return Err(ProtoError::from("unsupported mac algorithm")),
        };
        Ok(res)
    }

    /// Return true if cryptographic operations needed for using this algorithm are supported,
    /// false otherwise
    pub fn supported(&self) -> bool {
        use Algorithm::*;
        matches!(self, HmacSha256 | HmacSha384 | HmacSha512 | HmacSha512_256)
    }
}

impl fmt::Display for Algorithm {
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
    let tsig = if let (RecordType::TSIG, RData::TSIG(tsig_data)) = (sig.rr_type(), sig.rdata()) {
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
    // emit the tsig pseudo-record
    tsig.emit_tsig_for_mac(&mut encoder, sig.name())?;

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
        .set_rdata(RData::TSIG(rdata));
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
            Algorithm::Unknown(Name::from_ascii("unkown_algorithm").unwrap()),
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
            Algorithm::HmacSha256,
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

        let tbv = signed_bitmessage_to_buf(None, &message_byte).unwrap().0;

        assert_eq!(tbs, tbv);
    }

    #[test]
    fn test_sign_encode_id_changed() {
        let mut message = Message::new();
        message.set_id(123).add_answer(Record::new());

        let key_name = Name::from_ascii("some.name").unwrap();

        let pre_tsig = TSIG::new(
            Algorithm::HmacSha256,
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

        let tbv = signed_bitmessage_to_buf(None, &message_byte).unwrap().0;

        assert_eq!(tbs, tbv);
    }
}
