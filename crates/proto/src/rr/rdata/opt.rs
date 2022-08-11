/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! option record for passing protocol options between the client and server
#![allow(clippy::use_self)]

use std::collections::HashMap;

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use tracing::warn;

use crate::error::*;
use crate::serialize::binary::*;

#[cfg(feature = "dnssec")]
use crate::rr::dnssec::SupportedAlgorithms;

/// The OPT record type is used for ExtendedDNS records.
///
/// These allow for additional information to be associated with the DNS request that otherwise
/// would require changes to the DNS protocol.
///
/// [RFC 6891, EDNS(0) Extensions, April 2013](https://tools.ietf.org/html/rfc6891#section-6)
///
/// ```text
/// 6.1.  OPT Record Definition
///
/// 6.1.1.  Basic Elements
///
///    An OPT pseudo-RR (sometimes called a meta-RR) MAY be added to the
///    additional data section of a request.
///
///    The OPT RR has RR type 41.
///
///    If an OPT record is present in a received request, compliant
///    responders MUST include an OPT record in their respective responses.
///
///    An OPT record does not carry any DNS data.  It is used only to
///    contain control information pertaining to the question-and-answer
///    sequence of a specific transaction.  OPT RRs MUST NOT be cached,
///    forwarded, or stored in or loaded from Zone Files.
///
///    The OPT RR MAY be placed anywhere within the additional data section.
///    When an OPT RR is included within any DNS message, it MUST be the
///    only OPT RR in that message.  If a query message with more than one
///    OPT RR is received, a FORMERR (RCODE=1) MUST be returned.  The
///    placement flexibility for the OPT RR does not override the need for
///    the TSIG or SIG(0) RRs to be the last in the additional section
///    whenever they are present.
///
/// 6.1.2.  Wire Format
///
///    An OPT RR has a fixed part and a variable set of options expressed as
///    {attribute, value} pairs.  The fixed part holds some DNS metadata,
///    and also a small collection of basic extension elements that we
///    expect to be so popular that it would be a waste of wire space to
///    encode them as {attribute, value} pairs.
///
///    The fixed part of an OPT RR is structured as follows:
///
///        +------------+--------------+------------------------------+
///        | Field Name | Field Type   | Description                  |
///        +------------+--------------+------------------------------+
///        | NAME       | domain name  | MUST be 0 (root domain)      |
///        | TYPE       | u_int16_t    | OPT (41)                     |
///        | CLASS      | u_int16_t    | requestor's UDP payload size |
///        | TTL        | u_int32_t    | extended RCODE and flags     |
///        | RDLEN      | u_int16_t    | length of all RDATA          |
///        | RDATA      | octet stream | {attribute,value} pairs      |
///        +------------+--------------+------------------------------+
///
///                                OPT RR Format
///
///    The variable part of an OPT RR may contain zero or more options in
///    the RDATA.  Each option MUST be treated as a bit field.  Each option
///    is encoded as:
///
///                   +0 (MSB)                            +1 (LSB)
///        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
///     0: |                          OPTION-CODE                          |
///        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
///     2: |                         OPTION-LENGTH                         |
///        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
///     4: |                                                               |
///        /                          OPTION-DATA                          /
///        /                                                               /
///        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
///
///    OPTION-CODE
///       Assigned by the Expert Review process as defined by the DNSEXT
///       working group and the IESG.
///
///    OPTION-LENGTH
///       Size (in octets) of OPTION-DATA.
///
///    OPTION-DATA
///       Varies per OPTION-CODE.  MUST be treated as a bit field.
///
///    The order of appearance of option tuples is not defined.  If one
///    option modifies the behaviour of another or multiple options are
///    related to one another in some way, they have the same effect
///    regardless of ordering in the RDATA wire encoding.
///
///    Any OPTION-CODE values not understood by a responder or requestor
///    MUST be ignored.  Specifications of such options might wish to
///    include some kind of signaled acknowledgement.  For example, an
///    option specification might say that if a responder sees and supports
///    option XYZ, it MUST include option XYZ in its response.
///
/// 6.1.3.  OPT Record TTL Field Use
///
///    The extended RCODE and flags, which OPT stores in the RR Time to Live
///    (TTL) field, are structured as follows:
///
///                   +0 (MSB)                            +1 (LSB)
///        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
///     0: |         EXTENDED-RCODE        |            VERSION            |
///        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
///     2: | DO|                           Z                               |
///        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
///
///    EXTENDED-RCODE
///       Forms the upper 8 bits of extended 12-bit RCODE (together with the
///       4 bits defined in [RFC1035].  Note that EXTENDED-RCODE value 0
///       indicates that an unextended RCODE is in use (values 0 through
///       15).
///
///    VERSION
///       Indicates the implementation level of the setter.  Full
///       conformance with this specification is indicated by version '0'.
///       Requestors are encouraged to set this to the lowest implemented
///       level capable of expressing a transaction, to minimise the
///       responder and network load of discovering the greatest common
///       implementation level between requestor and responder.  A
///       requestor's version numbering strategy MAY ideally be a run-time
///       configuration option.
///       If a responder does not implement the VERSION level of the
///       request, then it MUST respond with RCODE=BADVERS.  All responses
///       MUST be limited in format to the VERSION level of the request, but
///       the VERSION of each response SHOULD be the highest implementation
///       level of the responder.  In this way, a requestor will learn the
///       implementation level of a responder as a side effect of every
///       response, including error responses and including RCODE=BADVERS.
///
/// 6.1.4.  Flags
///
///    DO
///       DNSSEC OK bit as defined by [RFC3225].
///
///    Z
///       Set to zero by senders and ignored by receivers, unless modified
///       in a subsequent specification.
/// ```
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct OPT {
    options: HashMap<EdnsCode, EdnsOption>,
}

impl OPT {
    /// Creates a new OPT record data.
    ///
    /// # Arguments
    ///
    /// * `options` - A map of the codes and record types
    ///
    /// # Return value
    ///
    /// The newly created OPT data
    pub fn new(options: HashMap<EdnsCode, EdnsOption>) -> Self {
        Self { options }
    }

    #[deprecated(note = "Please use as_ref() or as_mut() for shared/mutable references")]
    /// The entire map of options
    pub fn options(&self) -> &HashMap<EdnsCode, EdnsOption> {
        &self.options
    }

    /// Get a single option based on the code
    pub fn get(&self, code: EdnsCode) -> Option<&EdnsOption> {
        self.options.get(&code)
    }

    /// Insert a new option, the key is derived from the `EdnsOption`
    pub fn insert(&mut self, option: EdnsOption) {
        self.options.insert((&option).into(), option);
    }

    /// Remove an option, the key is derived from the `EdnsOption`
    pub fn remove(&mut self, option: EdnsCode) {
        self.options.remove(&option);
    }
}

impl AsMut<HashMap<EdnsCode, EdnsOption>> for OPT {
    fn as_mut(&mut self) -> &mut HashMap<EdnsCode, EdnsOption> {
        &mut self.options
    }
}

impl AsRef<HashMap<EdnsCode, EdnsOption>> for OPT {
    fn as_ref(&self) -> &HashMap<EdnsCode, EdnsOption> {
        &self.options
    }
}

/// Read the RData from the given Decoder
pub fn read(decoder: &mut BinDecoder<'_>, rdata_length: Restrict<u16>) -> ProtoResult<OPT> {
    let mut state: OptReadState = OptReadState::ReadCode;
    let mut options: HashMap<EdnsCode, EdnsOption> = HashMap::new();
    let start_idx = decoder.index();

    // There is no unsafe direct use of the rdata length after this point
    let rdata_length =
        rdata_length.map(|u| u as usize).unverified(/*rdata length usage is bounded*/);
    while rdata_length > decoder.index() - start_idx {
        match state {
            OptReadState::ReadCode => {
                state = OptReadState::Code {
                    code: EdnsCode::from(
                        decoder.read_u16()?.unverified(/*EdnsCode is verified as safe*/),
                    ),
                };
            }
            OptReadState::Code { code } => {
                let length = decoder
                    .read_u16()?
                    .map(|u| u as usize)
                    .verify_unwrap(|u| *u <= rdata_length)
                    .map_err(|_| ProtoError::from("OPT value length exceeds rdata length"))?;
                // If we know that the length is 0, we can avoid the `OptReadState::Data` state
                // and directly add the option to the map.
                // The data state does not process 0-length correctly, since it always reads at
                // least 1 byte, thus making the length check fail.
                state = if length == 0 {
                    options.insert(code, (code, &[] as &[u8]).into());
                    OptReadState::ReadCode
                } else {
                    OptReadState::Data {
                        code,
                        length,
                        // TODO: this cean be replaced with decoder.read_vec(), right?
                        //  the current version allows for malformed opt to be skipped...
                        collected: Vec::<u8>::with_capacity(length),
                    }
                };
            }
            OptReadState::Data {
                code,
                length,
                mut collected,
            } => {
                // TODO: can this be replaced by read_slice()?
                collected.push(decoder.pop()?.unverified(/*byte array is safe*/));
                if length == collected.len() {
                    options.insert(code, (code, &collected as &[u8]).into());
                    state = OptReadState::ReadCode;
                } else {
                    state = OptReadState::Data {
                        code,
                        length,
                        collected,
                    };
                }
            }
        }
    }

    if state != OptReadState::ReadCode {
        // there was some problem parsing the data for the options, ignoring them
        // TODO: should we ignore all of the EDNS data in this case?
        warn!("incomplete or poorly formatted EDNS options: {:?}", state);
        options.clear();
    }

    // the record data is stored as unstructured data, the expectation is that this will be processed after initial parsing.
    Ok(OPT::new(options))
}

/// Write the RData from the given Decoder
pub fn emit(encoder: &mut BinEncoder<'_>, opt: &OPT) -> ProtoResult<()> {
    for (edns_code, edns_option) in opt.as_ref().iter() {
        encoder.emit_u16(u16::from(*edns_code))?;
        encoder.emit_u16(edns_option.len())?;
        edns_option.emit(encoder)?
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum OptReadState {
    ReadCode,
    Code {
        code: EdnsCode,
    }, // expect LSB for the opt code, store the high byte
    Data {
        code: EdnsCode,
        length: usize,
        collected: Vec<u8>,
    }, // expect the data for the option
}

/// The code of the EDNS data option
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Hash, Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EdnsCode {
    /// [RFC 6891, Reserved](https://tools.ietf.org/html/rfc6891)
    Zero,

    /// [RFC 8764l, Apple's Long-Lived Queries, Optional](https://tools.ietf.org/html/rfc8764)
    LLQ,

    /// [UL On-hold](http://files.dns-sd.org/draft-sekar-dns-ul.txt)
    UL,

    /// [RFC 5001, NSID](https://tools.ietf.org/html/rfc5001)
    NSID,
    // 4 Reserved [draft-cheshire-edns0-owner-option] -EXPIRED-
    /// [RFC 6975, DNSSEC Algorithm Understood](https://tools.ietf.org/html/rfc6975)
    DAU,

    /// [RFC 6975, DS Hash Understood](https://tools.ietf.org/html/rfc6975)
    DHU,

    /// [RFC 6975, NSEC3 Hash Understood](https://tools.ietf.org/html/rfc6975)
    N3U,

    /// [RFC 7871, Client Subnet, Optional](https://tools.ietf.org/html/rfc7871)
    Subnet,

    /// [RFC 7314, EDNS EXPIRE, Optional](https://tools.ietf.org/html/rfc7314)
    Expire,

    /// [RFC 7873, DNS Cookies](https://tools.ietf.org/html/rfc7873)
    Cookie,

    /// [RFC 7828, edns-tcp-keepalive](https://tools.ietf.org/html/rfc7828)
    Keepalive,

    /// [RFC 7830, The EDNS(0) Padding](https://tools.ietf.org/html/rfc7830)
    Padding,

    /// [RFC 7901, CHAIN Query Requests in DNS, Optional](https://tools.ietf.org/html/rfc7901)
    Chain,

    /// Unknown, used to deal with unknown or unsupported codes
    Unknown(u16),
}

// TODO: implement a macro to perform these inversions
impl From<u16> for EdnsCode {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::Zero,
            1 => Self::LLQ,
            2 => Self::UL,
            3 => Self::NSID,
            // 4 Reserved [draft-cheshire-edns0-owner-option] -EXPIRED-
            5 => Self::DAU,
            6 => Self::DHU,
            7 => Self::N3U,
            8 => Self::Subnet,
            9 => Self::Expire,
            10 => Self::Cookie,
            11 => Self::Keepalive,
            12 => Self::Padding,
            13 => Self::Chain,
            _ => Self::Unknown(value),
        }
    }
}

impl From<EdnsCode> for u16 {
    fn from(value: EdnsCode) -> Self {
        match value {
            EdnsCode::Zero => 0,
            EdnsCode::LLQ => 1,
            EdnsCode::UL => 2,
            EdnsCode::NSID => 3,
            // 4 Reserved [draft-cheshire-edns0-owner-option] -EXPIRED-
            EdnsCode::DAU => 5,
            EdnsCode::DHU => 6,
            EdnsCode::N3U => 7,
            EdnsCode::Subnet => 8,
            EdnsCode::Expire => 9,
            EdnsCode::Cookie => 10,
            EdnsCode::Keepalive => 11,
            EdnsCode::Padding => 12,
            EdnsCode::Chain => 13,
            EdnsCode::Unknown(value) => value,
        }
    }
}

/// options used to pass information about capabilities between client and server
///
/// `note: Not all EdnsOptions are supported at this time.`
///
/// <http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-13>
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialOrd, PartialEq, Eq, Clone, Hash)]
#[non_exhaustive]
pub enum EdnsOption {
    /// [RFC 6975, DNSSEC Algorithm Understood](https://tools.ietf.org/html/rfc6975)
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    DAU(SupportedAlgorithms),

    /// [RFC 6975, DS Hash Understood](https://tools.ietf.org/html/rfc6975)
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    DHU(SupportedAlgorithms),

    /// [RFC 6975, NSEC3 Hash Understood](https://tools.ietf.org/html/rfc6975)
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    N3U(SupportedAlgorithms),

    /// Unknown, used to deal with unknown or unsupported codes
    Unknown(u16, Vec<u8>),
}

impl EdnsOption {
    /// Returns the length in bytes of the EdnsOption
    pub fn len(&self) -> u16 {
        match *self {
            #[cfg(feature = "dnssec")]
            EdnsOption::DAU(ref algorithms)
            | EdnsOption::DHU(ref algorithms)
            | EdnsOption::N3U(ref algorithms) => algorithms.len(),
            EdnsOption::Unknown(_, ref data) => data.len() as u16, // TODO: should we verify?
        }
    }

    /// Returns `true` if the length in bytes of the EdnsOption is 0
    pub fn is_empty(&self) -> bool {
        match *self {
            #[cfg(feature = "dnssec")]
            EdnsOption::DAU(ref algorithms)
            | EdnsOption::DHU(ref algorithms)
            | EdnsOption::N3U(ref algorithms) => algorithms.is_empty(),
            EdnsOption::Unknown(_, ref data) => data.is_empty(),
        }
    }
}

impl BinEncodable for EdnsOption {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        match *self {
            #[cfg(feature = "dnssec")]
            EdnsOption::DAU(ref algorithms)
            | EdnsOption::DHU(ref algorithms)
            | EdnsOption::N3U(ref algorithms) => algorithms.emit(encoder),
            EdnsOption::Unknown(_, ref data) => encoder.emit_vec(data), // gah, clone needed or make a crazy api.
        }
    }
}

/// only the supported extensions are listed right now.
impl<'a> From<(EdnsCode, &'a [u8])> for EdnsOption {
    #[allow(clippy::match_single_binding)]
    fn from(value: (EdnsCode, &'a [u8])) -> Self {
        match value.0 {
            #[cfg(feature = "dnssec")]
            EdnsCode::DAU => Self::DAU(value.1.into()),
            #[cfg(feature = "dnssec")]
            EdnsCode::DHU => Self::DHU(value.1.into()),
            #[cfg(feature = "dnssec")]
            EdnsCode::N3U => Self::N3U(value.1.into()),
            _ => Self::Unknown(value.0.into(), value.1.to_vec()),
        }
    }
}

impl<'a> From<&'a EdnsOption> for Vec<u8> {
    fn from(value: &'a EdnsOption) -> Self {
        match *value {
            #[cfg(feature = "dnssec")]
            EdnsOption::DAU(ref algorithms)
            | EdnsOption::DHU(ref algorithms)
            | EdnsOption::N3U(ref algorithms) => algorithms.into(),
            EdnsOption::Unknown(_, ref data) => data.clone(), // gah, clone needed or make a crazy api.
        }
    }
}

impl<'a> From<&'a EdnsOption> for EdnsCode {
    fn from(value: &'a EdnsOption) -> Self {
        match *value {
            #[cfg(feature = "dnssec")]
            EdnsOption::DAU(..) => Self::DAU,
            #[cfg(feature = "dnssec")]
            EdnsOption::DHU(..) => Self::DHU,
            #[cfg(feature = "dnssec")]
            EdnsOption::N3U(..) => Self::N3U,
            EdnsOption::Unknown(code, _) => code.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;

    #[test]
    #[cfg(feature = "dnssec")]
    fn test() {
        let mut rdata = OPT::default();
        rdata.insert(EdnsOption::DAU(SupportedAlgorithms::all()));

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        assert!(emit(&mut encoder, &rdata).is_ok());
        let bytes = encoder.into_bytes();

        println!("bytes: {:?}", bytes);

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let restrict = Restrict::new(bytes.len() as u16);
        let read_rdata = read(&mut decoder, restrict).expect("Decoding error");
        assert_eq!(rdata, read_rdata);
    }

    #[test]
    fn test_read_empty_option_at_end_of_opt() {
        let bytes: Vec<u8> = vec![
            0x00, 0x0a, 0x00, 0x08, 0x0b, 0x64, 0xb4, 0xdc, 0xd7, 0xb0, 0xcc, 0x8f, 0x00, 0x08,
            0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00,
        ];

        let mut decoder: BinDecoder<'_> = BinDecoder::new(&bytes);
        let read_rdata = read(&mut decoder, Restrict::new(bytes.len() as u16));
        assert!(
            read_rdata.is_ok(),
            "error decoding: {:?}",
            read_rdata.unwrap_err()
        );

        let opt = read_rdata.unwrap();
        let mut options = HashMap::default();
        options.insert(EdnsCode::Subnet, EdnsOption::Unknown(8, vec![0, 1, 0, 0]));
        options.insert(
            EdnsCode::Cookie,
            EdnsOption::Unknown(10, vec![0x0b, 0x64, 0xb4, 0xdc, 0xd7, 0xb0, 0xcc, 0x8f]),
        );
        options.insert(EdnsCode::Keepalive, EdnsOption::Unknown(11, vec![]));
        let options = OPT::new(options);
        assert_eq!(opt, options);
    }
}
