// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! option record for passing protocol options between the client and server
#![allow(clippy::use_self)]

use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    error::{ProtoError, ProtoErrorKind, ProtoResult},
    rr::{RData, RecordData, RecordDataDecodable, RecordType},
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder, Restrict},
};

#[cfg(feature = "__dnssec")]
use crate::dnssec::SupportedAlgorithms;

/// The OPT record type is used for ExtendedDNS records.
///
/// These allow for additional information to be associated with the DNS request that otherwise
/// would require changes to the DNS protocol.
///
/// Multiple options with the same code are allowed to appear in this record
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
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Default, Debug, Clone)]
pub struct OPT {
    options: Vec<(EdnsCode, EdnsOption)>,
}

impl OPT {
    /// Creates a new OPT record data.
    ///
    /// # Arguments
    ///
    /// * `options` - List of code and record type tuples
    ///
    /// # Return value
    ///
    /// The newly created OPT data
    pub fn new(options: Vec<(EdnsCode, EdnsOption)>) -> Self {
        Self { options }
    }

    /// Get a single option based on the code
    pub fn get(&self, code: EdnsCode) -> Option<&EdnsOption> {
        self.options
            .iter()
            .find_map(|(c, option)| if code == *c { Some(option) } else { None })
    }

    /// Get all options based on the code
    pub fn get_all(&self, code: EdnsCode) -> Vec<&EdnsOption> {
        self.options
            .iter()
            .filter_map(|(c, option)| if code == *c { Some(option) } else { None })
            .collect()
    }

    /// Insert a new option, the key is derived from the `EdnsOption`
    pub fn insert(&mut self, option: EdnsOption) {
        self.options.push(((&option).into(), option));
    }

    /// Removes all options based on the code
    pub fn remove(&mut self, option: EdnsCode) {
        self.options.retain(|(c, _)| *c != option)
    }
}

impl PartialEq for OPT {
    fn eq(&self, other: &Self) -> bool {
        let matching_elements_count = self
            .options
            .iter()
            .filter(|entry| other.options.contains(entry))
            .count();
        matching_elements_count == self.options.len()
            && matching_elements_count == other.options.len()
    }
}

impl Eq for OPT {}

impl AsMut<Vec<(EdnsCode, EdnsOption)>> for OPT {
    fn as_mut(&mut self) -> &mut Vec<(EdnsCode, EdnsOption)> {
        &mut self.options
    }
}

impl AsRef<[(EdnsCode, EdnsOption)]> for OPT {
    fn as_ref(&self) -> &[(EdnsCode, EdnsOption)] {
        &self.options
    }
}

impl BinEncodable for OPT {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        for (edns_code, edns_option) in self.as_ref().iter() {
            encoder.emit_u16(u16::from(*edns_code))?;
            encoder.emit_u16(edns_option.len())?;
            edns_option.emit(encoder)?
        }
        Ok(())
    }
}

impl<'r> RecordDataDecodable<'r> for OPT {
    fn read_data(decoder: &mut BinDecoder<'r>, length: Restrict<u16>) -> ProtoResult<Self> {
        let mut state: OptReadState = OptReadState::ReadCode;
        let mut options: Vec<(EdnsCode, EdnsOption)> = Vec::new();
        let start_idx = decoder.index();

        // There is no unsafe direct use of the rdata length after this point
        let rdata_length = length.map(|u| u as usize).unverified(/*rdata length usage is bounded*/);
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
                        options.push((code, (code, &[] as &[u8]).try_into()?));
                        OptReadState::ReadCode
                    } else {
                        OptReadState::Data {
                            code,
                            length,
                            // TODO: this can be replaced with decoder.read_vec(), right?
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
                        options.push((code, (code, &collected as &[u8]).try_into()?));
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
        Ok(Self::new(options))
    }
}

impl RecordData for OPT {
    fn try_from_rdata(data: RData) -> Result<Self, RData> {
        match data {
            RData::OPT(csync) => Ok(csync),
            _ => Err(data),
        }
    }

    fn try_borrow(data: &RData) -> Option<&Self> {
        match data {
            RData::OPT(csync) => Some(csync),
            _ => None,
        }
    }

    fn record_type(&self) -> RecordType {
        RecordType::OPT
    }

    fn into_rdata(self) -> RData {
        RData::OPT(self)
    }
}

impl fmt::Display for OPT {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        fmt::Debug::fmt(self, f)
    }
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
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Hash, Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EdnsCode {
    /// [RFC 6891, Reserved](https://tools.ietf.org/html/rfc6891)
    Zero,

    /// [RFC 8764l, Apple's Long-Lived Queries, Optional](https://tools.ietf.org/html/rfc8764)
    LLQ,

    /// [UL On-hold](https://files.dns-sd.org/draft-sekar-dns-ul.txt)
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
/// <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-13>
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialOrd, PartialEq, Eq, Clone, Hash)]
#[non_exhaustive]
pub enum EdnsOption {
    /// [RFC 6975, DNSSEC Algorithm Understood](https://tools.ietf.org/html/rfc6975)
    #[cfg(feature = "__dnssec")]
    DAU(SupportedAlgorithms),

    /// [RFC 7871, Client Subnet, Optional](https://tools.ietf.org/html/rfc7871)
    Subnet(ClientSubnet),

    /// Unknown, used to deal with unknown or unsupported codes
    Unknown(u16, Vec<u8>),
}

impl EdnsOption {
    /// Returns the length in bytes of the EdnsOption
    pub fn len(&self) -> u16 {
        match self {
            #[cfg(feature = "__dnssec")]
            EdnsOption::DAU(algorithms) => algorithms.len(),
            EdnsOption::Subnet(subnet) => subnet.len(),
            EdnsOption::Unknown(_, data) => data.len() as u16, // TODO: should we verify?
        }
    }

    /// Returns `true` if the length in bytes of the EdnsOption is 0
    pub fn is_empty(&self) -> bool {
        match self {
            #[cfg(feature = "__dnssec")]
            EdnsOption::DAU(algorithms) => algorithms.is_empty(),
            EdnsOption::Subnet(subnet) => subnet.is_empty(),
            EdnsOption::Unknown(_, data) => data.is_empty(),
        }
    }
}

impl BinEncodable for EdnsOption {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        match self {
            #[cfg(feature = "__dnssec")]
            EdnsOption::DAU(algorithms) => algorithms.emit(encoder),
            EdnsOption::Subnet(subnet) => subnet.emit(encoder),
            EdnsOption::Unknown(_, data) => encoder.emit_vec(data), // gah, clone needed or make a crazy api.
        }
    }
}

/// only the supported extensions are listed right now.
impl<'a> TryFrom<(EdnsCode, &'a [u8])> for EdnsOption {
    type Error = ProtoError;

    #[allow(clippy::match_single_binding)]
    fn try_from(value: (EdnsCode, &'a [u8])) -> Result<Self, Self::Error> {
        Ok(match value.0 {
            #[cfg(feature = "__dnssec")]
            EdnsCode::DAU => Self::DAU(value.1.into()),
            EdnsCode::Subnet => Self::Subnet(value.1.try_into()?),
            _ => Self::Unknown(value.0.into(), value.1.to_vec()),
        })
    }
}

impl<'a> TryFrom<&'a EdnsOption> for Vec<u8> {
    type Error = ProtoError;

    fn try_from(value: &'a EdnsOption) -> Result<Self, Self::Error> {
        Ok(match value {
            #[cfg(feature = "__dnssec")]
            EdnsOption::DAU(algorithms) => algorithms.into(),
            EdnsOption::Subnet(subnet) => subnet.try_into()?,
            EdnsOption::Unknown(_, data) => data.clone(), // gah, clone needed or make a crazy api.
        })
    }
}

impl<'a> From<&'a EdnsOption> for EdnsCode {
    fn from(value: &'a EdnsOption) -> Self {
        match value {
            #[cfg(feature = "__dnssec")]
            EdnsOption::DAU(..) => Self::DAU,
            EdnsOption::Subnet(..) => Self::Subnet,
            EdnsOption::Unknown(code, _) => (*code).into(),
        }
    }
}

/// [RFC 7871, Client Subnet, Optional](https://tools.ietf.org/html/rfc7871)
///
/// ```text
/// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
/// 0: |                            FAMILY                             |
///    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
/// 2: |     SOURCE PREFIX-LENGTH      |     SCOPE PREFIX-LENGTH       |
///    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
/// 4: |                           ADDRESS...                          /
///    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
///
/// o  FAMILY, 2 octets, indicates the family of the address contained in
///    the option, using address family codes as assigned by IANA in
///    Address Family Numbers [Address_Family_Numbers].
/// o  SOURCE PREFIX-LENGTH, an unsigned octet representing the leftmost
///    number of significant bits of ADDRESS to be used for the lookup.
///    In responses, it mirrors the same value as in the queries.
/// o  SCOPE PREFIX-LENGTH, an unsigned octet representing the leftmost
///    number of significant bits of ADDRESS that the response covers.
///    In queries, it MUST be set to 0.
/// o  ADDRESS, variable number of octets, contains either an IPv4 or
///    IPv6 address, depending on FAMILY, which MUST be truncated to the
///    number of bits indicated by the SOURCE PREFIX-LENGTH field,
///    padding with 0 bits to pad to the end of the last octet needed.
/// o  A server receiving an ECS option that uses either too few or too
///    many ADDRESS octets, or that has non-zero ADDRESS bits set beyond
///    SOURCE PREFIX-LENGTH, SHOULD return FORMERR to reject the packet,
///    as a signal to the software developer making the request to fix
///    their implementation.
/// ```
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialOrd, PartialEq, Eq, Clone, Copy, Hash)]
pub struct ClientSubnet {
    address: IpAddr,
    source_prefix: u8,
    scope_prefix: u8,
}

impl ClientSubnet {
    /// Construct a new EcsOption with the address, source_prefix and scope_prefix.
    pub fn new(address: IpAddr, source_prefix: u8, scope_prefix: u8) -> Self {
        Self {
            address,
            source_prefix,
            scope_prefix,
        }
    }

    /// Returns the length in bytes of the EdnsOption
    pub fn len(&self) -> u16 {
        // FAMILY: 2 octets
        // SOURCE PREFIX-LENGTH: 1 octets
        // SCOPE PREFIX-LENGTH: 1 octets
        // ADDRESS: runcated to the number of bits indicated by the SOURCE PREFIX-LENGTH field
        2 + 1 + 1 + self.addr_len()
    }

    /// Returns `true` if the length in bytes of the EcsOption is 0
    #[inline]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// returns the ip address
    pub fn addr(&self) -> IpAddr {
        self.address
    }

    /// set the ip address
    pub fn set_addr(&mut self, addr: IpAddr) {
        self.address = addr;
    }

    /// returns the source prefix
    pub fn source_prefix(&self) -> u8 {
        self.source_prefix
    }

    /// returns the source prefix
    pub fn set_source_prefix(&mut self, source_prefix: u8) {
        self.source_prefix = source_prefix;
    }

    /// returns the scope prefix
    pub fn scope_prefix(&self) -> u8 {
        self.scope_prefix
    }
    /// returns the scope prefix
    pub fn set_scope_prefix(&mut self, scope_prefix: u8) {
        self.scope_prefix = scope_prefix;
    }

    fn addr_len(&self) -> u16 {
        let source_prefix = self.source_prefix as u16;
        source_prefix / 8 + if source_prefix % 8 > 0 { 1 } else { 0 }
    }
}

impl BinEncodable for ClientSubnet {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        let address = self.address;
        let source_prefix = self.source_prefix;
        let scope_prefix = self.scope_prefix;

        let addr_len = self.addr_len();

        match address {
            IpAddr::V4(ip) => {
                encoder.emit_u16(1)?; // FAMILY: IPv4
                encoder.emit_u8(source_prefix)?;
                encoder.emit_u8(scope_prefix)?;
                let octets = ip.octets();
                let addr_len = addr_len as usize;
                if addr_len <= octets.len() {
                    encoder.emit_vec(&octets[0..addr_len])?
                } else {
                    return Err(ProtoErrorKind::Message(
                        "Invalid addr length for encode EcsOption",
                    )
                    .into());
                }
            }
            IpAddr::V6(ip) => {
                encoder.emit_u16(2)?; // FAMILY: IPv6
                encoder.emit_u8(source_prefix)?;
                encoder.emit_u8(scope_prefix)?;
                let octets = ip.octets();
                let addr_len = addr_len as usize;
                if addr_len <= octets.len() {
                    encoder.emit_vec(&octets[0..addr_len])?
                } else {
                    return Err(ProtoErrorKind::Message(
                        "Invalid addr length for encode EcsOption",
                    )
                    .into());
                }
            }
        }
        Ok(())
    }
}

impl<'a> BinDecodable<'a> for ClientSubnet {
    fn read(decoder: &mut BinDecoder<'a>) -> ProtoResult<Self> {
        let family = decoder.read_u16()?.unverified();

        match family {
            1 => {
                // ipv4
                let source_prefix = decoder.read_u8()?.unverified();
                let scope_prefix = decoder.read_u8()?.unverified();
                let addr_len =
                    (source_prefix / 8 + if source_prefix % 8 > 0 { 1 } else { 0 }) as usize;
                let mut octets = Ipv4Addr::UNSPECIFIED.octets();
                if addr_len > octets.len() {
                    return Err(ProtoErrorKind::Message("Invalid address length").into());
                }
                for octet in octets.iter_mut().take(addr_len) {
                    *octet = decoder.read_u8()?.unverified();
                }
                Ok(Self {
                    address: IpAddr::from(octets),
                    source_prefix,
                    scope_prefix,
                })
            }
            2 => {
                // ipv6
                let source_prefix = decoder.read_u8()?.unverified();
                let scope_prefix = decoder.read_u8()?.unverified();
                let addr_len =
                    (source_prefix / 8 + if source_prefix % 8 > 0 { 1 } else { 0 }) as usize;
                let mut octets = Ipv6Addr::UNSPECIFIED.octets();
                if addr_len > octets.len() {
                    return Err(ProtoErrorKind::Message("Invalid address length").into());
                }
                for octet in octets.iter_mut().take(addr_len) {
                    *octet = decoder.read_u8()?.unverified();
                }

                Ok(Self {
                    address: IpAddr::from(octets),
                    source_prefix,
                    scope_prefix,
                })
            }
            _ => Err(ProtoErrorKind::Message("Invalid family type.").into()),
        }
    }
}

impl<'a> TryFrom<&'a ClientSubnet> for Vec<u8> {
    type Error = ProtoError;

    fn try_from(value: &'a ClientSubnet) -> Result<Self, Self::Error> {
        let mut bytes = Self::with_capacity(value.len() as usize); // today this is less than 8
        let mut encoder = BinEncoder::new(&mut bytes);
        value.emit(&mut encoder)?;
        bytes.shrink_to_fit();
        Ok(bytes)
    }
}

impl<'a> TryFrom<&'a [u8]> for ClientSubnet {
    type Error = ProtoError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let mut decoder = BinDecoder::new(value);
        Self::read(&mut decoder)
    }
}

impl From<ipnet::IpNet> for ClientSubnet {
    fn from(net: ipnet::IpNet) -> Self {
        Self {
            address: net.addr(),
            source_prefix: net.prefix_len(),
            scope_prefix: Default::default(),
        }
    }
}

impl FromStr for ClientSubnet {
    type Err = ipnet::AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ipnet::IpNet::from_str(s).map(ClientSubnet::from)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use std::println;

    use super::*;

    #[test]
    #[cfg(feature = "__dnssec")]
    fn test() {
        let mut rdata = OPT::default();
        rdata.insert(EdnsOption::DAU(SupportedAlgorithms::all()));

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        assert!(rdata.emit(&mut encoder).is_ok());
        let bytes = encoder.into_bytes();

        println!("bytes: {bytes:?}");

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let restrict = Restrict::new(bytes.len() as u16);
        let read_rdata = OPT::read_data(&mut decoder, restrict).expect("Decoding error");
        assert_eq!(rdata, read_rdata);
    }

    #[test]
    fn test_read_empty_option_at_end_of_opt() {
        let bytes: Vec<u8> = vec![
            0x00, 0x0a, 0x00, 0x08, 0x0b, 0x64, 0xb4, 0xdc, 0xd7, 0xb0, 0xcc, 0x8f, 0x00, 0x08,
            0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00,
        ];

        let mut decoder: BinDecoder<'_> = BinDecoder::new(&bytes);
        let read_rdata = OPT::read_data(&mut decoder, Restrict::new(bytes.len() as u16));
        assert!(
            read_rdata.is_ok(),
            "error decoding: {:?}",
            read_rdata.unwrap_err()
        );

        let opt = read_rdata.unwrap();
        let options = vec![
            (
                EdnsCode::Subnet,
                EdnsOption::Subnet("0.0.0.0/0".parse().unwrap()),
            ),
            (
                EdnsCode::Cookie,
                EdnsOption::Unknown(10, vec![0x0b, 0x64, 0xb4, 0xdc, 0xd7, 0xb0, 0xcc, 0x8f]),
            ),
            (EdnsCode::Keepalive, EdnsOption::Unknown(11, vec![])),
        ];
        let options = OPT::new(options);
        assert_eq!(opt, options);
    }

    #[test]
    fn test_multiple_options_with_same_code() {
        let bytes: Vec<u8> = vec![
            0x00, 0x0f, 0x00, 0x02, 0x00, 0x06, 0x00, 0x0f, 0x00, 0x0f, 0x00, 0x09, 0x55, 0x6E,
            0x6B, 0x6E, 0x6F, 0x77, 0x6E, 0x20, 0x65, 0x72, 0x72, 0x6F, 0x72,
        ];

        let mut decoder: BinDecoder<'_> = BinDecoder::new(&bytes);
        let read_rdata = OPT::read_data(&mut decoder, Restrict::new(bytes.len() as u16));
        assert!(
            read_rdata.is_ok(),
            "error decoding: {:?}",
            read_rdata.unwrap_err()
        );

        let opt = read_rdata.unwrap();
        let options = vec![
            (
                EdnsCode::Unknown(15u16),
                EdnsOption::Unknown(15u16, vec![0x00, 0x06]),
            ),
            (
                EdnsCode::Unknown(15u16),
                EdnsOption::Unknown(
                    15u16,
                    vec![
                        0x00, 0x09, 0x55, 0x6E, 0x6B, 0x6E, 0x6F, 0x77, 0x6E, 0x20, 0x65, 0x72,
                        0x72, 0x6F, 0x72,
                    ],
                ),
            ),
        ];
        let options = OPT::new(options);
        assert_eq!(opt, options);
    }

    #[test]
    fn test_write_client_subnet() {
        let expected_bytes: Vec<u8> = vec![0x00, 0x01, 0x18, 0x00, 0xac, 0x01, 0x01];
        let ecs: ClientSubnet = "172.1.1.1/24".parse().unwrap();
        let bytes = Vec::<u8>::try_from(&ecs).unwrap();
        println!("bytes: {bytes:?}");
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn test_read_client_subnet() {
        let bytes: Vec<u8> = vec![0x00, 0x01, 0x18, 0x00, 0xac, 0x01, 0x01];
        let ecs = ClientSubnet::try_from(bytes.as_slice()).unwrap();
        assert_eq!(ecs, "172.1.1.0/24".parse().unwrap());
    }
}
