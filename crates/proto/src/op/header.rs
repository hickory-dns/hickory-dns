// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Message metadata

use std::{convert::From, fmt};

use crate::{
    error::*,
    op::{op_code::OpCode, response_code::ResponseCode},
    serialize::binary::*,
};

/// Metadata for the `Message` struct.
///
/// [RFC 1035, DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION, November 1987](https://tools.ietf.org/html/rfc1035)
///
/// ```text
/// 4.1.1. Header section format
///
/// The header contains the following fields
///
///                                    1  1  1  1  1  1
///      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                      ID                       |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |QR|   Opcode  |AA|TC|RD|RA|ZZ|AD|CD|   RCODE   |  /// AD and CD from RFC4035
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    QDCOUNT / ZCOUNT           |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    ANCOUNT / PRCOUNT          |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    NSCOUNT / UPCOUNT          |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    ARCOUNT / ADCOUNT          |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
/// where
///
/// Z               Reserved for future use.  Must be zero in all queries
///                 and responses.
///
/// ```
///
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Hash)]
pub struct Header {
    id: u16,
    message_type: MessageType,
    op_code: OpCode,
    authoritative: bool,
    truncation: bool,
    recursion_desired: bool,
    recursion_available: bool,
    authentic_data: bool,
    checking_disabled: bool,
    response_code: ResponseCode,
    query_count: u16,
    answer_count: u16,
    name_server_count: u16,
    additional_count: u16,
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{id}:{message_type}:{flags}:{code:?}:{op_code}:{answers}/{authorities}/{additionals}",
            id = self.id,
            message_type = self.message_type,
            flags = self.flags(),
            code = self.response_code,
            op_code = self.op_code,
            answers = self.answer_count,
            authorities = self.name_server_count,
            additionals = self.additional_count,
        )
    }
}

/// Message types are either Query (also Update) or Response
#[derive(Debug, PartialEq, Eq, PartialOrd, Copy, Clone, Hash)]
pub enum MessageType {
    /// Queries are Client requests, these are either Queries or Updates
    Query,
    /// Response message from the Server or upstream Resolver
    Response,
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let s = match self {
            Self::Query => "QUERY",
            Self::Response => "RESPONSE",
        };

        f.write_str(s)
    }
}

/// All the flags of the request/response header
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Flags {
    authoritative: bool,
    truncation: bool,
    recursion_desired: bool,
    recursion_available: bool,
    authentic_data: bool,
    checking_disabled: bool,
}

/// We are following the `dig` commands display format for the header flags
///
/// Example: "RD,AA,RA;" is Recursion-Desired, Authoritative-Answer, Recursion-Available.
impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        const SEPARATOR: &str = ",";

        let flags = [
            (self.recursion_desired, "RD"),
            (self.checking_disabled, "CD"),
            (self.truncation, "TC"),
            (self.authoritative, "AA"),
            (self.recursion_available, "RA"),
            (self.authentic_data, "AD"),
        ];

        let mut iter = flags
            .iter()
            .cloned()
            .filter_map(|(flag, s)| if flag { Some(s) } else { None });

        // print first without a separator, then print the rest.
        if let Some(s) = iter.next() {
            f.write_str(s)?
        }
        for s in iter {
            f.write_str(SEPARATOR)?;
            f.write_str(s)?;
        }

        Ok(())
    }
}

impl Default for Header {
    fn default() -> Self {
        Self::new()
    }
}

impl Header {
    // TODO: we should make id, message_type and op_code all required and non-editable
    /// A default Header, not very useful.
    pub const fn new() -> Self {
        Self {
            id: 0,
            message_type: MessageType::Query,
            op_code: OpCode::Query,
            authoritative: false,
            truncation: false,
            recursion_desired: false,
            recursion_available: false,
            authentic_data: false,
            checking_disabled: false,
            response_code: ResponseCode::NoError,
            query_count: 0,
            answer_count: 0,
            name_server_count: 0,
            additional_count: 0,
        }
    }

    /// Construct a new header based off the request header. This copies over the RD (recursion-desired)
    ///   and CD (checking-disabled), as well as the op_code and id of the request.
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc6895#section-2>
    ///
    /// ```text
    /// The AA, TC, RD, RA, and CD bits are each theoretically meaningful
    ///    only in queries or only in responses, depending on the bit.  The AD
    ///    bit was only meaningful in responses but is expected to have a
    ///    separate but related meaning in queries (see Section 5.7 of
    ///    [RFC6840]).  Only the RD and CD bits are expected to be copied from
    ///    the query to the response; however, some DNS implementations copy all
    ///    the query header as the initial value of the response header.  Thus,
    ///    any attempt to use a "query" bit with a different meaning in a
    ///    response or to define a query meaning for a "response" bit may be
    ///    dangerous, given the existing implementation.  Meanings for these
    ///    bits may only be assigned by a Standards Action.
    /// ```
    pub fn response_from_request(header: &Self) -> Self {
        Self {
            id: header.id,
            message_type: MessageType::Response,
            op_code: header.op_code,
            authoritative: false,
            truncation: false,
            recursion_desired: header.recursion_desired,
            recursion_available: false,
            authentic_data: false,
            checking_disabled: header.checking_disabled,
            response_code: ResponseCode::default(),
            query_count: 0,
            answer_count: 0,
            name_server_count: 0,
            additional_count: 0,
        }
    }

    /// Length of the header, always 12 bytes
    #[inline(always)]
    pub fn len() -> usize {
        12 /* this is always 12 bytes */
    }

    /// Sets the id of the message, for queries this should be random.
    pub fn set_id(&mut self, id: u16) -> &mut Self {
        self.id = id;
        self
    }

    /// Sets the message type, Queries and Updates both use Query.
    pub fn set_message_type(&mut self, message_type: MessageType) -> &mut Self {
        self.message_type = message_type;
        self
    }

    /// Set the operation code for the message
    pub fn set_op_code(&mut self, op_code: OpCode) -> &mut Self {
        self.op_code = op_code;
        self
    }

    /// From the server is specifies that it is an authoritative response.
    pub fn set_authoritative(&mut self, authoritative: bool) -> &mut Self {
        self.authoritative = authoritative;
        self
    }

    /// Specifies that the records were too large for the payload.
    ///
    /// See EDNS or TCP for resolutions to truncation.
    pub fn set_truncated(&mut self, truncated: bool) -> &mut Self {
        self.truncation = truncated;
        self
    }

    /// Specify that the resolver should recursively request data from upstream DNS nodes
    pub fn set_recursion_desired(&mut self, recursion_desired: bool) -> &mut Self {
        self.recursion_desired = recursion_desired;
        self
    }

    /// Specifies that recursion is available from this or the remote resolver
    pub fn set_recursion_available(&mut self, recursion_available: bool) -> &mut Self {
        self.recursion_available = recursion_available;
        self
    }

    /// Specifies that the data is authentic, i.e. the resolver believes all data to be valid through DNSSec
    pub fn set_authentic_data(&mut self, authentic_data: bool) -> &mut Self {
        self.authentic_data = authentic_data;
        self
    }

    /// Used during recursive resolution to specified if a resolver should or should not validate DNSSec signatures
    pub fn set_checking_disabled(&mut self, checking_disabled: bool) -> &mut Self {
        self.checking_disabled = checking_disabled;
        self
    }

    /// A method to get all header flags (useful for Display purposes)
    pub fn flags(&self) -> Flags {
        Flags {
            authoritative: self.authoritative,
            authentic_data: self.authentic_data,
            checking_disabled: self.checking_disabled,
            recursion_available: self.recursion_available,
            recursion_desired: self.recursion_desired,
            truncation: self.truncation,
        }
    }

    /// The low response code (original response codes before EDNS extensions)
    pub fn set_response_code(&mut self, response_code: ResponseCode) -> &mut Self {
        self.response_code = response_code;
        self
    }

    /// This combines the high and low response code values to form the complete ResponseCode from the EDNS record.
    ///   The existing high order bits will be overwritten (if set), and `high_response_code` will be merge with
    ///   the existing low order bits.
    ///
    /// This is intended for use during decoding.
    #[doc(hidden)]
    pub fn merge_response_code(&mut self, high_response_code: u8) {
        self.response_code = ResponseCode::from(high_response_code, self.response_code.low());
    }

    /// Number or query records in the message
    pub fn set_query_count(&mut self, query_count: u16) -> &mut Self {
        self.query_count = query_count;
        self
    }

    /// Number of answer records in the message
    pub fn set_answer_count(&mut self, answer_count: u16) -> &mut Self {
        self.answer_count = answer_count;
        self
    }

    /// Number of name server records in the message
    pub fn set_name_server_count(&mut self, name_server_count: u16) -> &mut Self {
        self.name_server_count = name_server_count;
        self
    }

    /// Number of additional records in the message
    pub fn set_additional_count(&mut self, additional_count: u16) -> &mut Self {
        self.additional_count = additional_count;
        self
    }

    /// ```text
    /// ID              A 16 bit identifier assigned by the program that
    ///                 generates any kind of query.  This identifier is copied
    ///                 the corresponding reply and can be used by the requester
    ///                 to match up replies to outstanding queries.
    /// ```
    pub fn id(&self) -> u16 {
        self.id
    }

    /// ```text
    /// QR              A one bit field that specifies whether this message is a
    ///                 query (0), or a response (1).
    /// ```
    pub fn message_type(&self) -> MessageType {
        self.message_type
    }

    /// ```text
    /// OPCODE          A four bit field that specifies kind of query in this
    ///                 message.  This value is set by the originator of a query
    ///                 and copied into the response.  The values are: <see super::op_code>
    /// ```
    pub fn op_code(&self) -> OpCode {
        self.op_code
    }

    /// ```text
    /// AA              Authoritative Answer - this bit is valid in responses,
    ///                 and specifies that the responding name server is an
    ///                 authority for the domain name in question section.
    ///
    ///                 Note that the contents of the answer section may have
    ///                 multiple owner names because of aliases.  The AA bit
    ///                 corresponds to the name which matches the query name, or
    ///                 the first owner name in the answer section.
    /// ```
    pub fn authoritative(&self) -> bool {
        self.authoritative
    }

    /// ```text
    /// TC              TrunCation - specifies that this message was truncated
    ///                 due to length greater than that permitted on the
    ///                 transmission channel.
    /// ```
    pub fn truncated(&self) -> bool {
        self.truncation
    }

    /// ```text
    /// RD              Recursion Desired - this bit may be set in a query and
    ///                 is copied into the response.  If RD is set, it directs
    ///                 the name server to pursue the query recursively.
    ///                 Recursive query support is optional.
    /// ```
    pub fn recursion_desired(&self) -> bool {
        self.recursion_desired
    }

    /// ```text
    /// RA              Recursion Available - this be is set or cleared in a
    ///                 response, and denotes whether recursive query support is
    ///                 available in the name server.
    /// ```
    pub fn recursion_available(&self) -> bool {
        self.recursion_available
    }

    /// [RFC 4035, DNSSEC Resource Records, March 2005](https://tools.ietf.org/html/rfc4035#section-3.1.6)
    ///
    /// ```text
    ///
    /// 3.1.6.  The AD and CD Bits in an Authoritative Response
    ///
    ///   The CD and AD bits are designed for use in communication between
    ///   security-aware resolvers and security-aware recursive name servers.
    ///   These bits are for the most part not relevant to query processing by
    ///   security-aware authoritative name servers.
    ///
    ///   A security-aware name server does not perform signature validation
    ///   for authoritative data during query processing, even when the CD bit
    ///   is clear.  A security-aware name server SHOULD clear the CD bit when
    ///   composing an authoritative response.
    ///
    ///   A security-aware name server MUST NOT set the AD bit in a response
    ///   unless the name server considers all RRsets in the Answer and
    ///   Authority sections of the response to be authentic.  A security-aware
    ///   name server's local policy MAY consider data from an authoritative
    ///   zone to be authentic without further validation.  However, the name
    ///   server MUST NOT do so unless the name server obtained the
    ///   authoritative zone via secure means (such as a secure zone transfer
    ///   mechanism) and MUST NOT do so unless this behavior has been
    ///   configured explicitly.
    ///
    ///   A security-aware name server that supports recursion MUST follow the
    ///   rules for the CD and AD bits given in Section 3.2 when generating a
    ///   response that involves data obtained via recursion.
    /// ```
    pub fn authentic_data(&self) -> bool {
        self.authentic_data
    }

    /// see `is_authentic_data()`
    pub fn checking_disabled(&self) -> bool {
        self.checking_disabled
    }

    /// ```text
    /// RCODE           Response code - this 4 bit field is set as part of
    ///                 responses.  The values have the following
    ///                 interpretation: <see super::response_code>
    /// ```
    pub fn response_code(&self) -> ResponseCode {
        self.response_code
    }

    /// ```text
    /// QDCOUNT         an unsigned 16 bit integer specifying the number of
    ///                 entries in the question section.
    /// ```
    ///
    /// # Return value
    ///
    /// If this is a query, this will return the number of queries in the query section of the
    //   message, fo updates this represents the zone count (must be no more than 1).
    pub fn query_count(&self) -> u16 {
        self.query_count
    }

    /// ```text
    /// ANCOUNT         an unsigned 16 bit integer specifying the number of
    ///                 resource records in the answer section.
    /// ```
    ///
    /// # Return value
    ///
    /// For query responses this is the number of records in the answer section, should be 0 for
    ///  requests, for updates this is the count of prerequisite records.
    pub fn answer_count(&self) -> u16 {
        self.answer_count
    }

    /// for queries this is the nameservers which are authorities for the SOA of the Record
    /// for updates this is the update record count
    /// ```text
    /// NSCOUNT         an unsigned 16 bit integer specifying the number of name
    ///                 server resource records in the authority records
    ///                 section.
    /// ```
    ///
    /// # Return value
    ///
    /// For query responses this is the number of authorities, or nameservers, in the name server
    ///  section, for updates this is the number of update records being sent.
    pub fn name_server_count(&self) -> u16 {
        self.name_server_count
    }

    /// ```text
    /// ARCOUNT         an unsigned 16 bit integer specifying the number of
    ///                 resource records in the additional records section.
    /// ```
    ///
    /// # Return value
    ///
    /// This is the additional record section count, this section may include EDNS options.
    pub fn additional_count(&self) -> u16 {
        self.additional_count
    }
}

impl BinEncodable for Header {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        encoder.reserve(12)?; // the 12 bytes for the following fields;

        // Id
        encoder.emit_u16(self.id)?;

        // IsQuery, OpCode, Authoritative, Truncation, RecursionDesired
        let mut q_opcd_a_t_r: u8 = if let MessageType::Response = self.message_type {
            0x80
        } else {
            0x00
        };
        q_opcd_a_t_r |= u8::from(self.op_code) << 3;
        q_opcd_a_t_r |= if self.authoritative { 0x4 } else { 0x0 };
        q_opcd_a_t_r |= if self.truncation { 0x2 } else { 0x0 };
        q_opcd_a_t_r |= if self.recursion_desired { 0x1 } else { 0x0 };
        encoder.emit(q_opcd_a_t_r)?;

        // IsRecursionAvailable, Triple 0's, ResponseCode
        let mut r_z_ad_cd_rcod: u8 = if self.recursion_available {
            0b1000_0000
        } else {
            0b0000_0000
        };
        r_z_ad_cd_rcod |= if self.authentic_data {
            0b0010_0000
        } else {
            0b0000_0000
        };
        r_z_ad_cd_rcod |= if self.checking_disabled {
            0b0001_0000
        } else {
            0b0000_0000
        };
        r_z_ad_cd_rcod |= self.response_code.low();
        encoder.emit(r_z_ad_cd_rcod)?;

        encoder.emit_u16(self.query_count)?;
        encoder.emit_u16(self.answer_count)?;
        encoder.emit_u16(self.name_server_count)?;
        encoder.emit_u16(self.additional_count)?;

        Ok(())
    }
}

impl<'r> BinDecodable<'r> for Header {
    fn read(decoder: &mut BinDecoder<'r>) -> ProtoResult<Self> {
        let id = decoder.read_u16()?.unverified(/*it is valid for this to be any u16*/);

        let q_opcd_a_t_r = decoder.pop()?.unverified(/*used as a bitfield, this is safe*/);
        // if the first bit is set
        let message_type = if (0b1000_0000 & q_opcd_a_t_r) == 0b1000_0000 {
            MessageType::Response
        } else {
            MessageType::Query
        };
        // the 4bit opcode, masked and then shifted right 3bits for the u8...
        let op_code: OpCode = OpCode::from_u8((0b0111_1000 & q_opcd_a_t_r) >> 3)?;
        let authoritative = (0b0000_0100 & q_opcd_a_t_r) == 0b0000_0100;
        let truncation = (0b0000_0010 & q_opcd_a_t_r) == 0b0000_0010;
        let recursion_desired = (0b0000_0001 & q_opcd_a_t_r) == 0b0000_0001;

        let r_z_ad_cd_rcod = decoder.pop()?.unverified(/*used as a bitfield, this is safe*/); // fail fast...

        let recursion_available = (0b1000_0000 & r_z_ad_cd_rcod) == 0b1000_0000;
        let authentic_data = (0b0010_0000 & r_z_ad_cd_rcod) == 0b0010_0000;
        let checking_disabled = (0b0001_0000 & r_z_ad_cd_rcod) == 0b0001_0000;
        let response_code: u8 = 0b0000_1111 & r_z_ad_cd_rcod;
        let response_code = ResponseCode::from_low(response_code);

        // TODO: We should pass these restrictions on, they can't be trusted, but that would seriously complicate the Header type..
        // TODO: perhaps the read methods for BinDecodable should return Restrict?
        let query_count =
            decoder.read_u16()?.unverified(/*this must be verified when reading queries*/);
        let answer_count =
            decoder.read_u16()?.unverified(/*this must be evaluated when reading records*/);
        let name_server_count =
            decoder.read_u16()?.unverified(/*this must be evaluated when reading records*/);
        let additional_count =
            decoder.read_u16()?.unverified(/*this must be evaluated when reading records*/);

        // TODO: question, should this use the builder pattern instead? might be cleaner code, but
        //  this guarantees that the Header is fully instantiated with all values...
        Ok(Self {
            id,
            message_type,
            op_code,
            authoritative,
            truncation,
            recursion_desired,
            recursion_available,
            authentic_data,
            checking_disabled,
            response_code,
            query_count,
            answer_count,
            name_server_count,
            additional_count,
        })
    }
}

#[test]
fn test_parse() {
    let byte_vec = vec![
        0x01, 0x10, 0xAA, 0x83, // 0b1010 1010 1000 0011
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    ];

    let mut decoder = BinDecoder::new(&byte_vec);

    let expect = Header {
        id: 0x0110,
        message_type: MessageType::Response,
        op_code: OpCode::Update,
        authoritative: false,
        truncation: true,
        recursion_desired: false,
        recursion_available: true,
        authentic_data: false,
        checking_disabled: false,
        response_code: ResponseCode::NXDomain,
        query_count: 0x8877,
        answer_count: 0x6655,
        name_server_count: 0x4433,
        additional_count: 0x2211,
    };

    let got = Header::read(&mut decoder).unwrap();

    assert_eq!(got, expect);
}

#[test]
fn test_write() {
    let header = Header {
        id: 0x0110,
        message_type: MessageType::Response,
        op_code: OpCode::Update,
        authoritative: false,
        truncation: true,
        recursion_desired: false,
        recursion_available: true,
        authentic_data: false,
        checking_disabled: false,
        response_code: ResponseCode::NXDomain,
        query_count: 0x8877,
        answer_count: 0x6655,
        name_server_count: 0x4433,
        additional_count: 0x2211,
    };

    let expect: Vec<u8> = vec![
        0x01, 0x10, 0xAA, 0x83, // 0b1010 1010 1000 0011
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    ];

    let mut bytes = Vec::with_capacity(512);
    {
        let mut encoder = BinEncoder::new(&mut bytes);
        header.emit(&mut encoder).unwrap();
    }

    assert_eq!(bytes, expect);
}
