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

// there is not much to format in this file, and we don't want rustfmt to mess up the comments

//! All defined response codes in DNS

use std::fmt;
use std::fmt::{Display, Formatter};

/// The status code of the response to a query.
///
/// [RFC 1035, DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION, November 1987](https://tools.ietf.org/html/rfc1035)
///
/// ```text
/// RCODE           Response code - this 4 bit field is set as part of
///                 responses.  The values have the following
///                 interpretation:
///
///                 0               No error condition
///
///                 1               Format error - The name server was
///                                 unable to interpret the query.
///
///                 2               Server failure - The name server was
///                                 unable to process this query due to a
///                                 problem with the name server.
///
///                 3               Name Error - Meaningful only for
///                                 responses from an authoritative name
///                                 server, this code signifies that the
///                                 domain name referenced in the query does
///                                 not exist.
///
///                 4               Not Implemented - The name server does
///                                 not support the requested kind of query.
///
///                 5               Refused - The name server refuses to
///                                 perform the specified operation for
///                                 policy reasons.  For example, a name
///                                 server may not wish to provide the
///                                 information to the particular requester,
///                                 or a name server may not wish to perform
///                                 a particular operation (e.g., zone
///                                 transfer) for particular data.
///
///                 6-15            Reserved for future use.
///  ```
#[derive(Debug, Eq, PartialEq, PartialOrd, Copy, Clone, Hash)]
#[allow(dead_code)]
pub enum ResponseCode {
    /// No Error [RFC 1035](https://tools.ietf.org/html/rfc1035)
    NoError,

    /// Format Error [RFC 1035](https://tools.ietf.org/html/rfc1035)
    FormErr,

    /// Server Failure [RFC 1035](https://tools.ietf.org/html/rfc1035)
    ServFail,

    /// Non-Existent Domain [RFC 1035](https://tools.ietf.org/html/rfc1035)
    NXDomain,

    /// Not Implemented [RFC 1035](https://tools.ietf.org/html/rfc1035)
    NotImp,

    /// Query Refused [RFC 1035](https://tools.ietf.org/html/rfc1035)
    Refused,

    /// Name Exists when it should not [RFC 2136](https://tools.ietf.org/html/rfc2136)
    YXDomain,

    /// RR Set Exists when it should not [RFC 2136](https://tools.ietf.org/html/rfc2136)
    YXRRSet,

    /// RR Set that should exist does not [RFC 2136](https://tools.ietf.org/html/rfc2136)
    NXRRSet,

    /// Server Not Authoritative for zone [RFC 2136](https://tools.ietf.org/html/rfc2136)
    /// or Not Authorized [RFC 2845](https://tools.ietf.org/html/rfc2845)
    NotAuth,

    /// Name not contained in zone [RFC 2136](https://tools.ietf.org/html/rfc2136)
    NotZone,

    /// Bad OPT Version [RFC 6891](https://tools.ietf.org/html/rfc6891#section-9)
    BADVERS,

    /// TSIG Signature Failure [RFC 2845](https://tools.ietf.org/html/rfc2845)
    BADSIG,

    /// Key not recognized [RFC 2845](https://tools.ietf.org/html/rfc2845)
    BADKEY,

    /// Signature out of time window [RFC 2845](https://tools.ietf.org/html/rfc2845)
    BADTIME,

    /// Bad TKEY Mode [RFC 2930](https://tools.ietf.org/html/rfc2930#section-2.6)
    BADMODE,

    /// Duplicate key name [RFC 2930](https://tools.ietf.org/html/rfc2930#section-2.6)
    BADNAME,

    /// Algorithm not supported [RFC 2930](https://tools.ietf.org/html/rfc2930#section-2.6)
    BADALG,

    /// Bad Truncation [RFC 4635](https://tools.ietf.org/html/rfc4635#section-4)
    BADTRUNC,

    /// Bad/missing server cookie [draft-ietf-dnsop-cookies](https://tools.ietf.org/html/draft-ietf-dnsop-cookies-10)
    BADCOOKIE,
    // 24-3840      Unassigned
    // 3841-4095    Reserved for Private Use                        [RFC6895]
    // 4096-65534   Unassigned
    // 65535        Reserved, can be allocated by Standards Action  [RFC6895]
    /// An unknown or unregisterd response code was received.
    Unknown(u16),
}

impl ResponseCode {
    /// returns the lower 4 bits of the response code (for the original header portion of the code)
    pub fn low(self) -> u8 {
        (u16::from(self) & 0x000F) as u8
    }

    /// returns the high 8 bits for the EDNS portion of the response code
    pub fn high(self) -> u8 {
        ((u16::from(self) & 0x0FF0) >> 4) as u8
    }

    /// DNS can not store the entire space of ResponseCodes in 4 bit space of the Header, this function
    ///   allows for a initial value of the first 4 bits to be set.
    ///
    /// After the EDNS is read, the entire ResponseCode (12 bits) can be reconstructed for the full ResponseCode.
    pub fn from_low(low: u8) -> Self {
        ((u16::from(low)) & 0x000F).into()
    }

    /// Combines the EDNS high and low from the Header to produce the Extended ResponseCode
    pub fn from(high: u8, low: u8) -> Self {
        ((u16::from(high) << 4) | ((u16::from(low)) & 0x000F)).into()
    }

    /// Transforms the response code into the human message
    pub fn to_str(self) -> &'static str {
        match self {
            Self::NoError => "No Error",
            Self::FormErr => "Form Error", // 1     FormErr       Format Error                        [RFC1035]
            Self::ServFail => "Server Failure", // 2     ServFail      Server Failure                      [RFC1035]
            Self::NXDomain => "Non-Existent Domain", // 3     NXDomain      Non-Existent Domain                 [RFC1035]
            Self::NotImp => "Not Implemented", // 4     NotImp        Not Implemented                     [RFC1035]
            Self::Refused => "Query Refused", // 5     Refused       Query Refused                       [RFC1035]
            Self::YXDomain => "Name should not exist", // 6     YXDomain      Name Exists when it should not      [RFC2136][RFC6672]
            Self::YXRRSet => "RR Set should not exist", // 7     YXRRSet       RR Set Exists when it should not    [RFC2136]
            Self::NXRRSet => "RR Set does not exist", // 8     NXRRSet       RR Set that should exist does not   [RFC2136]
            Self::NotAuth => "Not authorized", // 9     NotAuth       Server Not Authoritative for zone   [RFC2136]
            Self::NotZone => "Name not in zone", // 10    NotZone       Name not contained in zone          [RFC2136]
            Self::BADVERS => "Bad option verions", // 16    BADVERS       Bad OPT Version                     [RFC6891]
            Self::BADSIG => "TSIG Failure", // 16    BADSIG        TSIG Signature Failure              [RFC2845]
            Self::BADKEY => "Key not recognized", // 17    BADKEY        Key not recognized                  [RFC2845]
            Self::BADTIME => "Signature out of time window", // 18    BADTIME       Signature out of time window        [RFC2845]
            Self::BADMODE => "Bad TKEY mode", // 19    BADMODE       Bad TKEY Mode                       [RFC2930]
            Self::BADNAME => "Duplicate key name", // 20    BADNAME       Duplicate key name                  [RFC2930]
            Self::BADALG => "Algorithm not supported", // 21    BADALG        Algorithm not supported             [RFC2930]
            Self::BADTRUNC => "Bad truncation", // 22    BADTRUNC      Bad Truncation                      [RFC4635]
            Self::BADCOOKIE => "Bad server cookie", // 23    BADCOOKIE (TEMPORARY - registered 2015-07-26, expires 2016-07-26)    Bad/missing server cookie    [draft-ietf-dnsop-cookies]
            Self::Unknown(_) => "Unknown response code",
        }
    }
}

impl Default for ResponseCode {
    fn default() -> Self {
        Self::NoError
    }
}

impl Display for ResponseCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(self.to_str())
    }
}

/// Convert from `ResponseCode` to `u16`
///
/// ```
/// use std::convert::From;
/// use trust_dns_proto::op::response_code::ResponseCode;
///
/// let var: ResponseCode = From::from(0);
/// assert_eq!(ResponseCode::NoError, var);
///
/// let var: ResponseCode = 0.into();
/// assert_eq!(ResponseCode::NoError, var);
/// ```
impl From<ResponseCode> for u16 {
    fn from(rt: ResponseCode) -> Self {
        match rt {
            ResponseCode::NoError => 0, // 0   NoError    No Error                              [RFC1035]
            ResponseCode::FormErr => 1, // 1   FormErr    Format Error                          [RFC1035]
            ResponseCode::ServFail => 2, // 2   ServFail   Server Failure                        [RFC1035]
            ResponseCode::NXDomain => 3, // 3   NXDomain   Non-Existent Domain                   [RFC1035]
            ResponseCode::NotImp => 4, // 4   NotImp     Not Implemented                       [RFC1035]
            ResponseCode::Refused => 5, // 5   Refused    Query Refused                         [RFC1035]
            ResponseCode::YXDomain => 6, // 6   YXDomain   Name Exists when it should not        [RFC2136][RFC6672]
            ResponseCode::YXRRSet => 7, // 7   YXRRSet    RR Set Exists when it should not      [RFC2136]
            ResponseCode::NXRRSet => 8, // 8   NXRRSet    RR Set that should exist does not     [RFC2136]
            ResponseCode::NotAuth => 9, // 9   NotAuth    Server Not Authoritative for zone     [RFC2136]
            ResponseCode::NotZone => 10, // 10  NotZone    Name not contained in zone            [RFC2136]
            //
            // 11-15    Unassigned
            //
            // 16  BADVERS  Bad OPT Version         [RFC6891]
            // 16  BADSIG   TSIG Signature Failure  [RFC2845]
            ResponseCode::BADVERS | ResponseCode::BADSIG => 16,
            ResponseCode::BADKEY => 17, // 17  BADKEY    Key not recognized                     [RFC2845]
            ResponseCode::BADTIME => 18, // 18  BADTIME   Signature out of time window           [RFC2845]
            ResponseCode::BADMODE => 19, // 19  BADMODE   Bad TKEY Mode                          [RFC2930]
            ResponseCode::BADNAME => 20, // 20  BADNAME   Duplicate key name                     [RFC2930]
            ResponseCode::BADALG => 21, // 21  BADALG    Algorithm not supported                [RFC2930]
            ResponseCode::BADTRUNC => 22, // 22  BADTRUNC  Bad Truncation                         [RFC4635]
            // 23  BADCOOKIE (TEMPORARY - registered 2015-07-26, expires 2016-07-26)    Bad/missing server cookie    [draft-ietf-dnsop-cookies]
            ResponseCode::BADCOOKIE => 23,
            ResponseCode::Unknown(code) => code,
        }
    }
}

/// Convert from `u16` to `ResponseCode`
///
/// ```
/// use std::convert::From;
/// use trust_dns_proto::op::response_code::ResponseCode;
///
/// let var: u16 = From::from(ResponseCode::NoError);
/// assert_eq!(0, var);
///
/// let var: u16 = ResponseCode::NoError.into();
/// assert_eq!(0, var);
/// ```
impl From<u16> for ResponseCode {
    #[allow(clippy::unimplemented)]
    fn from(value: u16) -> Self {
        match value {
            0 => Self::NoError, // 0    NoError    No Error                             [RFC1035]
            1 => Self::FormErr, // 1    FormErr    Format Error                         [RFC1035]
            2 => Self::ServFail, // 2    ServFail   Server Failure                       [RFC1035]
            3 => Self::NXDomain, // 3    NXDomain   Non-Existent Domain                  [RFC1035]
            4 => Self::NotImp,  // 4    NotImp     Not Implemented                      [RFC1035]
            5 => Self::Refused, // 5    Refused    Query Refused                        [RFC1035]
            6 => Self::YXDomain, // 6    YXDomain   Name Exists when it should not       [RFC2136][RFC6672]
            7 => Self::YXRRSet,  // 7    YXRRSet    RR Set Exists when it should not     [RFC2136]
            8 => Self::NXRRSet,  // 8    NXRRSet    RR Set that should exist does not    [RFC2136]
            9 => Self::NotAuth,  // 9    NotAuth    Server Not Authoritative for zone    [RFC2136]
            10 => Self::NotZone, // 10   NotZone    Name not contained in zone           [RFC2136]
            // this looks to be backwards compat for 4 bit ResponseCodes.
            // 16    BADVERS    Bad OPT Version    [RFC6891]
            // 16 => ResponseCode::BADVERS,
            16 => Self::BADSIG, // 16    BADSIG    TSIG Signature Failure               [RFC2845]
            17 => Self::BADKEY, // 17    BADKEY    Key not recognized                   [RFC2845]
            18 => Self::BADTIME, // 18    BADTIME   Signature out of time window         [RFC2845]
            19 => Self::BADMODE, // 19    BADMODE   Bad TKEY Mode                        [RFC2930]
            20 => Self::BADNAME, // 20    BADNAME   Duplicate key name                   [RFC2930]
            21 => Self::BADALG, // 21    BADALG    Algorithm not supported              [RFC2930]
            22 => Self::BADTRUNC, // 22    BADTRUNC  Bad Truncation                       [RFC4635]
            23 => Self::BADCOOKIE, // 23    BADCOOKIE (TEMPORARY - registered 2015-07-26, expires 2016-07-26)    Bad/missing server cookie    [draft-ietf-dnsop-cookies]
            code => Self::Unknown(code),
        }
    }
}
