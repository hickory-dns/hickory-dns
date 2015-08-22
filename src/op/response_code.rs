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

/*
 * RFC 1035        Domain Implementation and Specification    November 1987
 *
 * RCODE           Response code - this 4 bit field is set as part of
 *                 responses.  The values have the following
 *                 interpretation:
 *
 *                 0               No error condition
 *
 *                 1               Format error - The name server was
 *                                 unable to interpret the query.
 *
 *                 2               Server failure - The name server was
 *                                 unable to process this query due to a
 *                                 problem with the name server.
 *
 *                 3               Name Error - Meaningful only for
 *                                 responses from an authoritative name
 *                                 server, this code signifies that the
 *                                 domain name referenced in the query does
 *                                 not exist.
 *
 *                 4               Not Implemented - The name server does
 *                                 not support the requested kind of query.
 *
 *                 5               Refused - The name server refuses to
 *                                 perform the specified operation for
 *                                 policy reasons.  For example, a name
 *                                 server may not wish to provide the
 *                                 information to the particular requester,
 *                                 or a name server may not wish to perform
 *                                 a particular operation (e.g., zone
 *
 *                                 transfer) for particular data.
 *
 *                 6-15            Reserved for future use.
 */
#[derive(Debug, PartialEq, PartialOrd, Copy, Clone)]
#[allow(dead_code)]
pub enum ResponseCode {
  NoError,   // 0	NoError	No Error	[RFC1035]
  FormErr,   // 1	FormErr	Format Error	[RFC1035]
  ServFail,  // 2	ServFail	Server Failure	[RFC1035]
  NXDomain,  // 3	NXDomain	Non-Existent Domain	[RFC1035]
  NotImp,    // 4	NotImp	Not Implemented	[RFC1035]
  Refused,   // 5	Refused	Query Refused	[RFC1035]
  YXDomain,  // 6	YXDomain	Name Exists when it should not	[RFC2136][RFC6672]
  YXRRSet,   // 7	YXRRSet	RR Set Exists when it should not	[RFC2136]
  NXRRSet,   // 8	NXRRSet	RR Set that should exist does not	[RFC2136]
  NotAuth,   // 9	NotAuth	Server Not Authoritative for zone	[RFC2136]
             // 9	NotAuth	Not Authorized	[RFC2845]
  NotZone,   // 10	NotZone	Name not contained in zone	[RFC2136]
             // 11-15	Unassigned
  BADVERS,   // 16	BADVERS	Bad OPT Version	[RFC6891]
  BADSIG,    // 16	BADSIG	TSIG Signature Failure	[RFC2845]
  BADKEY,    // 17	BADKEY	Key not recognized	[RFC2845]
  BADTIME,   // 18	BADTIME	Signature out of time window	[RFC2845]
  BADMODE,   // 19	BADMODE	Bad TKEY Mode	[RFC2930]
  BADNAME,   // 20	BADNAME	Duplicate key name	[RFC2930]
  BADALG,    // 21	BADALG	Algorithm not supported	[RFC2930]
  BADTRUNC,  // 22	BADTRUNC	Bad Truncation	[RFC4635]
  BADCOOKIE, // 23	BADCOOKIE (TEMPORARY - registered 2015-07-26, expires 2016-07-26)	Bad/missing server cookie	[draft-ietf-dnsop-cookies]
             // 24-3840	Unassigned
             // 3841-4095	Reserved for Private Use		[RFC6895]
             // 4096-65534	Unassigned
             // 65535	Reserved, can be allocated by Standards Action		[RFC6895]
}

/**
 * Convert from ResponseCode to u8
 *
 * ```
 * use std::convert::From;
 * use trust_dns::op::response_code::ResponseCode;
 *
 * let var: ResponseCode = From::from(0);
 * assert_eq!(ResponseCode::NoError, var);
 *
 * let var: ResponseCode = 0.into();
 * assert_eq!(ResponseCode::NoError, var);
 * ```
 */
impl From<ResponseCode> for u8 {
  fn from(rt: ResponseCode) -> Self {
    match rt {
      ResponseCode::NoError   => 0,  // 0	  NoError	No Error	[RFC1035]
      ResponseCode::FormErr   => 1,  // 1	  FormErr	Format Error	[RFC1035]
      ResponseCode::ServFail  => 2,  // 2	  ServFail	Server Failure	[RFC1035]
      ResponseCode::NXDomain  => 3,  // 3	  NXDomain	Non-Existent Domain	[RFC1035]
      ResponseCode::NotImp    => 4,  // 4	  NotImp	Not Implemented	[RFC1035]
      ResponseCode::Refused   => 5,  // 5	  Refused	Query Refused	[RFC1035]
      ResponseCode::YXDomain  => 6,  // 6	  YXDomain	Name Exists when it should not	[RFC2136][RFC6672]
      ResponseCode::YXRRSet   => 7,  // 7	  YXRRSet	RR Set Exists when it should not	[RFC2136]
      ResponseCode::NXRRSet   => 8,  // 8	  NXRRSet	RR Set that should exist does not	[RFC2136]
      ResponseCode::NotAuth   => 9,  // 9	  NotAuth	Server Not Authoritative for zone	[RFC2136]
      ResponseCode::NotZone   => 10, // 10	NotZone	Name not contained in zone	[RFC2136]
      ResponseCode::BADVERS   => 16, // 16	BADVERS	Bad OPT Version	[RFC6891]
      ResponseCode::BADSIG    => 16, // 16	BADSIG	TSIG Signature Failure	[RFC2845]
      ResponseCode::BADKEY    => 17, // 17	BADKEY	Key not recognized	[RFC2845]
      ResponseCode::BADTIME   => 18, // 18	BADTIME	Signature out of time window	[RFC2845]
      ResponseCode::BADMODE   => 19, // 19	BADMODE	Bad TKEY Mode	[RFC2930]
      ResponseCode::BADNAME   => 20, // 20	BADNAME	Duplicate key name	[RFC2930]
      ResponseCode::BADALG    => 21, // 21	BADALG	Algorithm not supported	[RFC2930]
      ResponseCode::BADTRUNC  => 22, // 22	BADTRUNC	Bad Truncation	[RFC4635]
      ResponseCode::BADCOOKIE => 23, // 23	BADCOOKIE (TEMPORARY - registered 2015-07-26, expires 2016-07-26)	Bad/missing server cookie	[draft-ietf-dnsop-cookies]
    }
  }
}

/**
 * Convert from u8 to ResponseCode
 *
 * ```
 * use std::convert::From;
 * use trust_dns::op::response_code::ResponseCode;
 *
 * let var: u8 = From::from(ResponseCode::NoError);
 * assert_eq!(0, var);
 *
 * let var: u8 = ResponseCode::NoError.into();
 * assert_eq!(0, var);
 * ```
 */
impl From<u8> for ResponseCode {
  fn from(value: u8) -> Self {
    match value {
      0  => ResponseCode::NoError,   // 0	NoError	No Error	[RFC1035]
      1  => ResponseCode::FormErr,   // 1	FormErr	Format Error	[RFC1035]
      2  => ResponseCode::ServFail,  // 2	ServFail	Server Failure	[RFC1035]
      3  => ResponseCode::NXDomain,  // 3	NXDomain	Non-Existent Domain	[RFC1035]
      4  => ResponseCode::NotImp,    // 4	NotImp	Not Implemented	[RFC1035]
      5  => ResponseCode::Refused,   // 5	Refused	Query Refused	[RFC1035]
      6  => ResponseCode::YXDomain,  // 6	YXDomain	Name Exists when it should not	[RFC2136][RFC6672]
      7  => ResponseCode::YXRRSet,   // 7	YXRRSet	RR Set Exists when it should not	[RFC2136]
      8  => ResponseCode::NXRRSet,   // 8	NXRRSet	RR Set that should exist does not	[RFC2136]
      9  => ResponseCode::NotAuth,   // 9	NotAuth	Server Not Authoritative for zone	[RFC2136]
      10 => ResponseCode::NotZone,   // 10	NotZone	Name not contained in zone	[RFC2136]
      // this looks to be backwards compat for 4 bit ResponseCodes.
      //16 => ResponseCode::BADVERS,   // 16	BADVERS	Bad OPT Version	[RFC6891]
      16 => ResponseCode::BADSIG,    // 16	BADSIG	TSIG Signature Failure	[RFC2845]
      17 => ResponseCode::BADKEY,    // 17	BADKEY	Key not recognized	[RFC2845]
      18 => ResponseCode::BADTIME,   // 18	BADTIME	Signature out of time window	[RFC2845]
      19 => ResponseCode::BADMODE,   // 19	BADMODE	Bad TKEY Mode	[RFC2930]
      20 => ResponseCode::BADNAME,   // 20	BADNAME	Duplicate key name	[RFC2930]
      21 => ResponseCode::BADALG,    // 21	BADALG	Algorithm not supported	[RFC2930]
      22 => ResponseCode::BADTRUNC,  // 22	BADTRUNC	Bad Truncation	[RFC4635]
      23 => ResponseCode::BADCOOKIE, // 23	BADCOOKIE (TEMPORARY - registered 2015-07-26, expires 2016-07-26)	Bad/missing server cookie	[draft-ietf-dnsop-cookies]
      _ => unimplemented!(),
    }
  }
}
