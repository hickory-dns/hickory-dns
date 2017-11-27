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

//! Operation code for queries, updates, and responses

use std::convert::From;

use error::*;

/// Operation code for queries, updates, and responses
///
/// [RFC 1035, DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION, November 1987](https://tools.ietf.org/html/rfc1035)
///
/// ```text
/// OPCODE          A four bit field that specifies kind of query in this
///                 message.  This value is set by the originator of a query
///                 and copied into the response.  The values are:
///
///                 0               a standard query (QUERY)
///
///                 1               an inverse query (IQUERY)
///
///                 2               a server status request (STATUS)
///
///                 3-15            reserved for future use
/// ```
#[derive(Debug, PartialEq, PartialOrd, Copy, Clone)]
#[allow(dead_code)]
pub enum OpCode {
    /// Query request [RFC 1035](https://tools.ietf.org/html/rfc1035)
    Query,

    /// Status message [RFC 1035](https://tools.ietf.org/html/rfc1035)
    Status,

    /// Notify of change [RFC 1996](https://tools.ietf.org/html/rfc1996)
    Notify,

    /// Update message [RFC 2136](https://tools.ietf.org/html/rfc2136)
    Update,
}

/// Convert from OpCode to u8
///
/// ```
/// use std::convert::From;
/// use trust_dns_proto::op::op_code::OpCode;
///
/// let var: u8 = From::from(OpCode::Query);
/// assert_eq!(0, var);
///
/// let var: u8 = OpCode::Query.into();
/// assert_eq!(0, var);
/// ```
impl From<OpCode> for u8 {
    fn from(rt: OpCode) -> Self {
        match rt {
            OpCode::Query => 0,
            // 1	IQuery (Inverse Query, OBSOLETE)	[RFC3425]
            OpCode::Status => 2,
            // 3	Unassigned
            OpCode::Notify => 4,
            OpCode::Update => 5,
            // 6-15	Unassigned
        }
    }
}

/// Convert from u8 to OpCode
///
/// ```
/// use std::convert::From;
/// use trust_dns_proto::op::op_code::OpCode;
///
/// let var: OpCode = OpCode::from_u8(0).unwrap();
/// assert_eq!(OpCode::Query, var);
/// ```
impl OpCode {
    /// Decodes the binary value of the OpCode
    pub fn from_u8(value: u8) -> ProtoResult<Self> {
        match value {
            0 => Ok(OpCode::Query),
            2 => Ok(OpCode::Status),
            4 => Ok(OpCode::Notify),
            5 => Ok(OpCode::Update),
            _ => Err(ProtoErrorKind::Msg(format!("unknown OpCode: {}", value)).into()),
        }
    }
}
