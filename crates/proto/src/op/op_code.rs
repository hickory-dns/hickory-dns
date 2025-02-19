// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Operation code for queries, updates, and responses

use core::{convert::From, fmt};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

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
#[derive(Debug, PartialEq, Eq, PartialOrd, Copy, Clone, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
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

    /// Any other opcode
    Unknown(u8),
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Query => f.write_str("QUERY"),
            Self::Status => f.write_str("STATUS"),
            Self::Notify => f.write_str("NOTIFY"),
            Self::Update => f.write_str("UPDATE"),
            Self::Unknown(opcode) => write!(f, "Unknown opcode ({opcode})"),
        }
    }
}

/// Convert from `OpCode` to `u8`
///
/// ```
/// use hickory_proto::op::op_code::OpCode;
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
            OpCode::Unknown(opcode) => opcode,
        }
    }
}

/// Convert from `u8` to `OpCode`
///
/// ```
/// use hickory_proto::op::op_code::OpCode;
///
/// let var: OpCode = OpCode::from_u8(0);
/// assert_eq!(OpCode::Query, var);
/// ```
impl OpCode {
    /// Decodes the binary value of the OpCode
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Query,
            2 => Self::Status,
            4 => Self::Notify,
            5 => Self::Update,
            _ => Self::Unknown(value),
        }
    }
}
