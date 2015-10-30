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

use std::convert::From;

/*
 * RFC 1035        Domain Implementation and Specification    November 1987
 *
 * OPCODE          A four bit field that specifies kind of query in this
 *                 message.  This value is set by the originator of a query
 *                 and copied into the response.  The values are:
 *
 *                 0               a standard query (QUERY)
 *
 *                 1               an inverse query (IQUERY)
 *
 *                 2               a server status request (STATUS)
 *
 *                 3-15            reserved for future use
 */
#[derive(Debug, PartialEq, PartialOrd, Copy, Clone)]
#[allow(dead_code)]
pub enum OpCode {
  Query,  // 0	Query	[RFC1035]
          // 1	IQuery (Inverse Query, OBSOLETE)	[RFC3425]
  Status, // 2	Status	[RFC1035]
          // 3	Unassigned
  Notify, // 4	Notify	[RFC1996]
  Update, // 5	Update	[RFC2136]
          // 6-15	Unassigned
}

/// Convert from OpCode to u8
///
/// ```
/// use std::convert::From;
/// use trust_dns::op::op_code::OpCode;
///
/// let var: OpCode = From::from(0);
/// assert_eq!(OpCode::Query, var);
///
/// let var: OpCode = 0.into();
/// assert_eq!(OpCode::Query, var);
/// ```
impl From<OpCode> for u8 {
  fn from(rt: OpCode) -> Self {
    match rt {
      OpCode::Query  => 0,
      OpCode::Status => 2,
      OpCode::Notify => 4,
      OpCode::Update => 5,
    }
  }
}

/// Convert from u8 to OpCode
///
/// ```
/// use std::convert::From;
/// use trust_dns::op::op_code::OpCode;
///
/// let var: u8 = From::from(OpCode::Query);
/// assert_eq!(0, var);
///
/// let var: u8 = OpCode::Query.into();
/// assert_eq!(0, var);
/// ```
impl From<u8> for OpCode {
  fn from(value: u8) -> Self {
    match value {
      0 => OpCode::Query,
      2 => OpCode::Status,
      4 => OpCode::Notify,
      5 => OpCode::Update,
      _ => panic!("unimplemented code: {}", value),
    }
  }
}
