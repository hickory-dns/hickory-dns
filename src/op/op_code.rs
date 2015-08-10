use std::convert::From;

#[derive(Debug, PartialEq, PartialOrd)]
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
      _ => unimplemented!(),
    }
  }
}
