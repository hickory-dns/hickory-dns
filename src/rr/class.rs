use std::convert::From;

#[derive(Debug, PartialEq, PartialOrd)]
#[allow(dead_code)]
pub enum RecordClass {
  IN,          //	1	RFC 1035	Internet (IN)
  CH,          // 3 Chaos (CH)
  HS,          // 4 Hesiod (HS)
  NONE,        // 254 QCLASS NONE
  ANY,         // 255 QCLASS * (ANY)
}

// TODO make these a macro...

/// Convert from RecordClass to &str
///
/// ```
/// use std::convert::From;
/// use trust_dns::rr::record_types::RecordClass;
///
/// let var: &'static str = From::from(RecordClass::IN);
/// assert_eq!("IN", var);
///
/// let var: &'static str = RecordClass::IN.into();
/// assert_eq!("IN", var);
/// ```
impl From<RecordClass> for &'static str {
  fn from(rt: RecordClass) -> &'static str {
    match rt {
      RecordClass::IN => "IN",
      RecordClass::CH => "CH",
      RecordClass::HS => "HS",
      RecordClass::NONE => "NONE",
      RecordClass::ANY => "ANY",
      _ => unimplemented!(),
    }
  }
}

/// Convert from RecordClass to &str
///
/// ```
/// use std::convert::From;
/// use trust_dns::rr::record_types::RecordClass;
///
/// let var: RecordClass = From::from("A");
/// assert_eq!(RecordClass::A, var);
///
/// let var: RecordClass = "A".into();
/// assert_eq!(RecordClass::A, var);
/// ```
impl<'a> From<&'a str> for RecordClass {
  fn from(str: &'a str) -> Self {
    match str {
      "IN" => RecordClass::IN,
      "CH" => RecordClass::CH,
      "HS" => RecordClass::HS,
      "NONE" => RecordClass::NONE,
      "ANY" => RecordClass::ANY,
      "*" => RecordClass::ANY,
      _ => unimplemented!(),
    }
  }
}

/// Convert from RecordClass to &str
///
/// ```
/// use std::convert::From;
/// use trust_dns::rr::record_types::RecordClass;
///
/// let var: RecordClass = From::from(1);
/// assert_eq!(RecordClass::A, var);
///
/// let var: RecordClass = 1.into();
/// assert_eq!(RecordClass::A, var);
/// ```
impl From<RecordClass> for u16 {
  fn from(rt: RecordClass) -> Self {
    match rt {
      RecordClass::IN => 1,
      RecordClass::CH => 3,
      RecordClass::HS => 4,
      RecordClass::NONE => 254,
      RecordClass::ANY => 255,
      _ => unimplemented!(),
    }
  }
}

/// Convert from RecordClass to &str
///
/// ```
/// use std::convert::From;
/// use trust_dns::rr::record_types::RecordClass;
///
/// let var: u16 = From::from(RecordClass::A);
/// assert_eq!(1, var);
///
/// let var: u16 = RecordClass::A.into();
/// assert_eq!(1, var);
/// ```
impl From<u16> for RecordClass {
  fn from(value: u16) -> Self {
    match value {
      1 => RecordClass::IN,
      3 => RecordClass::CH,
      4 => RecordClass::HS,
      254 => RecordClass::NONE,
      255 => RecordClass::ANY,
      _ => unimplemented!(),
    }
  }
}
