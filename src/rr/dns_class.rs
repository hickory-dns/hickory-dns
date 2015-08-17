use std::convert::From;
use super::util;

#[derive(Debug, PartialEq, PartialOrd, Copy, Clone)]
#[allow(dead_code)]
pub enum DNSClass {
  IN,          //	1	RFC 1035	Internet (IN)
  CH,          // 3 Chaos (CH)
  HS,          // 4 Hesiod (HS)
  NONE,        // 254 QCLASS NONE
  ANY,         // 255 QCLASS * (ANY)
}

impl DNSClass {
  pub fn parse(data: &mut Vec<u8>) -> Self {
    util::parse_u16(data).into()
  }

  pub fn write_to(&self, buf: &mut Vec<u8>) {
    util::write_u16_to(buf, (*self).into());
  }
}

// TODO make these a macro or annotation

/// Convert from DNSClass to &str
///
/// ```
/// use std::convert::From;
/// use trust_dns::rr::dns_class::DNSClass;
///
/// let var: &'static str = From::from(DNSClass::IN);
/// assert_eq!("IN", var);
///
/// let var: &'static str = DNSClass::IN.into();
/// assert_eq!("IN", var);
/// ```
impl From<DNSClass> for &'static str {
  fn from(rt: DNSClass) -> &'static str {
    match rt {
      DNSClass::IN => "IN",
      DNSClass::CH => "CH",
      DNSClass::HS => "HS",
      DNSClass::NONE => "NONE",
      DNSClass::ANY => "ANY",
    }
  }
}

/// Convert from &str to DNSClass
///
/// ```
/// use std::convert::From;
/// use trust_dns::rr::dns_class::DNSClass;
///
/// let var: DNSClass = From::from("IN");
/// assert_eq!(DNSClass::IN, var);
///
/// let var: DNSClass = "IN".into();
/// assert_eq!(DNSClass::IN, var);
/// ```
impl<'a> From<&'a str> for DNSClass {
  fn from(str: &'a str) -> Self {
    match str {
      "IN" => DNSClass::IN,
      "CH" => DNSClass::CH,
      "HS" => DNSClass::HS,
      "NONE" => DNSClass::NONE,
      "ANY" => DNSClass::ANY,
      "*" => DNSClass::ANY,
      _ => unimplemented!(),
    }
  }
}

/// Convert from DNSClass to u16
///
/// ```
/// use std::convert::From;
/// use trust_dns::rr::dns_class::DNSClass;
///
/// let var: DNSClass = From::from(1);
/// assert_eq!(DNSClass::IN, var);
///
/// let var: DNSClass = 1.into();
/// assert_eq!(DNSClass::IN, var);
/// ```
impl From<DNSClass> for u16 {
  fn from(rt: DNSClass) -> Self {
    match rt {
      DNSClass::IN => 1,
      DNSClass::CH => 3,
      DNSClass::HS => 4,
      DNSClass::NONE => 254,
      DNSClass::ANY => 255,
    }
  }
}

/// Convert from u16 to DNSClass
///
/// ```
/// use std::convert::From;
/// use trust_dns::rr::dns_class::DNSClass;
///
/// let var: u16 = From::from(DNSClass::IN);
/// assert_eq!(1, var);
///
/// let var: u16 = DNSClass::IN.into();
/// assert_eq!(1, var);
/// ```
impl From<u16> for DNSClass {
  fn from(value: u16) -> Self {
    match value {
      1 => DNSClass::IN,
      3 => DNSClass::CH,
      4 => DNSClass::HS,
      254 => DNSClass::NONE,
      255 => DNSClass::ANY,
      _ => unimplemented!(),
    }
  }
}
