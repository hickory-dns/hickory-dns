use std::convert::From;
use ::serialize::binary::*;
use ::error::*;

#[derive(Debug, PartialEq, PartialOrd, Copy, Clone)]
#[allow(dead_code)]
pub enum DNSClass {
  IN,          //	1	RFC 1035	Internet (IN)
  CH,          // 3 Chaos (CH)
  HS,          // 4 Hesiod (HS)
  NONE,        // 254 QCLASS NONE
//  ANY,         // 255 QCLASS * (ANY)
}

impl DNSClass {
  /// Convert from &str to DNSClass
  ///
  /// ```
  /// use trust_dns::rr::dns_class::DNSClass;
  ///
  /// let var: DNSClass = DNSClass::from_str("IN").unwrap();
  /// assert_eq!(DNSClass::IN, var);
  /// ```
  pub fn from_str(str: &str) -> DecodeResult<Self> {
    match str {
      "IN" => Ok(DNSClass::IN),
      "CH" => Ok(DNSClass::CH),
      "HS" => Ok(DNSClass::HS),
      "NONE" => Ok(DNSClass::NONE),
      //      "ANY" => DNSClass::ANY,
      //      "*" => DNSClass::ANY,
      _ => Err(DecodeError::UnknownDnsClassStr(str.to_string())),
    }
  }


  /// Convert from u16 to DNSClass
  ///
  /// ```
  /// use trust_dns::rr::dns_class::DNSClass;
  ///
  /// let var = DNSClass::from_u16(1).unwrap();
  /// assert_eq!(DNSClass::IN, var);
  /// ```
  pub fn from_u16(value: u16) -> DecodeResult<Self> {
    match value {
      1 => Ok(DNSClass::IN),
      3 => Ok(DNSClass::CH),
      4 => Ok(DNSClass::HS),
      254 => Ok(DNSClass::NONE),
      //      255 => DNSClass::ANY,
      _ => Err(DecodeError::UnknownDnsClassValue(value)),
    }
  }
}

impl BinSerializable for DNSClass {
  fn read(decoder: &mut BinDecoder) -> DecodeResult<Self> {
    Self::from_u16(try!(decoder.read_u16()))
  }

  fn emit(&self, encoder: &mut BinEncoder) -> EncodeResult {
    encoder.emit_u16((*self).into())
  }
}

// TODO make these a macro or annotation

/// Convert from DNSClass to &str
///
/// ```
/// use trust_dns::rr::dns_class::DNSClass;
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
//      DNSClass::ANY => "ANY",
    }
  }
}



/// Convert from DNSClass to u16
///
/// ```
/// use trust_dns::rr::dns_class::DNSClass;
///
/// let var: u16 = DNSClass::IN.into();
/// assert_eq!(1, var);
/// ```
impl From<DNSClass> for u16 {
  fn from(rt: DNSClass) -> Self {
    match rt {
      DNSClass::IN => 1,
      DNSClass::CH => 3,
      DNSClass::HS => 4,
      DNSClass::NONE => 254,
//      DNSClass::ANY => 255,
    }
  }
}
