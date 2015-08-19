use std::convert::From;
use super::util;

#[derive(Debug, PartialEq, PartialOrd, Copy, Clone)]
#[allow(dead_code)]
pub enum RecordType {
    A,          //	1	RFC 1035[1]	IPv4 Address record
    AAAA,       //	28	RFC 3596[2]	IPv6 address record
  //  AFSDB,      //	18	RFC 1183	AFS database record
  //  APL,        //	42	RFC 3123	Address Prefix List
  //  CAA,        //	257	RFC 6844	Certification Authority Authorization
  //  CDNSKEY,    //	60	RFC 7344	Child DNSKEY
  //  CDS,        //	59	RFC 7344	Child DS
  //  CERT,       //	37	RFC 4398	Certificate record
    CNAME,      //	5	RFC 1035[1]	Canonical name record
  //  DHCID,      //	49	RFC 4701	DHCP identifier
  //  DLV,        //	32769	RFC 4431	DNSSEC Lookaside Validation record
  //  DNAME,      //	39	RFC 2672	Delegation Name
  //  DNSKEY,     //	48	RFC 4034	DNS Key record
  //  DS,         //	43	RFC 4034	Delegation signer
  //  HIP,        //	55	RFC 5205	Host Identity Protocol
  //  IPSECKEY,   //	45	RFC 4025	IPsec Key
  //  KEY,        //	25	RFC 2535[3] and RFC 2930[4]	Key record
  //  KX,         //	36	RFC 2230	Key eXchanger record
  //  LOC,        //	29	RFC 1876	Location record
    MX,         //	15	RFC 1035[1]	Mail exchange record
  //  NAPTR,      //	35	RFC 3403	Naming Authority Pointer
    NS,         //	2	RFC 1035[1]	Name server record
  //  NSEC,       //	47	RFC 4034	Next-Secure record
  //  NSEC3,      //	50	RFC 5155	NSEC record version 3
  //  NSEC3PARAM, //	51	RFC 5155	NSEC3 parameters
    PTR,        //	12	RFC 1035[1]	Pointer record
  //  RRSIG,      //	46	RFC 4034	DNSSEC signature
  //  RP,         //	17	RFC 1183	Responsible person
  //  SIG,        //	24	RFC 2535	Signature
    SOA,        //	6	RFC 1035[1] and RFC 2308[9]	Start of [a zone of] authority record
  //  SRV,        //	33	RFC 2782	Service locator
  //  SSHFP,      //	44	RFC 4255	SSH Public Key Fingerprint
  //  TA,         //	32768	N/A	DNSSEC Trust Authorities
  //  TKEY,       //	249	RFC 2930	Secret key record
  //  TLSA,       //	52	RFC 6698	TLSA certificate association
  //  TSIG,       //	250	RFC 2845	Transaction Signature
    TXT,        //	16	RFC 1035[1]	Text record
  //  ANY,        //  *	255	RFC 1035[1]	All cached records, aka ANY
    AXFR,       //	252	RFC 1035[1]	Authoritative Zone Transfer
    IXFR,       //	251	RFC 1996	Incremental Zone Transfer
    OPT,        //	41	RFC 6891	Option
}

impl RecordType {
  pub fn parse(data: &mut Vec<u8>) -> Self {
    util::parse_u16(data).into()
  }

  pub fn write_to(&self, buf: &mut Vec<u8>) {
    util::write_u16_to(buf, (*self).into());
  }
}


// TODO make these a macro...


/// Convert from RecordType to &str
///
/// ```
/// use std::convert::From;
/// use trust_dns::rr::record_type::RecordType;
///
/// let var: &'static str = From::from(RecordType::A);
/// assert_eq!("A", var);
///
/// let var: &'static str = RecordType::A.into();
/// assert_eq!("A", var);
/// ```
impl From<RecordType> for &'static str {
  fn from(rt: RecordType) -> &'static str {
    match rt {
      RecordType::A => "A",
      RecordType::AAAA => "AAAA",
      RecordType::CNAME => "CNAME",
      RecordType::NS => "NS",
      RecordType::SOA => "SOA",
      _ => panic!("unsupported RecordType: {:?}", rt),
    }
  }
}

/// Convert from RecordType to &str
///
/// ```
/// use std::convert::From;
/// use trust_dns::rr::record_type::RecordType;
///
/// let var: RecordType = From::from("A");
/// assert_eq!(RecordType::A, var);
///
/// let var: RecordType = "A".into();
/// assert_eq!(RecordType::A, var);
/// ```
impl<'a> From<&'a str> for RecordType {
  fn from(str: &'a str) -> Self {
    match str {
      "A" => RecordType::A,
      "AAAA" => RecordType::AAAA,
      "CNAME" => RecordType::CNAME,
      "NS" => RecordType::NS,
      "SOA" => RecordType::SOA,
      _ => panic!("unsupported RecordType: {:?}", str),
    }
  }
}

/// Convert from RecordType to &str
///
/// ```
/// use std::convert::From;
/// use trust_dns::rr::record_type::RecordType;
///
/// let var: RecordType = From::from(1);
/// assert_eq!(RecordType::A, var);
///
/// let var: RecordType = 1.into();
/// assert_eq!(RecordType::A, var);
/// ```
impl From<RecordType> for u16 {
  fn from(rt: RecordType) -> Self {
    match rt {
      RecordType::A => 1,
      RecordType::AAAA => 28,
      RecordType::CNAME => 5,
      RecordType::NS => 2,
      RecordType::SOA => 6,
      _ => panic!("unsupported RecordType: {:?}", rt),
    }
  }
}

/// Convert from RecordType to &str
///
/// ```
/// use std::convert::From;
/// use trust_dns::rr::record_type::RecordType;
///
/// let var: u16 = From::from(RecordType::A);
/// assert_eq!(1, var);
///
/// let var: u16 = RecordType::A.into();
/// assert_eq!(1, var);
/// ```
impl From<u16> for RecordType {
  fn from(value: u16) -> Self {
    match value {
      1 => RecordType::A,
      28 => RecordType::AAAA,
      5 => RecordType::CNAME,
      2 => RecordType::NS,
      6 => RecordType::SOA,
      _ => panic!("unsupported RecordType: {:?}", value),
    }
  }
}
