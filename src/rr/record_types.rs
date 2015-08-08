use core::convert::{From, Into}

#[derive(Debug)]
pub enum RecordType {
    A,          //	1	RFC 1035[1]	IPv4 Address record
    AAAA,       //	28	RFC 3596[2]	IPv6 address record
    AFSDB,      //	18	RFC 1183	AFS database record
    APL,        //	42	RFC 3123	Address Prefix List
    CAA,        //	257	RFC 6844	Certification Authority Authorization
    CDNSKEY,    //	60	RFC 7344	Child DNSKEY
    CDS,        //	59	RFC 7344	Child DS
    CERT,       //	37	RFC 4398	Certificate record
    CNAME,      //	5	RFC 1035[1]	Canonical name record
    DHCID,      //	49	RFC 4701	DHCP identifier
    DLV,        //	32769	RFC 4431	DNSSEC Lookaside Validation record
    DNAME,      //	39	RFC 2672	Delegation Name
    DNSKEY,     //	48	RFC 4034	DNS Key record
    DS,         //	43	RFC 4034	Delegation signer
    HIP,        //	55	RFC 5205	Host Identity Protocol
    IPSECKEY,   //	45	RFC 4025	IPsec Key
    KEY,        //	25	RFC 2535[3] and RFC 2930[4]	Key record
    KX,         //	36	RFC 2230	Key eXchanger record
    LOC,        //	29	RFC 1876	Location record
    MX,         //	15	RFC 1035[1]	Mail exchange record
    NAPTR,      //	35	RFC 3403	Naming Authority Pointer
    NS,         //	2	RFC 1035[1]	Name server record
    NSEC,       //	47	RFC 4034	Next-Secure record
    NSEC3,      //	50	RFC 5155	NSEC record version 3
    NSEC3PARAM, //	51	RFC 5155	NSEC3 parameters
    PTR,        //	12	RFC 1035[1]	Pointer record
    RRSIG,      //	46	RFC 4034	DNSSEC signature
    RP,         //	17	RFC 1183	Responsible person
    SIG,        //	24	RFC 2535	Signature
    SOA,        //	6	RFC 1035[1] and RFC 2308[9]	Start of [a zone of] authority record
    SRV,        //	33	RFC 2782	Service locator
    SSHFP,      //	44	RFC 4255	SSH Public Key Fingerprint
    TA,         //	32768	N/A	DNSSEC Trust Authorities
    TKEY,       //	249	RFC 2930	Secret key record
    TLSA,       //	52	RFC 6698	TLSA certificate association
    TSIG,       //	250	RFC 2845	Transaction Signature
    TXT,        //	16	RFC 1035[1]	Text record
    ANY,        //  *	255	RFC 1035[1]	All cached records, aka ANY
    AXFR,       //	252	RFC 1035[1]	Authoritative Zone Transfer
    IXFR,       //	251	RFC 1996	Incremental Zone Transfer
    OPT,        //	41	RFC 6891	Option
}


// TODO make these a macro...


/// Convert from RecordType to String
///
/// ```
/// assert_eq!("A", A.into());
/// ```
pub impl From<RecordType> for String {
  fn from(self) -> Self {
    match self {
      A => "A",
      AAAA => "AAAA",
      CNAME => "CNAME",
      NS => "NS",
      SOA => "SOA",
      _ => unimplemented!(),
    }
  }
}

pub impl From<String> for RecordType {
  fn from(self) -> Self {
    match self.as_slice() {
      "A" => A,
      "AAAA" => AAAA,
      "CNAME" => CNAME,
      "NS" => NS,
      "SOA" => SOA,
      _ => unimplemented!(),
    }
  }
}

pub impl From<RecordType> for i32 {
  fn from(self) -> Self {
    match self {
      A => 1,
      AAAA => 28,
      CNAME => 5,
      NS => 2,
      SOA => 6,
      _ => unimplemented!(),
    }
  }
}

pub impl From<i32> for RecordType {
  fn from(self) -> Self {
    1 => A,
    28 => AAAA,
    5 => CNAME,
    2 => NS,
    6 => SOA,
    _ => unimplemented!(),
  }
}
