#[derive(Debug, PartialEq, PartialOrd)]
#[allow(dead_code)]
pub enum ResultCode {
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

/// Convert from ResultCode to u8
///
/// ```
/// use std::convert::From;
/// use trust_dns::op::result_code::ResultCode;
///
/// let var: ResultCode = From::from(0);
/// assert_eq!(ResultCode::NoError, var);
///
/// let var: ResultCode = 0.into();
/// assert_eq!(ResultCode::NoError, var);
/// ```
impl From<ResultCode> for u8 {
  fn from(rt: ResultCode) -> Self {
    match rt {
      ResultCode::NoError   => 0,  // 0	  NoError	No Error	[RFC1035]
      ResultCode::FormErr   => 1,  // 1	  FormErr	Format Error	[RFC1035]
      ResultCode::ServFail  => 2,  // 2	  ServFail	Server Failure	[RFC1035]
      ResultCode::NXDomain  => 3,  // 3	  NXDomain	Non-Existent Domain	[RFC1035]
      ResultCode::NotImp    => 4,  // 4	  NotImp	Not Implemented	[RFC1035]
      ResultCode::Refused   => 5,  // 5	  Refused	Query Refused	[RFC1035]
      ResultCode::YXDomain  => 6,  // 6	  YXDomain	Name Exists when it should not	[RFC2136][RFC6672]
      ResultCode::YXRRSet   => 7,  // 7	  YXRRSet	RR Set Exists when it should not	[RFC2136]
      ResultCode::NXRRSet   => 8,  // 8	  NXRRSet	RR Set that should exist does not	[RFC2136]
      ResultCode::NotAuth   => 9,  // 9	  NotAuth	Server Not Authoritative for zone	[RFC2136]
      ResultCode::NotZone   => 10, // 10	NotZone	Name not contained in zone	[RFC2136]
      ResultCode::BADVERS   => 16, // 16	BADVERS	Bad OPT Version	[RFC6891]
      ResultCode::BADSIG    => 16, // 16	BADSIG	TSIG Signature Failure	[RFC2845]
      ResultCode::BADKEY    => 17, // 17	BADKEY	Key not recognized	[RFC2845]
      ResultCode::BADTIME   => 18, // 18	BADTIME	Signature out of time window	[RFC2845]
      ResultCode::BADMODE   => 19, // 19	BADMODE	Bad TKEY Mode	[RFC2930]
      ResultCode::BADNAME   => 20, // 20	BADNAME	Duplicate key name	[RFC2930]
      ResultCode::BADALG    => 21, // 21	BADALG	Algorithm not supported	[RFC2930]
      ResultCode::BADTRUNC  => 22, // 22	BADTRUNC	Bad Truncation	[RFC4635]
      ResultCode::BADCOOKIE => 23, // 23	BADCOOKIE (TEMPORARY - registered 2015-07-26, expires 2016-07-26)	Bad/missing server cookie	[draft-ietf-dnsop-cookies]
    }
  }
}

/// Convert from u8 to ResultCode
///
/// ```
/// use std::convert::From;
/// use trust_dns::op::result_code::ResultCode;
///
/// let var: u8 = From::from(ResultCode::NoError);
/// assert_eq!(0, var);
///
/// let var: u8 = ResultCode::NoError.into();
/// assert_eq!(0, var);
/// ```
impl From<u8> for ResultCode {
  fn from(value: u8) -> Self {
    match value {
      0  => ResultCode::NoError,   // 0	NoError	No Error	[RFC1035]
      1  => ResultCode::FormErr,   // 1	FormErr	Format Error	[RFC1035]
      2  => ResultCode::ServFail,  // 2	ServFail	Server Failure	[RFC1035]
      3  => ResultCode::NXDomain,  // 3	NXDomain	Non-Existent Domain	[RFC1035]
      4  => ResultCode::NotImp,    // 4	NotImp	Not Implemented	[RFC1035]
      5  => ResultCode::Refused,   // 5	Refused	Query Refused	[RFC1035]
      6  => ResultCode::YXDomain,  // 6	YXDomain	Name Exists when it should not	[RFC2136][RFC6672]
      7  => ResultCode::YXRRSet,   // 7	YXRRSet	RR Set Exists when it should not	[RFC2136]
      8  => ResultCode::NXRRSet,   // 8	NXRRSet	RR Set that should exist does not	[RFC2136]
      9  => ResultCode::NotAuth,   // 9	NotAuth	Server Not Authoritative for zone	[RFC2136]
      10 => ResultCode::NotZone,   // 10	NotZone	Name not contained in zone	[RFC2136]
      // this looks to be backwards compat for 4 bit ResultCodes.
      //16 => ResultCode::BADVERS,   // 16	BADVERS	Bad OPT Version	[RFC6891]
      16 => ResultCode::BADSIG,    // 16	BADSIG	TSIG Signature Failure	[RFC2845]
      17 => ResultCode::BADKEY,    // 17	BADKEY	Key not recognized	[RFC2845]
      18 => ResultCode::BADTIME,   // 18	BADTIME	Signature out of time window	[RFC2845]
      19 => ResultCode::BADMODE,   // 19	BADMODE	Bad TKEY Mode	[RFC2930]
      20 => ResultCode::BADNAME,   // 20	BADNAME	Duplicate key name	[RFC2930]
      21 => ResultCode::BADALG,    // 21	BADALG	Algorithm not supported	[RFC2930]
      22 => ResultCode::BADTRUNC,  // 22	BADTRUNC	Bad Truncation	[RFC4635]
      23 => ResultCode::BADCOOKIE, // 23	BADCOOKIE (TEMPORARY - registered 2015-07-26, expires 2016-07-26)	Bad/missing server cookie	[draft-ietf-dnsop-cookies]
      _ => unimplemented!(),
    }
  }
}
