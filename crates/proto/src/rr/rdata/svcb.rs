// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! SSHFP records for SSH public key fingerprints
use std::cmp::{Ord, Ordering, PartialOrd};
use std::fmt;

use crate::error::*;
use crate::rr::Name;
use crate::serialize::binary::*;

///  [draft-ietf-dnsop-svcb-https-03 SVCB and HTTPS RRs for DNS, February 2021](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-03#section-2.2)
///
/// ```text
/// 2.2.  RDATA wire format
///
///   The RDATA for the SVCB RR consists of:
///
///   *  a 2 octet field for SvcPriority as an integer in network byte
///      order.
///   *  the uncompressed, fully-qualified TargetName, represented as a
///      sequence of length-prefixed labels as in Section 3.1 of [RFC1035].
///   *  the SvcParams, consuming the remainder of the record (so smaller
///      than 65535 octets and constrained by the RDATA and DNS message
///      sizes).
///
///   When the list of SvcParams is non-empty (ServiceMode), it contains a
///   series of SvcParamKey=SvcParamValue pairs, represented as:
///
///   *  a 2 octet field containing the SvcParamKey as an integer in
///      network byte order.  (See Section 14.3.2 for the defined values.)
///   *  a 2 octet field containing the length of the SvcParamValue as an
///      integer between 0 and 65535 in network byte order (but constrained
///      by the RDATA and DNS message sizes).
///   *  an octet string of this length whose contents are in a format
///      determined by the SvcParamKey.
///
///   SvcParamKeys SHALL appear in increasing numeric order.
///
///   Clients MUST consider an RR malformed if:
///
///   *  the end of the RDATA occurs within a SvcParam.
///   *  SvcParamKeys are not in strictly increasing numeric order.
///   *  the SvcParamValue for an SvcParamKey does not have the expected
///      format.
///
///   Note that the second condition implies that there are no duplicate
///   SvcParamKeys.
///
///   If any RRs are malformed, the client MUST reject the entire RRSet and
///   fall back to non-SVCB connection establishment.
/// ```
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SVCB {
    svc_priority: u16,
    target_name: Name,
    svc_params: Vec<(SvcParamKey, SvcParamValue)>,
}

impl SVCB {
    /// Create a new SVCB record from parts
    ///
    /// It is up to the caller to validate the data going into the record
    pub fn new(
        svc_priority: u16,
        target_name: Name,
        svc_params: Vec<(SvcParamKey, SvcParamValue)>,
    ) -> Self {
        Self {
            svc_priority,
            target_name,
            svc_params,
        }
    }
}

/// ```text
/// 14.3.2.  Initial contents
///
///   The "Service Binding (SVCB) Parameter Registry" shall initially be
///   populated with the registrations below:
///
///   +=============+=================+======================+===========+
///   | Number      | Name            | Meaning              | Reference |
///   +=============+=================+======================+===========+
///   | 0           | mandatory       | Mandatory keys in    | (This     |
///   |             |                 | this RR              | document) |
///   +-------------+-----------------+----------------------+-----------+
///   | 1           | alpn            | Additional supported | (This     |
///   |             |                 | protocols            | document) |
///   +-------------+-----------------+----------------------+-----------+
///   | 2           | no-default-alpn | No support for       | (This     |
///   |             |                 | default protocol     | document) |
///   +-------------+-----------------+----------------------+-----------+
///   | 3           | port            | Port for alternative | (This     |
///   |             |                 | endpoint             | document) |
///   +-------------+-----------------+----------------------+-----------+
///   | 4           | ipv4hint        | IPv4 address hints   | (This     |
///   |             |                 |                      | document) |
///   +-------------+-----------------+----------------------+-----------+
///   | 5           | echconfig       | Encrypted            | (This     |
///   |             |                 | ClientHello info     | document) |
///   +-------------+-----------------+----------------------+-----------+
///   | 6           | ipv6hint        | IPv6 address hints   | (This     |
///   |             |                 |                      | document) |
///   +-------------+-----------------+----------------------+-----------+
///   | 65280-65534 | keyNNNNN        | Private Use          | (This     |
///   |             |                 |                      | document) |
///   +-------------+-----------------+----------------------+-----------+
///   | 65535       | key65535        | Reserved ("Invalid   | (This     |
///   |             |                 | key")                | document) |
///   +-------------+-----------------+----------------------+-----------+
///
/// parsing done via:
///   *  a 2 octet field containing the SvcParamKey as an integer in
///      network byte order.  (See Section 14.3.2 for the defined values.)
/// ```
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum SvcParamKey {
    /// Mandatory keys in this RR
    Mandatory,
    /// Additional supported protocols
    Alpn,
    /// No support for default protocol
    NoDefaultAlpn,
    /// Port for alternative endpoint
    Port,
    /// IPv4 address hints
    Ipv4Hint,
    /// Encrypted ClientHello info
    EchConfig,
    /// IPv6 address hints
    Ipv6Hint,
    /// Private Use
    Key(u16),
    /// Reserved ("Invalid key")
    Key65535,
    /// Unknown
    Unknown(u16),
}

impl From<u16> for SvcParamKey {
    fn from(val: u16) -> Self {
        match val {
            0 => SvcParamKey::Mandatory,
            1 => SvcParamKey::Alpn,
            2 => SvcParamKey::NoDefaultAlpn,
            3 => SvcParamKey::Port,
            4 => SvcParamKey::Ipv4Hint,
            5 => SvcParamKey::EchConfig,
            6 => SvcParamKey::Ipv6Hint,
            65280..=65534 => SvcParamKey::Key(val),
            65535 => SvcParamKey::Key65535,
            _ => SvcParamKey::Unknown(val),
        }
    }
}

impl From<SvcParamKey> for u16 {
    fn from(val: SvcParamKey) -> Self {
        match val {
            SvcParamKey::Mandatory => 0,
            SvcParamKey::Alpn => 1,
            SvcParamKey::NoDefaultAlpn => 2,
            SvcParamKey::Port => 3,
            SvcParamKey::Ipv4Hint => 4,
            SvcParamKey::EchConfig => 5,
            SvcParamKey::Ipv6Hint => 6,
            SvcParamKey::Key(val) => val,
            SvcParamKey::Key65535 => 65535,
            SvcParamKey::Unknown(val) => val,
        }
    }
}

impl fmt::Display for SvcParamKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let mut write_key = |name| write!(f, "{}", name);

        match *self {
            SvcParamKey::Mandatory => write_key("mandatory")?,
            SvcParamKey::Alpn => write_key("alpn")?,
            SvcParamKey::NoDefaultAlpn => write_key("no-default-alpn")?,
            SvcParamKey::Port => write_key("port")?,
            SvcParamKey::Ipv4Hint => write_key("ipv4hint")?,
            SvcParamKey::EchConfig => write_key("echconfig")?,
            SvcParamKey::Ipv6Hint => write_key("ipv6hint")?,
            SvcParamKey::Key(val) => write!(f, "key{}", val)?,
            SvcParamKey::Key65535 => write_key("key65535")?,
            SvcParamKey::Unknown(val) => write!(f, "unknown{}", val)?,
        }

        Ok(())
    }
}

impl Ord for SvcParamKey {
    fn cmp(&self, other: &Self) -> Ordering {
        u16::from(*self).cmp(&u16::from(*other))
    }
}

impl PartialOrd for SvcParamKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Warning, it is currently up to users of this type to validate the data against that expected by the key
///
/// ```text
///   *  a 2 octet field containing the length of the SvcParamValue as an
///      integer between 0 and 65535 in network byte order (but constrained
///      by the RDATA and DNS message sizes).
///   *  an octet string of this length whose contents are in a format
///      determined by the SvcParamKey.
/// ```
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[repr(transparent)]
pub struct SvcParamValue(Vec<u8>);

impl SvcParamValue {
    /// Return the inner data as a slice of bytes
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for SvcParamValue {
    fn from(val: Vec<u8>) -> Self {
        Self(val)
    }
}

impl From<SvcParamValue> for Vec<u8> {
    fn from(val: SvcParamValue) -> Self {
        val.0
    }
}

/// Reads the SVCB record from the decoder.
///
/// ```text
///   Clients MUST consider an RR malformed if:
///
///   *  the end of the RDATA occurs within a SvcParam.
///   *  SvcParamKeys are not in strictly increasing numeric order.
///   *  the SvcParamValue for an SvcParamKey does not have the expected
///      format.
///
///   Note that the second condition implies that there are no duplicate
///   SvcParamKeys.
///
///   If any RRs are malformed, the client MUST reject the entire RRSet and
///   fall back to non-SVCB connection establishment.
/// ```
pub fn read(decoder: &mut BinDecoder<'_>, rdata_length: Restrict<u16>) -> ProtoResult<SVCB> {
    let start_index = decoder.index();

    let svc_priority = decoder.read_u16()?.unverified(/*any u16 is valid*/);
    let target_name = Name::read(decoder)?;

    let mut remainder_len = rdata_length.map(|len| len as usize - (decoder.index() - start_index)).unverified(/*valid len*/);
    let mut svc_params: Vec<(SvcParamKey, SvcParamValue)> = Vec::new();

    // must have at least 4 bytes left for the key and the length
    while remainder_len >= 4 {
        // a 2 octet field containing the SvcParamKey as an integer in
        //      network byte order.  (See Section 14.3.2 for the defined values.)
        let key: SvcParamKey = decoder.read_u16()?.unverified(/*any u16 is valid*/).into();

        // a 2 octet field containing the length of the SvcParamValue as an
        //      integer between 0 and 65535 in network byte order (but constrained
        //      by the RDATA and DNS message sizes).
        let len: u16 = decoder
            .read_u16()?
            .verify_unwrap(|len| *len as usize <= remainder_len)
            .map_err(|u| {
                ProtoError::from(format!(
                    "length of SvcParamValue ({}) exceeds remainder in RDATA ({})",
                    u, remainder_len
                ))
            })?;

        // an octet string of this length whose contents are in a format
        //      determined by the SvcParamKey.
        let value = decoder.read_vec(len as usize)?.unverified(/*char data for users*/);

        if let Some(last_key) = svc_params.last().map(|(key, _)| key) {
            if last_key >= &key {
                return Err(ProtoError::from("SvcParams out of order"));
            }
        }

        svc_params.push((key, value.into()));
        remainder_len = rdata_length.map(|len| len as usize - (decoder.index() - start_index)).unverified(/*valid len*/);
    }

    Ok(SVCB {
        svc_priority,
        target_name,
        svc_params,
    })
}

/// Write the RData from the given Decoder
pub fn emit(encoder: &mut BinEncoder<'_>, svcb: &SVCB) -> ProtoResult<()> {
    svcb.svc_priority.emit(encoder)?;
    svcb.target_name.emit(encoder)?;

    let mut last_key: Option<SvcParamKey> = None;
    for (key, param) in svcb.svc_params.iter() {
        if let Some(last_key) = last_key {
            if key <= &last_key {
                return Err(ProtoError::from("SvcParams out of order"));
            }
        }

        if param.as_slice().len() > u16::MAX as usize {
            return Err(ProtoError::from("SvcParams exceeds u16 max size"));
        }

        encoder.emit_u16((*key).into())?;
        encoder.emit_u16(param.as_slice().len() as u16)?;
        encoder.emit_vec(param.as_slice())?;

        last_key = Some(*key);
    }

    Ok(())
}

/// [draft-ietf-dnsop-svcb-https-03 SVCB and HTTPS RRs for DNS, February 2021](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-03#section-10.3)
///
/// ```text
/// simple.example. 7200 IN HTTPS 1 . alpn=h3
/// pool  7200 IN HTTPS 1 h3pool alpn=h2,h3 echconfig="123..."
///               HTTPS 2 .      alpn=h2 echconfig="abc..."
/// @     7200 IN HTTPS 0 www
/// _8765._baz.api.example.com. 7200 IN SVCB 0 svc4-baz.example.net.
/// ```
impl fmt::Display for SVCB {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{svc_priority} {target_name}",
            svc_priority = self.svc_priority,
            target_name = self.target_name,
        )?;

        for (key, param) in self.svc_params.iter() {
            let param = String::from_utf8_lossy(param.as_slice());
            write!(f, " {key}=\"{param}\"", key = key, param = param)?
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_svcb_key() {
        assert_eq!(SvcParamKey::Mandatory, 0.into());
        assert_eq!(SvcParamKey::Alpn, 1.into());
        assert_eq!(SvcParamKey::NoDefaultAlpn, 2.into());
        assert_eq!(SvcParamKey::Port, 3.into());
        assert_eq!(SvcParamKey::Ipv4Hint, 4.into());
        assert_eq!(SvcParamKey::EchConfig, 5.into());
        assert_eq!(SvcParamKey::Ipv6Hint, 6.into());
        assert_eq!(SvcParamKey::Key(65280), 65280.into());
        assert_eq!(SvcParamKey::Key(65534), 65534.into());
        assert_eq!(SvcParamKey::Key65535, 65535.into());
        assert_eq!(SvcParamKey::Unknown(65279), 65279.into());
    }

    #[test]
    fn read_svcb_key_to_u16() {
        assert_eq!(u16::from(SvcParamKey::Mandatory), 0);
        assert_eq!(u16::from(SvcParamKey::Alpn), 1);
        assert_eq!(u16::from(SvcParamKey::NoDefaultAlpn), 2);
        assert_eq!(u16::from(SvcParamKey::Port), 3);
        assert_eq!(u16::from(SvcParamKey::Ipv4Hint), 4);
        assert_eq!(u16::from(SvcParamKey::EchConfig), 5);
        assert_eq!(u16::from(SvcParamKey::Ipv6Hint), 6);
        assert_eq!(u16::from(SvcParamKey::Key(65280)), 65280);
        assert_eq!(u16::from(SvcParamKey::Key(65534)), 65534);
        assert_eq!(u16::from(SvcParamKey::Key65535), 65535);
        assert_eq!(u16::from(SvcParamKey::Unknown(65279)), 65279);
    }

    #[track_caller]
    fn test_encode_decode(rdata: SVCB) {
        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        emit(&mut encoder, &rdata).expect("failed to emit SVCB");
        let bytes = encoder.into_bytes();

        println!("svcb: {}", rdata);
        println!("bytes: {:?}", bytes);

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let read_rdata =
            read(&mut decoder, Restrict::new(bytes.len() as u16)).expect("failed to read back");
        assert_eq!(rdata, read_rdata);
    }

    #[test]
    fn test_encode_decode_svcb() {
        test_encode_decode(SVCB::new(
            0,
            Name::from_utf8("www.example.com.").unwrap(),
            vec![],
        ));
        test_encode_decode(SVCB::new(
            0,
            Name::from_utf8(".").unwrap(),
            vec![(SvcParamKey::Alpn, "h2".as_bytes().to_vec().into())],
        ));
        test_encode_decode(SVCB::new(
            0,
            Name::from_utf8("example.com.").unwrap(),
            vec![
                (SvcParamKey::Mandatory, "alpn".as_bytes().to_vec().into()),
                (SvcParamKey::Alpn, "h2".as_bytes().to_vec().into()),
            ],
        ));
    }

    #[test]
    #[should_panic]
    fn test_encode_decode_svcb_bad_order() {
        test_encode_decode(SVCB::new(
            0,
            Name::from_utf8(".").unwrap(),
            vec![
                (SvcParamKey::Alpn, "h2".as_bytes().to_vec().into()),
                (SvcParamKey::Mandatory, "alpn".as_bytes().to_vec().into()),
            ],
        ));
    }
}
