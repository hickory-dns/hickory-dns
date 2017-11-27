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

//! mail exchange, email, record

use serialize::binary::*;
use error::*;
use rr::domain::Name;

/// [RFC 1035, DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION, November 1987](https://tools.ietf.org/html/rfc1035)
///
/// ```text
/// 3.3.9. MX RDATA format
///
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                  PREFERENCE                   |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     /                   EXCHANGE                    /
///     /                                               /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
/// MX records cause type A additional section processing for the host
/// specified by EXCHANGE.  The use of MX RRs is explained in detail in
/// [RFC-974].
///
/// ```
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct MX {
    preference: u16,
    exchange: Name,
}

impl MX {
    /// Constructs a new MX RData
    ///
    /// # Arguments
    ///
    /// * `preference` - weight of this MX record as opposed to others, lower values have the higher preference
    /// * `exchange` - Name labels for the mail server
    ///
    /// # Returns
    ///
    /// A new MX RData for use in a Resource Record
    pub fn new(preference: u16, exchange: Name) -> MX {
        MX {
            preference: preference,
            exchange: exchange,
        }
    }

    /// [RFC 1035, DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION, November 1987](https://tools.ietf.org/html/rfc1035)
    ///
    /// ```text
    /// PREFERENCE      A 16 bit integer which specifies the preference given to
    ///                 this RR among others at the same owner.  Lower values
    ///                 are preferred.
    /// ```
    pub fn preference(&self) -> u16 {
        self.preference
    }

    /// [RFC 1035, DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION, November 1987](https://tools.ietf.org/html/rfc1035)
    ///
    /// ```text
    /// EXCHANGE        A <domain-name> which specifies a host willing to act as
    ///                 a mail exchange for the owner name.
    /// ```
    pub fn exchange(&self) -> &Name {
        &self.exchange
    }
}

/// Read the RData from the given Decoder
pub fn read(decoder: &mut BinDecoder) -> ProtoResult<MX> {
    Ok(MX::new(decoder.read_u16()?, Name::read(decoder)?))
}

/// [RFC 4034](https://tools.ietf.org/html/rfc4034#section-6), DNSSEC Resource Records, March 2005
///
/// ```text
/// 6.2.  Canonical RR Form
///
///    For the purposes of DNS security, the canonical form of an RR is the
///    wire format of the RR where:
///
///    ...
///
///    3.  if the type of the RR is NS, MD, MF, CNAME, SOA, MB, MG, MR, PTR,
///        HINFO, MINFO, MX, HINFO, RP, AFSDB, RT, SIG, PX, NXT, NAPTR, KX,
///        SRV, DNAME, A6, RRSIG, or NSEC (rfc6840 removes NSEC), all uppercase
///        US-ASCII letters in the DNS names contained within the RDATA are replaced
///        by the corresponding lowercase US-ASCII letters;
/// ```
pub fn emit(encoder: &mut BinEncoder, mx: &MX) -> ProtoResult<()> {
    let is_canonical_names = encoder.is_canonical_names();
    encoder.emit_u16(mx.preference())?;
    mx.exchange()
        .emit_with_lowercase(encoder, is_canonical_names)?;
    Ok(())
}

#[test]
pub fn test() {
    let rdata = MX::new(16, Name::from_labels(vec!["mail", "example", "com"]));

    let mut bytes = Vec::new();
    let mut encoder: BinEncoder = BinEncoder::new(&mut bytes);
    assert!(emit(&mut encoder, &rdata).is_ok());
    let bytes = encoder.into_bytes();

    println!("bytes: {:?}", bytes);

    let mut decoder: BinDecoder = BinDecoder::new(bytes);
    let read_rdata = read(&mut decoder);
    assert!(
        read_rdata.is_ok(),
        format!("error decoding: {:?}", read_rdata.unwrap_err())
    );
    assert_eq!(rdata, read_rdata.unwrap());
}
