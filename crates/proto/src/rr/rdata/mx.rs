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

use std::fmt;

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use crate::error::*;
use crate::rr::domain::Name;
use crate::serialize::binary::*;

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
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
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
    pub fn new(preference: u16, exchange: Name) -> Self {
        Self {
            preference,
            exchange,
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
pub fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<MX> {
    Ok(MX::new(
        decoder.read_u16()?.unverified(/*any u16 is valid*/),
        Name::read(decoder)?,
    ))
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
pub fn emit(encoder: &mut BinEncoder<'_>, mx: &MX) -> ProtoResult<()> {
    let is_canonical_names = encoder.is_canonical_names();
    encoder.emit_u16(mx.preference())?;
    mx.exchange()
        .emit_with_lowercase(encoder, is_canonical_names)?;
    Ok(())
}

/// [RFC 1033](https://tools.ietf.org/html/rfc1033), DOMAIN OPERATIONS GUIDE, November 1987

/// ```text
///   MX (Mail Exchanger)  (See RFC-974 for more details.)
///
///           <name>   [<ttl>] [<class>]   MX   <preference>   <host>
///
///   MX records specify where mail for a domain name should be delivered.
///   There may be multiple MX records for a particular name.  The
///   preference value specifies the order a mailer should try multiple MX
///   records when delivering mail.  Zero is the highest preference.
///   Multiple records for the same name may have the same preference.
///
///   A host BAR.FOO.COM may want its mail to be delivered to the host
///   PO.FOO.COM and would then use the MX record:
///
///           BAR.FOO.COM.    MX      10      PO.FOO.COM.
///
///   A host BAZ.FOO.COM may want its mail to be delivered to one of three
///   different machines, in the following order:
///
///           BAZ.FOO.COM.    MX      10      PO1.FOO.COM.
///                           MX      20      PO2.FOO.COM.
///                           MX      30      PO3.FOO.COM.
///
///   An entire domain of hosts not connected to the Internet may want
///   their mail to go through a mail gateway that knows how to deliver
///   mail to them.  If they would like mail addressed to any host in the
///   domain FOO.COM to go through the mail gateway they might use:
///
///           FOO.COM.        MX       10     RELAY.CS.NET.
///           *.FOO.COM.      MX       20     RELAY.CS.NET.
///
///   Note that you can specify a wildcard in the MX record to match on
///   anything in FOO.COM, but that it won't match a plain FOO.COM.
impl fmt::Display for MX {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{pref} {ex}", pref = self.preference, ex = self.exchange)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;

    #[test]
    fn test() {
        use std::str::FromStr;

        let rdata = MX::new(16, Name::from_str("mail.example.com").unwrap());

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        assert!(emit(&mut encoder, &rdata).is_ok());
        let bytes = encoder.into_bytes();

        println!("bytes: {:?}", bytes);

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let read_rdata = read(&mut decoder).expect("Decoding error");
        assert_eq!(rdata, read_rdata);
    }
}
