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

//! service records for identify port mapping for specific services on a host
use std::fmt;

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use crate::error::*;
use crate::rr::domain::Name;
use crate::serialize::binary::*;

/// [RFC 2782, DNS SRV RR, February 2000](https://tools.ietf.org/html/rfc2782)
///
/// ```text
/// Introductory example
///
///  If a SRV-cognizant LDAP client wants to discover a LDAP server that
///  supports TCP protocol and provides LDAP service for the domain
///  example.com., it does a lookup of
///
/// _ldap._tcp.example.com
///
///  as described in [ARM].  The example zone file near the end of this
///  memo contains answering RRs for an SRV query.
///
///  Note: LDAP is chosen as an example for illustrative purposes only,
///  and the LDAP examples used in this document should not be considered
///  a definitive statement on the recommended way for LDAP to use SRV
///  records. As described in the earlier applicability section, consult
///  the appropriate LDAP documents for the recommended procedures.
///
/// The format of the SRV RR
///
///  Here is the format of the SRV RR, whose DNS type code is 33:
///
/// _Service._Proto.Name TTL Class SRV Priority Weight Port Target
///
/// (There is an example near the end of this document.)
///
///  Service
/// The symbolic name of the desired service, as defined in Assigned
/// Numbers [STD 2] or locally.  An underscore (_) is prepended to
/// the service identifier to avoid collisions with DNS labels that
/// occur in nature.
///
/// Some widely used services, notably POP, don't have a single
/// universal name.  If Assigned Numbers names the service
/// indicated, that name is the only name which is legal for SRV
/// lookups.  The Service is case insensitive.
///
///  Proto
/// The symbolic name of the desired protocol, with an underscore
/// (_) prepended to prevent collisions with DNS labels that occur
/// in nature.  _TCP and _UDP are at present the most useful values
/// for this field, though any name defined by Assigned Numbers or
/// locally may be used (as for Service).  The Proto is case
/// insensitive.
///
///  Name
/// The domain this RR refers to.  The SRV RR is unique in that the
/// name one searches for is not this name; the example near the end
/// shows this clearly.
///
///  TTL
/// Standard DNS meaning [RFC 1035].
///
///  Class
/// Standard DNS meaning [RFC 1035].   SRV records occur in the IN
/// Class.
///
/// ```
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SRV {
    priority: u16,
    weight: u16,
    port: u16,
    target: Name,
}

impl SRV {
    /// Creates a new SRV record data.
    ///
    /// # Arguments
    ///
    /// * `priority` - lower values have a higher priority and clients will attempt to use these
    ///                first.
    /// * `weight` - for servers with the same priority, higher weights will be chosen more often.
    /// * `port` - the socket port number on which the service is listening.
    /// * `target` - like CNAME, this is the target domain name to which the service is associated.
    ///
    /// # Return value
    ///
    /// The newly constructed SRV record data.
    pub fn new(priority: u16, weight: u16, port: u16, target: Name) -> Self {
        Self {
            priority,
            weight,
            port,
            target,
        }
    }

    /// ```text
    ///  Priority
    /// The priority of this target host.  A client MUST attempt to
    /// contact the target host with the lowest-numbered priority it can
    /// reach; target hosts with the same priority SHOULD be tried in an
    /// order defined by the weight field.  The range is 0-65535.  This
    /// is a 16 bit unsigned integer in network byte order.
    /// ```
    pub fn priority(&self) -> u16 {
        self.priority
    }

    /// ```text
    ///  Weight
    /// A server selection mechanism.  The weight field specifies a
    /// relative weight for entries with the same priority. Larger
    /// weights SHOULD be given a proportionately higher probability of
    /// being selected. The range of this number is 0-65535.  This is a
    /// 16 bit unsigned integer in network byte order.  Domain
    /// administrators SHOULD use Weight 0 when there isn't any server
    /// selection to do, to make the RR easier to read for humans (less
    /// noisy).  In the presence of records containing weights greater
    /// than 0, records with weight 0 should have a very small chance of
    /// being selected.
    ///
    /// In the absence of a protocol whose specification calls for the
    /// use of other weighting information, a client arranges the SRV
    /// RRs of the same Priority in the order in which target hosts,
    /// specified by the SRV RRs, will be contacted. The following
    /// algorithm SHOULD be used to order the SRV RRs of the same
    /// priority:
    ///
    /// To select a target to be contacted next, arrange all SRV RRs
    /// (that have not been ordered yet) in any order, except that all
    /// those with weight 0 are placed at the beginning of the list.
    ///
    /// Compute the sum of the weights of those RRs, and with each RR
    /// associate the running sum in the selected order. Then choose a
    /// uniform random number between 0 and the sum computed
    /// (inclusive), and select the RR whose running sum value is the
    /// first in the selected order which is greater than or equal to
    /// the random number selected. The target host specified in the
    /// selected SRV RR is the next one to be contacted by the client.
    /// Remove this SRV RR from the set of the unordered SRV RRs and
    /// apply the described algorithm to the unordered SRV RRs to select
    /// the next target host.  Continue the ordering process until there
    /// are no unordered SRV RRs.  This process is repeated for each
    /// Priority.
    /// ```
    pub fn weight(&self) -> u16 {
        self.weight
    }

    /// ```text
    ///  Port
    /// The port on this target host of this service.  The range is 0-
    /// 65535.  This is a 16 bit unsigned integer in network byte order.
    /// This is often as specified in Assigned Numbers but need not be.
    ///
    /// ```
    pub fn port(&self) -> u16 {
        self.port
    }

    /// ```text
    ///  Target
    /// The domain name of the target host.  There MUST be one or more
    /// address records for this name, the name MUST NOT be an alias (in
    /// the sense of RFC 1034 or RFC 2181).  Implementors are urged, but
    /// not required, to return the address record(s) in the Additional
    /// Data section.  Unless and until permitted by future standards
    /// action, name compression is not to be used for this field.
    ///
    /// A Target of "." means that the service is decidedly not
    /// available at this domain.
    /// ```
    pub fn target(&self) -> &Name {
        &self.target
    }
}

/// Read the RData from the given Decoder
pub fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<SRV> {
    // SRV { priority: u16, weight: u16, port: u16, target: Name, },
    Ok(SRV::new(
        decoder.read_u16()?.unverified(/*any u16 is valid*/),
        decoder.read_u16()?.unverified(/*any u16 is valid*/),
        decoder.read_u16()?.unverified(/*any u16 is valid*/),
        Name::read(decoder)?,
    ))
}

/// [RFC 4034](https://tools.ietf.org/html/rfc4034#section-6), DNSSEC Resource Records, March 2005
///
/// This is accurate for all currently known name records.
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
///        SRV, DNAME, A6, RRSIG, or (rfc6840 removes NSEC), all uppercase
///        US-ASCII letters in the DNS names contained within the RDATA are replaced
///        by the corresponding lowercase US-ASCII letters;
/// ```
pub fn emit(encoder: &mut BinEncoder<'_>, srv: &SRV) -> ProtoResult<()> {
    let is_canonical_names = encoder.is_canonical_names();

    encoder.emit_u16(srv.priority())?;
    encoder.emit_u16(srv.weight())?;
    encoder.emit_u16(srv.port())?;
    srv.target()
        .emit_with_lowercase(encoder, is_canonical_names)?;
    Ok(())
}

/// [RFC 2782, DNS SRV RR, February 2000](https://tools.ietf.org/html/rfc2782)
///
/// ```text
/// The format of the SRV RR
///
///   Here is the format of the SRV RR, whose DNS type code is 33:
///
///   _Service._Proto.Name TTL Class SRV Priority Weight Port Target
///
///   (There is an example near the end of this document.)
/// ```
impl fmt::Display for SRV {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{priority} {weight} {port} {target}",
            priority = self.priority,
            weight = self.weight,
            port = self.port,
            target = self.target,
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;

    #[test]
    fn test() {
        use std::str::FromStr;

        let rdata = SRV::new(1, 2, 3, Name::from_str("_dns._tcp.example.com").unwrap());

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
