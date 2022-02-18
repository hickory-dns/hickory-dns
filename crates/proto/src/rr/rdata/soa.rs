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

//! start of authority record defining ownership and defaults for the zone

use std::fmt;

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use crate::error::*;
use crate::rr::domain::Name;
use crate::serialize::binary::*;

/// [RFC 1035, DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION, November 1987](https://tools.ietf.org/html/rfc1035)
///
/// ```text
/// 3.3.13. SOA RDATA format
///
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     /                     MNAME                     /
///     /                                               /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     /                     RNAME                     /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    SERIAL                     |
///     |                                               |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    REFRESH                    |
///     |                                               |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                     RETRY                     |
///     |                                               |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    EXPIRE                     |
///     |                                               |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    MINIMUM                    |
///     |                                               |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
/// where:
///
/// SOA records cause no additional section processing.
///
/// All times are in units of seconds.
///
/// Most of these fields are pertinent only for name server maintenance
/// operations.  However, MINIMUM is used in all query operations that
/// retrieve RRs from a zone.  Whenever a RR is sent in a response to a
/// query, the TTL field is set to the maximum of the TTL field from the RR
/// and the MINIMUM field in the appropriate SOA.  Thus MINIMUM is a lower
/// bound on the TTL field for all RRs in a zone.  Note that this use of
/// MINIMUM should occur when the RRs are copied into the response and not
/// when the zone is loaded from a Zone File or via a zone transfer.  The
/// reason for this provison is to allow future dynamic update facilities to
/// change the SOA RR with known semantics.
/// ```
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SOA {
    mname: Name,
    rname: Name,
    serial: u32,
    refresh: i32,
    retry: i32,
    expire: i32,
    minimum: u32,
}

impl SOA {
    /// Creates a new SOA record data.
    ///
    /// # Arguments
    ///
    /// * `mname` - the name of the primary or authority for this zone.
    /// * `rname` - the name of the responsible party for this zone, e.g. an email address.
    /// * `serial` - the serial number of the zone, used for caching purposes.
    /// * `refresh` - the amount of time to wait before a zone is resynched.
    /// * `retry` - the minimum period to wait if there is a failure during refresh.
    /// * `expire` - the time until this primary is no longer authoritative for the zone.
    /// * `minimum` - no zone records should have time-to-live values less than this minimum.
    ///
    /// # Return value
    ///
    /// The newly created SOA record data.
    pub fn new(
        mname: Name,
        rname: Name,
        serial: u32,
        refresh: i32,
        retry: i32,
        expire: i32,
        minimum: u32,
    ) -> Self {
        Self {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        }
    }

    /// Increments the serial number by one
    pub fn increment_serial(&mut self) {
        self.serial += 1; // TODO: what to do on overflow?
    }

    /// ```text
    /// MNAME           The <domain-name> of the name server that was the
    ///                 original or primary source of data for this zone.
    /// ```
    ///
    /// # Return value
    ///
    /// The `domain-name` of the name server that was the original or primary source of data for
    /// this zone, i.e. the Primary Name Server.
    pub fn mname(&self) -> &Name {
        &self.mname
    }

    /// ```text
    /// RNAME           A <domain-name> which specifies the mailbox of the
    ///                 person responsible for this zone.
    /// ```
    ///
    /// # Return value
    ///
    /// A `domain-name` which specifies the mailbox of the person responsible for this zone, i.e.
    /// the responsible name.
    pub fn rname(&self) -> &Name {
        &self.rname
    }

    /// ```text
    /// SERIAL          The unsigned 32 bit version number of the original copy
    ///                 of the zone.  Zone transfers preserve this value.  This
    ///                 value wraps and should be compared using sequence space
    ///                 arithmetic.
    /// ```
    ///
    /// # Return value
    ///
    /// The unsigned 32 bit version number of the original copy of the zone. Zone transfers
    /// preserve this value. This value wraps and should be compared using sequence space arithmetic.
    pub fn serial(&self) -> u32 {
        self.serial
    }

    /// ```text
    /// REFRESH         A 32 bit time interval before the zone should be
    ///                 refreshed.
    /// ```
    ///
    /// # Return value
    ///
    /// A 32 bit time interval before the zone should be refreshed, in seconds.
    pub fn refresh(&self) -> i32 {
        self.refresh
    }

    /// ```text
    /// RETRY           A 32 bit time interval that should elapse before a
    ///                 failed refresh should be retried.
    /// ```
    ///
    /// # Return value
    ///
    /// A 32 bit time interval that should elapse before a failed refresh should be retried,
    /// in seconds.
    pub fn retry(&self) -> i32 {
        self.retry
    }

    /// ```text
    /// EXPIRE          A 32 bit time value that specifies the upper limit on
    ///                 the time interval that can elapse before the zone is no
    ///                 longer authoritative.
    /// ```
    ///
    /// # Return value
    ///
    /// A 32 bit time value that specifies the upper limit on the time interval that can elapse
    /// before the zone is no longer authoritative, in seconds
    pub fn expire(&self) -> i32 {
        self.expire
    }

    /// ```text
    /// MINIMUM         The unsigned 32 bit minimum TTL field that should be
    ///                 exported with any RR from this zone.
    /// ```
    ///
    /// # Return value
    ///
    /// The unsigned 32 bit minimum TTL field that should be exported with any RR from this zone.
    pub fn minimum(&self) -> u32 {
        self.minimum
    }
}

/// Read the RData from the given Decoder
pub fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<SOA> {
    Ok(SOA {
        mname: Name::read(decoder)?,
        rname: Name::read(decoder)?,
        serial: decoder.read_u32()?.unverified(/*any u32 is valid*/),
        refresh: decoder.read_i32()?.unverified(/*any i32 is valid*/),
        retry: decoder.read_i32()?.unverified(/*any i32 is valid*/),
        expire: decoder.read_i32()?.unverified(/*any i32 is valid*/),
        minimum: decoder.read_u32()?.unverified(/*any u32 is valid*/),
    })
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
pub fn emit(encoder: &mut BinEncoder<'_>, soa: &SOA) -> ProtoResult<()> {
    let is_canonical_names = encoder.is_canonical_names();

    soa.mname.emit_with_lowercase(encoder, is_canonical_names)?;
    soa.rname.emit_with_lowercase(encoder, is_canonical_names)?;
    encoder.emit_u32(soa.serial)?;
    encoder.emit_i32(soa.refresh)?;
    encoder.emit_i32(soa.retry)?;
    encoder.emit_i32(soa.expire)?;
    encoder.emit_u32(soa.minimum)?;
    Ok(())
}

/// [RFC 1033](https://tools.ietf.org/html/rfc1033), DOMAIN OPERATIONS GUIDE, November 1987
///
/// ```text
/// SOA  (Start Of Authority)
///
/// <name>  [<ttl>]  [<class>]  SOA  <origin>  <person>  (
///    <serial>
///    <refresh>
///    <retry>
///    <expire>
///    <minimum> )
///
/// The Start Of Authority record designates the start of a zone.  The
/// zone ends at the next SOA record.
///
/// <name> is the name of the zone.
///
/// <origin> is the name of the host on which the master zone file
/// resides.
///
/// <person> is a mailbox for the person responsible for the zone.  It is
/// formatted like a mailing address but the at-sign that normally
/// separates the user from the host name is replaced with a dot.
///
/// <serial> is the version number of the zone file.  It should be
/// incremented anytime a change is made to data in the zone.
///
/// <refresh> is how long, in seconds, a secondary name server is to
/// check with the primary name server to see if an update is needed.  A
/// good value here would be one hour (3600).
///
/// <retry> is how long, in seconds, a secondary name server is to retry
/// after a failure to check for a refresh.  A good value here would be
/// 10 minutes (600).
///
/// <expire> is the upper limit, in seconds, that a secondary name server
/// is to use the data before it expires for lack of getting a refresh.
/// You want this to be rather large, and a nice value is 3600000, about
/// 42 days.
///
/// <minimum> is the minimum number of seconds to be used for TTL values
/// in RRs.  A minimum of at least a day is a good value here (86400).
///
/// There should only be one SOA record per zone.  A sample SOA record
/// would look something like:
///
/// @   IN   SOA   SRI-NIC.ARPA.   HOSTMASTER.SRI-NIC.ARPA. (
///     45         ;serial
///     3600       ;refresh
///     600        ;retry
///     3600000    ;expire
///     86400 )    ;minimum
/// ```
impl fmt::Display for SOA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{mname} {rname} {serial} {refresh} {retry} {expire} {min}",
            mname = self.mname,
            rname = self.rname,
            serial = self.serial,
            refresh = self.refresh,
            retry = self.retry,
            expire = self.expire,
            min = self.minimum
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

        let rdata = SOA::new(
            Name::from_str("m.example.com").unwrap(),
            Name::from_str("r.example.com").unwrap(),
            1,
            2,
            3,
            4,
            5,
        );

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
