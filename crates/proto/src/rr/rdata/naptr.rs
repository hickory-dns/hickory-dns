// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Dynamic Delegation Discovery System

use std::fmt;

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use crate::error::*;
use crate::rr::domain::Name;
use crate::serialize::binary::*;

/// [RFC 3403 DDDS DNS Database, October 2002](https://tools.ietf.org/html/rfc3403#section-4)
///
/// ```text
/// 4.1 Packet Format
///
///   The packet format of the NAPTR RR is given below.  The DNS type code
///   for NAPTR is 35.
///
///      The packet format for the NAPTR record is as follows
///                                       1  1  1  1  1  1
///         0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
///       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///       |                     ORDER                     |
///       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///       |                   PREFERENCE                  |
///       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///       /                     FLAGS                     /
///       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///       /                   SERVICES                    /
///       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///       /                    REGEXP                     /
///       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///       /                  REPLACEMENT                  /
///       /                                               /
///       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
///   <character-string> and <domain-name> as used here are defined in RFC
///   1035 [7].
/// ```
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct NAPTR {
    order: u16,
    preference: u16,
    flags: Box<[u8]>,
    services: Box<[u8]>,
    regexp: Box<[u8]>,
    replacement: Name,
}

impl NAPTR {
    /// Constructs a new NAPTR record
    ///
    /// # Arguments
    ///
    /// * `order` - the order in which the NAPTR records MUST be processed in order to accurately represent the ordered list of Rules.
    /// * `preference` - this field is equivalent to the Priority value in the DDDS Algorithm.
    /// * `flags` - flags to control aspects of the rewriting and interpretation of the fields in the record.  Flags are single characters from the set A-Z and 0-9.
    /// * `services` - the Service Parameters applicable to this this delegation path.
    /// * `regexp` - substitution expression that is applied to the original string held by the client in order to construct the next domain name to lookup.
    /// * `replacement` - the next domain-name to query for depending on the potential values found in the flags field.
    pub fn new(
        order: u16,
        preference: u16,
        flags: Box<[u8]>,
        services: Box<[u8]>,
        regexp: Box<[u8]>,
        replacement: Name,
    ) -> Self {
        Self {
            order,
            preference,
            flags,
            services,
            regexp,
            replacement,
        }
    }

    /// ```text
    ///   ORDER
    ///      A 16-bit unsigned integer specifying the order in which the NAPTR
    ///      records MUST be processed in order to accurately represent the
    ///      ordered list of Rules.  The ordering is from lowest to highest.
    ///      If two records have the same order value then they are considered
    ///      to be the same rule and should be selected based on the
    ///      combination of the Preference values and Services offered.
    /// ```
    pub fn order(&self) -> u16 {
        self.order
    }

    /// ```text
    ///   PREFERENCE
    ///      Although it is called "preference" in deference to DNS
    ///      terminology, this field is equivalent to the Priority value in the
    ///      DDDS Algorithm.  It is a 16-bit unsigned integer that specifies
    ///      the order in which NAPTR records with equal Order values SHOULD be
    ///      processed, low numbers being processed before high numbers.  This
    ///      is similar to the preference field in an MX record, and is used so
    ///      domain administrators can direct clients towards more capable
    ///      hosts or lighter weight protocols.  A client MAY look at records
    ///      with higher preference values if it has a good reason to do so
    ///      such as not supporting some protocol or service very well.
    ///
    ///      The important difference between Order and Preference is that once
    ///      a match is found the client MUST NOT consider records with a
    ///      different Order but they MAY process records with the same Order
    ///      but different Preferences.  The only exception to this is noted in
    ///      the second important Note in the DDDS algorithm specification
    ///      concerning allowing clients to use more complex Service
    ///      determination between steps 3 and 4 in the algorithm.  Preference
    ///      is used to give communicate a higher quality of service to rules
    ///      that are considered the same from an authority standpoint but not
    ///      from a simple load balancing standpoint.
    ///
    ///      It is important to note that DNS contains several load balancing
    ///      mechanisms and if load balancing among otherwise equal services
    ///      should be needed then methods such as SRV records or multiple A
    ///      records should be utilized to accomplish load balancing.
    /// ```
    pub fn preference(&self) -> u16 {
        self.preference
    }

    /// ```text
    ///   FLAGS
    ///      A <character-string> containing flags to control aspects of the
    ///      rewriting and interpretation of the fields in the record.  Flags
    ///      are single characters from the set A-Z and 0-9.  The case of the
    ///      alphabetic characters is not significant.  The field can be empty.
    ///
    ///      It is up to the Application specifying how it is using this
    ///      Database to define the Flags in this field.  It must define which
    ///      ones are terminal and which ones are not.
    /// ```
    pub fn flags(&self) -> &[u8] {
        &self.flags
    }

    /// ```text
    ///   SERVICES
    ///      A <character-string> that specifies the Service Parameters
    ///      applicable to this this delegation path.  It is up to the
    ///      Application Specification to specify the values found in this
    ///      field.
    /// ```
    pub fn services(&self) -> &[u8] {
        &self.services
    }

    /// ```text
    ///   REGEXP
    ///      A <character-string> containing a substitution expression that is
    ///      applied to the original string held by the client in order to
    ///      construct the next domain name to lookup.  See the DDDS Algorithm
    ///      specification for the syntax of this field.
    ///
    ///      As stated in the DDDS algorithm, The regular expressions MUST NOT
    ///      be used in a cumulative fashion, that is, they should only be
    ///      applied to the original string held by the client, never to the
    ///      domain name p  roduced by a previous NAPTR rewrite.  The latter is
    ///      tempting in some applications but experience has shown such use to
    ///      be extremely fault sensitive, very error prone, and extremely
    ///      difficult to debug.
    /// ```
    pub fn regexp(&self) -> &[u8] {
        &self.regexp
    }

    /// ```text
    ///   REPLACEMENT
    ///      A <domain-name> which is the next domain-name to query for
    ///      depending on the potential values found in the flags field.  This
    ///      field is used when the regular expression is a simple replacement
    ///      operation.  Any value in this field MUST be a fully qualified
    ///      domain-name.  Name compression is not to be used for this field.
    ///
    ///      This field and the REGEXP field together make up the Substitution
    ///      Expression in the DDDS Algorithm.  It is simply a historical
    ///      optimization specifically for DNS compression that this field
    ///      exists.  The fields are also mutually exclusive.  If a record is
    ///      returned that has values for both fields then it is considered to
    ///      be in error and SHOULD be either ignored or an error returned.
    /// ```
    pub fn replacement(&self) -> &Name {
        &self.replacement
    }
}

/// verifies that the flags are valid
pub fn verify_flags(flags: &[u8]) -> bool {
    flags
        .iter()
        .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z'))
}

/// Read the RData from the given Decoder
pub fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<NAPTR> {
    Ok(NAPTR::new(
        decoder.read_u16()?.unverified(/*any u16 is valid*/),
        decoder.read_u16()?.unverified(/*any u16 is valid*/),
        // must be 0-9a-z
        decoder
            .read_character_data()?
            .verify_unwrap(|s| verify_flags(s))
            .map_err(|_e| ProtoError::from("flags are not within range [a-zA-Z0-9]"))?
            .to_vec()
            .into_boxed_slice(),
        decoder.read_character_data()?.unverified(/*any chardata*/).to_vec().into_boxed_slice(),
        decoder.read_character_data()?.unverified(/*any chardata*/).to_vec().into_boxed_slice(),
        Name::read(decoder)?,
    ))
}

/// Declares the method for emitting this type
pub fn emit(encoder: &mut BinEncoder<'_>, naptr: &NAPTR) -> ProtoResult<()> {
    naptr.order.emit(encoder)?;
    naptr.preference.emit(encoder)?;
    encoder.emit_character_data(&naptr.flags)?;
    encoder.emit_character_data(&naptr.services)?;
    encoder.emit_character_data(&naptr.regexp)?;

    encoder.with_canonical_names(|encoder| naptr.replacement.emit(encoder))?;
    Ok(())
}

/// [RFC 2915](https://tools.ietf.org/html/rfc2915), NAPTR DNS RR, September 2000
///
/// ```text
/// Master File Format
///
///   The master file format follows the standard rules in RFC-1035 [1].
///   Order and preference, being 16-bit unsigned integers, shall be an
///   integer between 0 and 65535.  The Flags and Services and Regexp
///   fields are all quoted <character-string>s.  Since the Regexp field
///   can contain numerous backslashes and thus should be treated with
///   care.  See Section 10 for how to correctly enter and escape the
///   regular expression.
///
/// ;;      order pref flags service           regexp replacement
/// IN NAPTR 100  50  "a"    "z3950+N2L+N2C"     ""   cidserver.example.com.
/// IN NAPTR 100  50  "a"    "rcds+N2C"          ""   cidserver.example.com.
/// IN NAPTR 100  50  "s"    "http+N2L+N2C+N2R"  ""   www.example.com.
/// ```
impl fmt::Display for NAPTR {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{order} {pref} \"{flags}\" \"{service}\" \"{regexp}\" {replace}",
            order = self.order,
            pref = self.preference,
            flags = &String::from_utf8_lossy(&self.flags),
            service = &String::from_utf8_lossy(&self.services),
            regexp = &String::from_utf8_lossy(&self.regexp),
            replace = self.replacement
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

        let rdata = NAPTR::new(
            8,
            16,
            b"aa11AA".to_vec().into_boxed_slice(),
            b"services".to_vec().into_boxed_slice(),
            b"regexpr".to_vec().into_boxed_slice(),
            Name::from_str("naptr.example.com").unwrap(),
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

    #[test]
    fn test_bad_data() {
        use std::str::FromStr;

        let rdata = NAPTR::new(
            8,
            16,
            b"aa11AA-".to_vec().into_boxed_slice(),
            b"services".to_vec().into_boxed_slice(),
            b"regexpr".to_vec().into_boxed_slice(),
            Name::from_str("naptr.example.com").unwrap(),
        );

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        assert!(emit(&mut encoder, &rdata).is_ok());
        let bytes = encoder.into_bytes();

        println!("bytes: {:?}", bytes);

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let read_rdata = read(&mut decoder);
        assert!(
            read_rdata.is_err(),
            "should have failed decoding with bad flag data"
        );
    }
}
