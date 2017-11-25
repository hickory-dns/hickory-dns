// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
// Copyright 2017 Google LLC.
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


//! tlsa records for storing TLS authentication records

use error::*;
use rr::rdata::TLSA;
use rr::rdata::tlsa::CertUsage;

const HEX: ::data_encoding::Encoding = new_encoding!{
    symbols: "0123456789abcdef",
    ignore: " \t\r\n",
    translate_from: "ABCDEF",
    translate_to: "abcdef",
};

fn to_u8(data: &str) -> ParseResult<u8> {
    u8::from_str_radix(data, 10).map_err(ParseError::from)
}

/// Parse the RData from a set of Tokens
///
/// [RFC 6698, DNS-Based Authentication for TLS](https://tools.ietf.org/html/rfc6698#section-2.2)
///
/// ```text
/// 2.2.  TLSA RR Presentation Format
///
///    The presentation format of the RDATA portion (as defined in
///    [RFC1035]) is as follows:
///
///    o  The certificate usage field MUST be represented as an 8-bit
///       unsigned integer.
///
///    o  The selector field MUST be represented as an 8-bit unsigned
///       integer.
///
///    o  The matching type field MUST be represented as an 8-bit unsigned
///       integer.
///
///    o  The certificate association data field MUST be represented as a
///       string of hexadecimal characters.  Whitespace is allowed within
///       the string of hexadecimal characters, as described in [RFC1035].
/// ```
pub fn parse<'i, I: Iterator<Item = &'i str>>(tokens: I) -> ParseResult<TLSA> {
    let mut iter = tokens;

    let token: &str = iter.next().ok_or_else(|| {
        ParseError::from(ParseErrorKind::Message("TLSA usage field missing"))
    })?;
    let usage = CertUsage::from(to_u8(token)?);

    let token = iter.next()
        .ok_or_else(|| ParseErrorKind::Message("TLSA selector field missing"))?;
    let selector = to_u8(token)?.into();

    let token = iter.next()
        .ok_or_else(|| ParseErrorKind::Message("TLSA matching field missing"))?;
    let matching = to_u8(token)?.into();

    // these are all in hex: "a string of hexadecimal characters"
    //   aside: personally I find it funny that the other fields are decimal, while this is hex encoded...
    let cert_data = iter.fold(String::new(), |mut cert_data, data| {
        cert_data.push_str(data);
        cert_data
    });
    println!("cert_data: {}", cert_data);
    let cert_data = HEX.decode(cert_data.as_bytes())?;

    if !cert_data.is_empty() {
        Ok(TLSA::new(usage, selector, matching, cert_data))
    } else {
        Err(ParseErrorKind::Message("TLSA data field missing").into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parsing() {
        assert!(
            parse(
                vec![
                    "0",
                    "0",
                    "1",
                    "d2abde240d7cd3ee6b4b28c54df034b9",
                    "7983a1d16e8a410e4561cb106618e971",
                ].into_iter()
            ).is_ok()
        );
        assert!(
            parse(
                vec![
                    "1",
                    "1",
                    "2",
                    "92003ba34942dc74152e2f2c408d29ec",
                    "a5a520e7f2e06bb944f4dca346baf63c",
                    "1b177615d466f6c4b71c216a50292bd5",
                    "8c9ebdd2f74e38fe51ffd48c43326cbc",
                ].into_iter()
            ).is_ok()
        );
    }
}
