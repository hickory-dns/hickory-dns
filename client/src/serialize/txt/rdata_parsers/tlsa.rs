// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


//! tlsa records for storing TLS authentication records
use std::slice::Iter;

use data_encoding::hex;

use serialize::txt::*;
use error::*;
use rr::rdata::TLSA;
use rr::rdata::tlsa::CertUsage;

fn to_u8(token: &Token) -> ParseResult<u8> {
    if let &Token::CharData(ref data) = token {
        u8::from_str_radix(data, 10).map_err(ParseError::from)
    } else {
        Err(ParseErrorKind::Message("expected CharData").into())
    }
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
pub fn parse(tokens: &Vec<Token>) -> ParseResult<TLSA> {
    let mut iter: Iter<Token> = tokens.iter();

    let token: &Token = iter.next().ok_or_else(|| {
        ParseError::from(ParseErrorKind::Message("TLSA usage field missing"))
    })?;
    let usage = CertUsage::from(to_u8(token)?);

    let token = iter.next().ok_or_else(|| {
        ParseErrorKind::Message("TLSA selector field missing")
    })?;
    let selector = to_u8(token)?.into();

    let token = iter.next().ok_or_else(|| {
        ParseErrorKind::Message("TLSA matching field missing")
    })?;
    let matching = to_u8(token)?.into();

    if iter.clone().any(|token| *token != Token::EOL) {
        return Err(
            ParseErrorKind::Message("TLSA unexpected data in record").into(),
        );
    }
    let (cert_data, error): (Vec<u8>, Option<ParseResult<TLSA>>) = iter.take_while(|token| **token != Token::EOL).fold((Vec::new(), None), |(mut cert_data, e), token| 
            if let Token::CharData(ref data) = *token {
                // these are all in hex: "a string of hexadecimal characters"
                //   aside: personally I find it funny that the other fields are decimal, while this is hex encoded...
                match hex::decode_nopad(data.as_bytes()) {
                    Ok(bytes) => {
                        cert_data.extend(bytes);
                        (cert_data, e)
                    },
                    Err(e) => {
                        (cert_data, Some(Err(e.into())))
                    }
                }
            } else {
                panic!("programming error, only CharData expected");
            }
    );

    if let Some(e) = error {
        return e;
    }

    Ok(TLSA::new(usage, selector, matching, cert_data))
}
