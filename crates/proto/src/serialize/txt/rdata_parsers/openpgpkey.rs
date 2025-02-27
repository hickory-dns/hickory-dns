// Copyright 2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! OPENPGPKEY records for OpenPGP public keys

use crate::rr::rdata::OPENPGPKEY;
use crate::serialize::txt::errors::{ParseErrorKind, ParseResult};

/// Parse the RData from a set of tokens.
///
/// [RFC 7929](https://tools.ietf.org/html/rfc7929#section-2.3)
///
/// ```text
/// 2.3.  The OPENPGPKEY RDATA Presentation Format
///
///    The RDATA Presentation Format, as visible in Zone Files [RFC1035],
///    consists of a single OpenPGP Transferable Public Key as defined in
///    Section 11.1 of [RFC4880] encoded in base64 as defined in Section 4
///    of [RFC4648].
/// ```
pub(crate) fn parse<'i, I: Iterator<Item = &'i str>>(mut tokens: I) -> ParseResult<OPENPGPKEY> {
    let encoded_public_key = tokens.next().ok_or(ParseErrorKind::Message(
        "OPENPGPKEY public key field is missing",
    ))?;
    let public_key = data_encoding::BASE64.decode(encoded_public_key.as_bytes())?;
    Some(OPENPGPKEY::new(public_key))
        .filter(|_| tokens.next().is_none())
        .ok_or_else(|| ParseErrorKind::Message("too many fields for OPENPGPKEY").into())
}

#[test]
fn test_parsing() {
    assert!(parse(core::iter::empty()).is_err());
    assert!(parse(vec!["äöüäööüä"].into_iter()).is_err());
    assert!(parse(vec!["ZmFpbGVk", "äöüäöüö"].into_iter()).is_err());

    assert!(
        parse(vec!["dHJ1c3RfZG5zIGlzIGF3ZXNvbWU="].into_iter())
            .map(|rd| rd == OPENPGPKEY::new(b"trust_dns is awesome".to_vec()))
            .unwrap_or(false)
    );
    assert!(
        parse(vec!["c2VsZi1wcmFpc2Ugc3Rpbmtz"].into_iter())
            .map(|rd| rd == OPENPGPKEY::new(b"self-praise stinks".to_vec()))
            .unwrap_or(false)
    );
}
