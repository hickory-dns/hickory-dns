// TODO license

//! OPENPGPKEY records for OpenPGP public keys

use error::*;
use rr::rdata::OPENPGPKEY;

/// Parse the RData from a set of tokens.
///
/// [RFC 7929](https://tools.ietf.org/html/rfc7929#section-2.3)
///
/// ```text
/// 2.3.  The OPENPGPKEY RDATA Presentation Format
///
///    The RDATA Presentation Format, as visible in master files [RFC1035],
///    consists of a single OpenPGP Transferable Public Key as defined in
///    Section 11.1 of [RFC4880] encoded in base64 as defined in Section 4
///    of [RFC4648].
/// ```
pub fn parse<'i, I: Iterator<Item = &'i str>>(tokens: I) -> ParseResult<OPENPGPKEY> {
    data_encoding::BASE64
        .decode(tokens.collect::<String>().as_bytes())
        .map_err(Into::into)
        .and_then(|public_key| {
            Some(public_key).filter(|s| !s.is_empty()).ok_or_else(|| {
                ParseErrorKind::Message("OPENPGPKEY public key field is missing").into()
            })
        })
        .map(OPENPGPKEY::new)
}

// TODO test
