// TODO license

//! SSHFP records for SSH public key fingerprints

use error::*;
use rr::rdata::SSHFP;

const HEX: ::data_encoding::Encoding = new_encoding! {
    symbols: "0123456789abcdef",
    ignore: " \t\r\n",
    translate_from: "ABCDEF",
    translate_to: "abcdef",
};

/// Parse the RData from a set of Tokens
///
/// [RFC 4255](https://tools.ietf.org/html/rfc4255#section-3.2)
///
/// ```text
/// 3.2.  Presentation Format of the SSHFP RR
///
///    The RDATA of the presentation format of the SSHFP resource record
///    consists of two numbers (algorithm and fingerprint type) followed by
///    the fingerprint itself, presented in hex, e.g.:
///
///        host.example.  SSHFP 2 1 123456789abcdef67890123456789abcdef67890
///
///    The use of mnemonics instead of numbers is not allowed.
/// ```
pub fn parse<'i, I: Iterator<Item = &'i str>>(mut tokens: I) -> ParseResult<SSHFP> {
    fn missing_field<E: From<ParseErrorKind>>(field: &str) -> E {
        ParseErrorKind::Msg(format!("SSHFP {} field missing", field)).into()
    }
    let (algorithm, fingerprint_type) = {
        let mut parse_u8 = |field: &str| {
            tokens
                .next()
                .ok_or_else(|| missing_field(field))
                .and_then(|t| t.parse::<u8>().map_err(ParseError::from))
        };
        (
            parse_u8("algorithm")?.into(),
            parse_u8("fingerprint type")?.into(),
        )
    };
    let fingerprint = HEX.decode(
        Some(tokens.collect::<String>())
            .filter(|fp| !fp.is_empty())
            .ok_or_else(|| missing_field::<ParseError>("fingerprint"))?
            .as_bytes(),
    )?;
    Ok(SSHFP::new(algorithm, fingerprint_type, fingerprint))
}

// TODO test
