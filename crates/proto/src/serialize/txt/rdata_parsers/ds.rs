//! Parser for DS text form

use alloc::string::String;
use alloc::vec::Vec;
use core::str::FromStr;

use crate::dnssec::rdata::ds::DS;
use crate::dnssec::{Algorithm, DigestType};
use crate::serialize::txt::errors::{ParseError, ParseErrorKind, ParseResult};

/// Parse the RData from a set of Tokens
///
/// [RFC 4034, Resource Records for the DNS Security Extensions](https://datatracker.ietf.org/doc/html/rfc4034#section-5.3)
/// ```text
/// 5.3.  The DS RR Presentation Format
///
///    The presentation format of the RDATA portion is as follows:
///
///    The Key Tag field MUST be represented as an unsigned decimal integer.
///
///    The Algorithm field MUST be represented either as an unsigned decimal
///    integer or as an algorithm mnemonic specified in Appendix A.1.
///
///    The Digest Type field MUST be represented as an unsigned decimal
///    integer.
///
///    The Digest MUST be represented as a sequence of case-insensitive
///    hexadecimal digits.  Whitespace is allowed within the hexadecimal
///    text.
/// ```
#[allow(deprecated)]
pub(crate) fn parse<'i, I: Iterator<Item = &'i str>>(mut tokens: I) -> ParseResult<DS> {
    let tag_str: &str = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::Message("key tag not present")))?;
    let algorithm_str: &str = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::Message("algorithm not present")))?;
    let digest_type_str: &str = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::Message("digest type not present")))?;
    let tag: u16 = tag_str.parse()?;
    let algorithm = match algorithm_str {
        // Mnemonics from Appendix A.1.
        "RSAMD5" => Algorithm::Unknown(1),
        "DH" => Algorithm::Unknown(2),
        "DSA" => Algorithm::Unknown(3),
        "ECC" => Algorithm::Unknown(4),
        "RSASHA1" => Algorithm::RSASHA1,
        "INDIRECT" => Algorithm::Unknown(252),
        "PRIVATEDNS" => Algorithm::Unknown(253),
        "PRIVATEOID" => Algorithm::Unknown(254),
        _ => Algorithm::from_u8(algorithm_str.parse()?),
    };
    let digest_type = DigestType::from(u8::from_str(digest_type_str)?);
    let digest_str: String = tokens.collect();
    if digest_str.is_empty() {
        return Err(ParseError::from(ParseErrorKind::Message(
            "digest not present",
        )));
    }
    let mut digest = Vec::with_capacity(digest_str.len() / 2);
    let mut s = digest_str.as_str();
    while s.len() >= 2 {
        if !s.is_char_boundary(2) {
            return Err(ParseError::from(ParseErrorKind::Message(
                "digest contains non hexadecimal text",
            )));
        }
        let (byte_str, rest) = s.split_at(2);
        s = rest;
        let byte = u8::from_str_radix(byte_str, 16)?;
        digest.push(byte);
    }
    Ok(DS::new(tag, algorithm, digest_type, digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn test_parsing() {
        assert_eq!(
            parse("60485 5 1 2BB183AF5F22588179A53B0A 98631FAD1A292118".split(' ')).unwrap(),
            DS::new(
                60485,
                Algorithm::RSASHA1,
                DigestType::SHA1,
                vec![
                    0x2B, 0xB1, 0x83, 0xAF, 0x5F, 0x22, 0x58, 0x81, 0x79, 0xA5, 0x3B, 0x0A, 0x98,
                    0x63, 0x1F, 0xAD, 0x1A, 0x29, 0x21, 0x18
                ]
            )
        );
    }
}
