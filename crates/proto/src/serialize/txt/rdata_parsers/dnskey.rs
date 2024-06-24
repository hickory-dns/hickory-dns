use core::str::FromStr as _;

use crate::rr::dnssec::rdata::dnskey::DNSKEY;
use crate::rr::dnssec::Algorithm;
use crate::serialize::txt::{ParseError, ParseErrorKind, ParseResult};

pub(crate) fn parse<'i>(mut tokens: impl Iterator<Item = &'i str>) -> ParseResult<DNSKEY> {
    let flags_str = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::Message("flags not present")))?;
    let protocol_str = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::Message("protocol not present")))?;
    let algorithm_str = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::Message("algorithm not present")))?;

    let flags = u16::from_str(flags_str)?;
    if ![0, 256, 257].contains(&flags) {
        return Err(ParseError::from(ParseErrorKind::Message(
            "flags field must be one of: 0, 256, 257",
        )));
    }

    let secure_entry_point = is_bit_set(flags, 0);
    let revoke = is_bit_set(flags, 7);
    let zone_key = is_bit_set(flags, 8);

    let protocol = u8::from_str(protocol_str)?;

    if protocol != 3 {
        return Err(ParseError::from(ParseErrorKind::Message(
            "protocol field must be 3",
        )));
    }

    let algorithm = Algorithm::from_u8(algorithm_str.parse()?);

    let public_key_str: String = tokens.collect();
    if public_key_str.is_empty() {
        return Err(ParseError::from(ParseErrorKind::Message(
            "public key not present",
        )));
    }

    let public_key = data_encoding::BASE64.decode(public_key_str.as_bytes())?;

    Ok(DNSKEY::new(
        zone_key,
        secure_entry_point,
        revoke,
        algorithm,
        public_key,
    ))
}

fn is_bit_set(value: u16, bit: usize) -> bool {
    let mask = 1 << bit;
    value & mask == mask
}

#[cfg(test)]
mod tests {
    use super::*;

    const DECODED: &[u8] = b"hello";
    const ENCODED: &str = "aGVsbG8=";

    #[test]
    fn accepts_real_world_data() {
        let trust_anchor = include_str!("../../../../tests/test-data/root.key");

        let mut did_parse = false;
        for line in trust_anchor.lines() {
            if line.trim_start().starts_with(';') {
                // skip comments
                continue;
            }

            // skip NAME TTL CLASS TYPE
            let parts = line.split_whitespace().skip(4);
            parse(parts).expect("could not parse");
            did_parse = true;
        }

        assert!(did_parse);
    }

    #[test]
    fn it_works() {
        let input = format!("256 3 8 {ENCODED}");
        let expected = DNSKEY::new(true, false, false, Algorithm::RSASHA256, DECODED.to_vec());
        assert_eq!(expected, parse_ok(&input),);
    }

    #[test]
    fn secure_entry_point() {
        let input = format!("257 3 8 {ENCODED}");
        let expected = DNSKEY::new(true, true, false, Algorithm::RSASHA256, DECODED.to_vec());
        assert_eq!(expected, parse_ok(&input),);
    }

    #[test]
    fn incomplete() {
        let cases = ["", "256", "256 3", "256 3 8"];
        for case in cases {
            let err = parse_err(case);
            assert!(err.to_string().contains("not present"))
        }
    }

    #[test]
    fn bad_flags() {
        let err = parse_err(&format!("2 3 8 {ENCODED}"));
        assert!(err.to_string().contains("flags field"))
    }

    #[test]
    fn bad_protocol() {
        let err = parse_err(&format!("256 0 8 {ENCODED}"));
        assert!(err.to_string().contains("protocol field"))
    }

    #[test]
    fn bad_public_key() {
        let mut input = format!("256 3 8 {ENCODED}");
        input.pop().unwrap(); // drop trailing '='
        let err = parse_err(&input);
        assert!(err.to_string().contains("data encoding error"))
    }

    fn parse_ok(input: &str) -> DNSKEY {
        parse(input.split_whitespace()).expect("parsing failed")
    }

    fn parse_err(input: &str) -> ParseError {
        parse(input.split_whitespace()).expect_err("parsing did not fail")
    }
}
