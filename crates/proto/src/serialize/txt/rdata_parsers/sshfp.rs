// Copyright 2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! SSHFP records for SSH public key fingerprints

#[cfg(test)]
use alloc::vec::Vec;

use crate::rr::rdata::{SSHFP, sshfp};
use crate::serialize::txt::errors::{ParseError, ParseErrorKind, ParseResult};

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
pub(crate) fn parse<'i, I: Iterator<Item = &'i str>>(mut tokens: I) -> ParseResult<SSHFP> {
    fn missing_field<E: From<ParseErrorKind>>(field: &str) -> E {
        ParseErrorKind::Msg(format!("SSHFP {field} field missing")).into()
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
    let fingerprint = sshfp::HEX.decode(
        tokens
            .next()
            .filter(|fp| !fp.is_empty())
            .ok_or_else(|| missing_field::<ParseError>("fingerprint"))?
            .as_bytes(),
    )?;
    Some(SSHFP::new(algorithm, fingerprint_type, fingerprint))
        .filter(|_| tokens.next().is_none())
        .ok_or_else(|| ParseErrorKind::Message("too many fields for SSHFP").into())
}

#[test]
fn test_parsing() {
    assert!(parse(core::iter::empty()).is_err());
    assert!(parse(vec!["51", "13"].into_iter()).is_err());
    assert!(parse(vec!["1", "-1"].into_iter()).is_err());
    assert!(parse(vec!["1", "1", "abcd", "foo"].into_iter()).is_err());

    use crate::rr::rdata::sshfp::Algorithm::*;
    use crate::rr::rdata::sshfp::FingerprintType::*;
    use crate::rr::rdata::sshfp::{Algorithm, FingerprintType};

    fn test_parsing(input: Vec<&str>, a: Algorithm, ft: FingerprintType, f: &[u8]) {
        assert!(
            parse(input.into_iter())
                .map(|rd| rd == SSHFP::new(a, ft, f.to_vec()))
                .unwrap_or(false)
        );
    }

    test_parsing(
        vec!["1", "1", "dd465c09cfa51fb45020cc83316fff21b9ec74ac"],
        RSA,
        SHA1,
        &[
            221, 70, 92, 9, 207, 165, 31, 180, 80, 32, 204, 131, 49, 111, 255, 33, 185, 236, 116,
            172,
        ],
    );
    test_parsing(
        vec![
            "1",
            "2",
            "b049f950d1397b8fee6a61e4d14a9acdc4721e084eff5460bbed80cfaa2ce2cb",
        ],
        RSA,
        SHA256,
        &[
            176, 73, 249, 80, 209, 57, 123, 143, 238, 106, 97, 228, 209, 74, 154, 205, 196, 114,
            30, 8, 78, 255, 84, 96, 187, 237, 128, 207, 170, 44, 226, 203,
        ],
    );
    test_parsing(
        vec!["2", "1", "3b6ba6110f5ffcd29469fc1ec2ee25d61718badd"],
        DSA,
        SHA1,
        &[
            59, 107, 166, 17, 15, 95, 252, 210, 148, 105, 252, 30, 194, 238, 37, 214, 23, 24, 186,
            221,
        ],
    );
    test_parsing(
        vec![
            "2",
            "2",
            "f9b8a6a460639306f1b38910456a6ae1018a253c47ecec12db77d7a0878b4d83",
        ],
        DSA,
        SHA256,
        &[
            249, 184, 166, 164, 96, 99, 147, 6, 241, 179, 137, 16, 69, 106, 106, 225, 1, 138, 37,
            60, 71, 236, 236, 18, 219, 119, 215, 160, 135, 139, 77, 131,
        ],
    );
    test_parsing(
        vec!["3", "1", "c64607a28c5300fec1180b6e417b922943cffcdd"],
        ECDSA,
        SHA1,
        &[
            198, 70, 7, 162, 140, 83, 0, 254, 193, 24, 11, 110, 65, 123, 146, 41, 67, 207, 252, 221,
        ],
    );
    test_parsing(
        vec![
            "3",
            "2",
            "821eb6c1c98d9cc827ab7f456304c0f14785b7008d9e8646a8519de80849afc7",
        ],
        ECDSA,
        SHA256,
        &[
            130, 30, 182, 193, 201, 141, 156, 200, 39, 171, 127, 69, 99, 4, 192, 241, 71, 133, 183,
            0, 141, 158, 134, 70, 168, 81, 157, 232, 8, 73, 175, 199,
        ],
    );
    test_parsing(
        vec!["4", "1", "6b6f6165636874657266696e6765727072696e74"],
        Ed25519,
        SHA1,
        &[
            107, 111, 97, 101, 99, 104, 116, 101, 114, 102, 105, 110, 103, 101, 114, 112, 114, 105,
            110, 116,
        ],
    );
    test_parsing(
        vec![
            "4",
            "2",
            "a87f1b687ac0e57d2a081a2f282672334d90ed316d2b818ca9580ea384d92401",
        ],
        Ed25519,
        SHA256,
        &[
            168, 127, 27, 104, 122, 192, 229, 125, 42, 8, 26, 47, 40, 38, 114, 51, 77, 144, 237,
            49, 109, 43, 129, 140, 169, 88, 14, 163, 132, 217, 36, 1,
        ],
    );
}
