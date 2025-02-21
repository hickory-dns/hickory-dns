/*
 * Copyright (C) 2024 Brian Taber <btaber@zsd.systems>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! cert records for storing certificate data

use crate::rr::rdata::CERT;
use crate::rr::rdata::cert::{Algorithm, CertType};
use crate::serialize::txt::errors::{ParseError, ParseErrorKind, ParseResult};

fn to_u16(data: &str) -> ParseResult<u16> {
    data.parse().map_err(ParseError::from)
}

fn to_u8(data: &str) -> ParseResult<u8> {
    data.parse().map_err(ParseError::from)
}

/// Parse the RData from a set of Tokens
pub(crate) fn parse<'i, I: Iterator<Item = &'i str>>(tokens: I) -> ParseResult<CERT> {
    let mut iter = tokens;

    let token = iter
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::Message("CERT cert type field missing")))?;
    let cert_type = CertType::from(to_u16(token).map_err(|_| {
        ParseError::from(ParseErrorKind::Message(
            "Invalid digit found in cert_type token",
        ))
    })?);

    let token = iter
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::Message("CERT key tag field missing")))?;
    let key_tag = to_u16(token).map_err(|_| {
        ParseError::from(ParseErrorKind::Message(
            "Invalid digit found in key_tag token",
        ))
    })?;

    let token = iter
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::Message("CERT algorithm field missing")))?;
    let algorithm = Algorithm::from(to_u8(token).map_err(|_| {
        ParseError::from(ParseErrorKind::Message(
            "Invalid digit found in algorithm token",
        ))
    })?);

    let token = iter
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::Message("CERT data missing")))?;

    let cert_data = data_encoding::BASE64
        .decode(token.as_bytes())
        .map_err(|_| ParseError::from(ParseErrorKind::Message("Invalid base64 CERT data")))?;

    Ok(CERT::new(cert_type, key_tag, algorithm, cert_data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_cert_data() {
        // Base64-encoded dummy certificate data.
        let tokens = vec!["1", "123", "3", "Q2VydGlmaWNhdGUgZGF0YQ=="].into_iter();

        let result = parse(tokens);

        assert!(result.is_ok());

        let cert = result.unwrap();
        assert_eq!(cert.cert_type(), CertType::from(1));
        assert_eq!(cert.key_tag(), 123);
        assert_eq!(cert.algorithm(), Algorithm::from(3));
        assert_eq!(cert.cert_data(), b"Certificate data".to_vec()); // Decoded base64 data.
    }

    #[test]
    fn test_invalid_base64_data() {
        // Invalid base64 data (contains invalid characters).
        let tokens = vec!["1", "123", "3", "Invalid_base64"].into_iter();

        let result = parse(tokens);

        // Expecting an error for invalid base64 data.
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(format!("{}", err), "Invalid base64 CERT data");
    }

    #[test]
    fn test_invalid_token_digit() {
        // Missing cert_type (first token) will try to decode cert leading to invalid digit
        let tokens = vec!["123", "3", "Q2VydGlmaWNhdGUgZGF0YQ=="].into_iter();

        let result = parse(tokens);

        // Expecting an error due to missing cert type.
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(format!("{}", err), "Invalid digit found in algorithm token");
    }

    #[test]
    fn test_missing_cert_data() {
        // Missing cert_data (last token)
        let tokens = vec!["1", "123", "3"].into_iter();

        let result = parse(tokens);

        // Expecting an error due to missing cert data.
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(format!("{}", err), "CERT data missing");
    }
}
