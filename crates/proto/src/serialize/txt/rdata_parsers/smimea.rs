//! SMIMEA records for storing S/MIME authentication records

use super::tlsa;
use crate::rr::rdata::SMIMEA;
use crate::serialize::txt::errors::ParseResult;

/// Parse the RData from a set of Tokens
pub(crate) fn parse<'i, I: Iterator<Item = &'i str>>(tokens: I) -> ParseResult<SMIMEA> {
    tlsa::parse_impl(tokens).map(|(usage, selector, matching, cert_data)| {
        SMIMEA::new(usage, selector, matching, cert_data)
    })
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
                ]
                .into_iter()
            )
            .is_ok()
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
                ]
                .into_iter()
            )
            .is_ok()
        );
    }
}
