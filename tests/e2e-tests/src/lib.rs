#![cfg(test)]

use std::env;

mod resolver;

#[test]
fn sanity_check() {
    for var in ["DNS_TEST_SUBJECT", "DNS_TEST_PEER"] {
        assert!(
            env::var_os(var).is_none(),
            "the environment variable {} must not be set when running this test suite",
            var
        )
    }
}
