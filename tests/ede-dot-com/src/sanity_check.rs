use std::env;

use dns_test::Result;

// control subdomain; authentic data is expected
#[test]
fn valid() -> Result<()> {
    let response = crate::compare("valid")?;

    dbg!(&response);

    assert!(response.status.is_noerror());
    assert!(response.flags.authenticated_data);

    Ok(())
}

#[test]
fn hermetic_valid() -> Result<()> {
    let response = crate::hermetic_compare("valid")?;

    dbg!(&response);

    assert!(response.status.is_noerror());
    assert!(response.flags.authenticated_data);

    Ok(())
}

#[test]
fn dns_test_vars_are_not_set() {
    for var in ["DNS_TEST_SUBJECT", "DNS_TEST_PEER"] {
        assert!(
            env::var_os(var).is_none(),
            "the environment variable {} must not be set when running this test suite",
            var
        )
    }
}
