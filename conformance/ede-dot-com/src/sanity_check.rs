use std::env;

use dns_test::Error;

// control subdomain; authentic data is expected
#[test]
fn valid_dnssec() -> Result<(), Error> {
    let response = crate::compare("valid", true)?;

    dbg!(&response);

    assert!(response.status.is_noerror());
    assert!(response.flags.authenticated_data);

    Ok(())
}

#[test]
fn hermetic_valid_dnssec() -> Result<(), Error> {
    let response = crate::hermetic_compare("valid", true)?;

    dbg!(&response);

    assert!(response.status.is_noerror());
    assert!(response.flags.authenticated_data);

    Ok(())
}

#[test]
fn valid_no_dnssec() -> Result<(), Error> {
    let response = crate::compare("valid", false)?;

    dbg!(&response);

    assert!(response.status.is_noerror());
    assert!(!response.flags.authenticated_data);

    Ok(())
}

#[test]
fn hermetic_valid_no_dnssec() -> Result<(), Error> {
    let response = crate::hermetic_compare("valid", false)?;

    dbg!(&response);

    assert!(response.status.is_noerror());
    assert!(!response.flags.authenticated_data);

    Ok(())
}

#[test]
fn dns_test_vars_are_not_set() {
    for var in ["DNS_TEST_SUBJECT", "DNS_TEST_PEER"] {
        assert!(
            env::var_os(var).is_none(),
            "the environment variable {var} must not be set when running this test suite"
        )
    }
}
