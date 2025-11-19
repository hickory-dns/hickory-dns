use std::fs;

use test_support::subscribe;

use crate::server_harness::named_test_harness;

#[test]
fn rfc_9539_smoke_test() {
    subscribe();

    const STATE_FILE_PATH: &str = "opp_enc_state.toml";

    named_test_harness("example_recursor_opportunistic_enc.toml", |_socket_ports| {
        // Just test that the server can start up and shut down. We can't query the recursor without
        // setting up a virtual network of authoritative name servers.
    });

    // Confirm that the state file was written out.
    assert!(fs::exists(STATE_FILE_PATH).unwrap());

    // Run a second time to confirm that the state file is loaded successfully.
    named_test_harness(
        "example_recursor_opportunistic_enc.toml",
        |_socket_ports| {},
    );

    // Clean up.
    fs::remove_file(STATE_FILE_PATH).unwrap();
}
