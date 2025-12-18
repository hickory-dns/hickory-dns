use std::fs;

use test_support::subscribe;

use crate::server_harness::TestServer;

#[test]
fn rfc_9539_smoke_test() {
    subscribe();

    const STATE_FILE_PATH: &str = "opp_enc_state.toml";

    {
        let _server = TestServer::start("example_recursor_opportunistic_enc.toml");
        // Just test that the server can start up and shut down. We can't query the recursor without
        // setting up a virtual network of authoritative name servers.
    }

    // Confirm that the state file was written out.
    assert!(fs::exists(STATE_FILE_PATH).unwrap());

    // Run a second time to confirm that the state file is loaded successfully.
    {
        let _server = TestServer::start("example_recursor_opportunistic_enc.toml");
    }

    // Clean up.
    fs::remove_file(STATE_FILE_PATH).unwrap();
}
