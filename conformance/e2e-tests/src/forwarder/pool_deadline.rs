//! Test that the forwarder's name server pool respects the end-to-end timeout deadline.

use std::time::{Duration, Instant};

use dns_test::{
    Error, FQDN, Forwarder, Implementation, Network, Resolver,
    client::{Client, DigSettings},
    name_server::NameServer,
    record::RecordType,
};

#[test]
fn pool_deadline_with_unresponsive_upstreams() -> Result<(), Error> {
    // The Hickory forwarder config's timeout setting.
    const HICKORY_TIMEOUT_SECS: u64 = 1;

    // The hickory forwarder config's num_concurrent_reqs setting.
    const HICKORY_NUM_CONCURRENT_REQS: usize = 1;

    // Number of unresponsive name servers.
    // We want more of these than the number of concurrent requests we'll make.
    const NUM_SERVERS: usize = HICKORY_NUM_CONCURRENT_REQS + 4;

    let network = Network::new()?;

    let mut servers = Vec::with_capacity(NUM_SERVERS);
    for _ in 0..NUM_SERVERS {
        let server = NameServer::new(
            // Configure the test server TCP-only. UDP queries will time out!
            &Implementation::test_server("base", "tcp"),
            FQDN::TEST_TLD,
            &network,
        )?;
        servers.push(server.start()?);
    }

    let root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let resolver = Resolver::new(&network, root_ns.root_hint())
        .start_with_subject(&Implementation::test_peer())?;
    let _root_ns = root_ns.start()?;

    // Configure multiple forwarder name servers, importantly only with type=udp.
    let name_server_entries = servers
        .iter()
        .map(|s| {
            format!(
                r#"
[[zones.stores.name_servers]]
ip = "{}"
connections = [{{ protocol = {{ type = "udp" }} }}]
"#,
                s.ipv4_addr()
            )
        })
        .collect::<String>();

    let config = format!(
        r#"
user = "nobody"
group = "nogroup"

[[zones]]
zone = "."
zone_type = "External"

[zones.stores]
type = "forward"

[zones.stores.options]
# Configure a global timeout.
timeout = {HICKORY_TIMEOUT_SECS}
# Don't muddy things with additional attempts after the initial attempt.
attempts = 0
# Race connections to this many nameservers at once.
num_concurrent_reqs = {HICKORY_NUM_CONCURRENT_REQS}
{name_server_entries}"#
    );

    let forwarder = Forwarder::new(&network, &resolver)
        .custom_config(config)
        .start_with_subject(&Implementation::hickory())?;

    let start = Instant::now();
    let result = Client::new(&network)?.dig(
        *DigSettings::default().recurse(),
        forwarder.ipv4_addr(),
        RecordType::A,
        &FQDN("example.com.")?,
    );
    assert!(
        result.is_ok(),
        "dig should complete, not error: {:?}",
        result
    );
    let elapsed = start.elapsed();

    // If the global timeout is being respected the elapsed time shouldn't have scaled
    // with the number of lame servers we had configured.
    let max_expected = Duration::from_secs(HICKORY_TIMEOUT_SECS + 1);
    assert!(
        elapsed < max_expected,
        "Pool should respect deadline. Expected < {max_expected:?} but took {elapsed:?}. \
         Forwarder logs:\n{}",
        forwarder.logs().unwrap_or_default()
    );

    Ok(())
}
