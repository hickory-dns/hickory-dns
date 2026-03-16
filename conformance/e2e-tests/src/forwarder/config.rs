use std::{net::Ipv4Addr, time::Duration};

use dns_test::{
    Error, FQDN, Forwarder, Implementation, Network, Resolver,
    client::{Client, DigSettings, DigStatus},
    name_server::NameServer,
    record::{A, RecordType},
    tshark::Direction,
};

#[test]
fn edns_payload_len() -> Result<(), Error> {
    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let mut leaf_ns = NameServer::new(&Implementation::test_peer(), FQDN::TEST_TLD, &network)?;

    leaf_ns.add(A {
        fqdn: FQDN::TEST_DOMAIN,
        ttl: 86400,
        ipv4_addr: Ipv4Addr::new(10, 0, 0, 1),
    });

    root_ns.referral(
        FQDN::TEST_TLD,
        FQDN("primary.tld-server.testing.")?,
        leaf_ns.ipv4_addr(),
    );

    let root_hint = root_ns.root_hint();

    let _root_ns = root_ns.start()?;
    let _leaf_ns = leaf_ns.start()?;

    let resolver =
        Resolver::new(&network, root_hint).start_with_subject(&Implementation::test_peer())?;
    let forwarder = Forwarder::new(&network, &resolver)
        .custom_config(minijinja::render!(
            EDNS_PAYLOAD_SIZE_FORWARDER_CONFIG,
            resolver => resolver.ipv4_addr(),
        ))
        .start_with_subject(&Implementation::hickory())?;
    let client = Client::new(&network)?;

    let mut tshark = forwarder.eavesdrop_udp()?;
    let resolver_ip = resolver.ipv4_addr();

    let settings = *DigSettings::default().recurse();
    let output = client.dig(
        settings,
        forwarder.ipv4_addr(),
        RecordType::A,
        &FQDN::TEST_DOMAIN,
    )?;
    assert_eq!(output.status, DigStatus::NOERROR);

    tshark.wait_until(
        |captures| {
            captures.iter().any(|capture| {
                let Direction::Outgoing { destination } = capture.direction else {
                    return false;
                };
                destination == resolver_ip
            })
        },
        Duration::from_secs(10),
    )?;
    let captures = tshark.terminate()?;
    for captures in captures {
        let Direction::Outgoing { destination } = captures.direction else {
            continue;
        };
        if destination != resolver_ip {
            continue;
        }
        assert_eq!(captures.message.udp_payload_size(), Some(1234));
    }

    Ok(())
}

static EDNS_PAYLOAD_SIZE_FORWARDER_CONFIG: &str = r#"
user = "nobody"
group = "nogroup"

[[zones]]
zone = "."
zone_type = "External"

[zones.stores]
type = "forward"
options.allow_answers = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
options.edns_payload_len = 1234

[[zones.stores.name_servers]]
ip = "{{resolver}}"
trust_negative_responses = true
connections = [ { protocol = { type = "udp" } } ]
"#;
