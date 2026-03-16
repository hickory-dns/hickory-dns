use std::{net::Ipv4Addr, time::Duration};

use dns_test::{
    Error, FQDN, Implementation, Network, Resolver,
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
    let resolver = Resolver::new(&network, root_hint)
        .custom_config(EDNS_PAYLOAD_SIZE_RECURSOR_CONFIG.to_string())
        .start_with_subject(&Implementation::hickory())?;
    let client = Client::new(&network)?;

    let _root_ns = root_ns.start()?;
    let leaf_ns = leaf_ns.start()?;
    let leaf_ip = leaf_ns.ipv4_addr();

    let mut tshark = resolver.eavesdrop_udp()?;

    let settings = *DigSettings::default().recurse();
    let output = client.dig(
        settings,
        resolver.ipv4_addr(),
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
                destination == leaf_ip
            })
        },
        Duration::from_secs(10),
    )?;
    let captures = tshark.terminate()?;
    for capture in captures {
        let Direction::Outgoing { destination } = capture.direction else {
            continue;
        };
        if destination != leaf_ip {
            continue;
        }
        assert_eq!(capture.message.udp_payload_size(), Some(1234));
    }

    Ok(())
}

static EDNS_PAYLOAD_SIZE_RECURSOR_CONFIG: &str = r#"
user = "nobody"
group = "nogroup"

[[zones]]
zone = "."
zone_type = "External"

[zones.stores]
type = "recursor"
roots = "/etc/root.hints"
dnssec_policy = "ValidationDisabled"
allow_server = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
edns_payload_len = 1234
"#;
