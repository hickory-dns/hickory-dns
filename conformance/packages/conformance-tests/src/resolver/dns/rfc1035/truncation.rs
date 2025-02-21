//! Section 7.4, "Using the cache" says in part, "When several RRs of the same type are available
//! for a particular owner name, the resolver should either cache them all or none at all. When a
//! response is truncated, and a resolver doesn't know whether it has a complete set, it should not
//! cache a possibly partial set of RRs."

use std::{fs, thread, time::Duration};

use dns_test::{
    FQDN, Implementation, Network, Resolver, Result,
    client::{Client, DigSettings, DigStatus},
    name_server::{Graph, NameServer},
    record::{Record, RecordType},
};

/// Verify that resolvers will retry a query over TCP if they get a truncated response via UDP, and
/// only cache the complete TCP response.
#[test]
fn truncated_response_caching_with_tcp_fallback() -> Result<()> {
    let target_fqdn = FQDN("example.testing.")?;
    let (resolver, client, _graph) =
        setup("src/resolver/dns/rfc1035/truncated_with_tcp_fallback.py")?;

    let dig_settings = *DigSettings::default().recurse().timeout(7);

    let result_1 = client.dig(
        dig_settings,
        resolver.ipv4_addr(),
        RecordType::TXT,
        &target_fqdn,
    );
    let response_1 = result_1
        .unwrap_or_else(|e| panic!("error {e:?} resolver logs: {}", resolver.logs().unwrap()));
    println!("first response: {response_1:?}");
    let (protocol_1, counter_1) = parse_txt_records(&response_1.answer)?;

    assert_eq!(response_1.status, DigStatus::NOERROR);

    // Check that the resolver fell back to TCP.
    assert_eq!(protocol_1.as_deref(), Some("TCP"));
    assert!(counter_1.is_some());

    let result_2 = client.dig(
        dig_settings,
        resolver.ipv4_addr(),
        RecordType::TXT,
        &target_fqdn,
    );
    let response_2 = result_2
        .unwrap_or_else(|e| panic!("error {e:?} resolver logs: {}", resolver.logs().unwrap()));
    println!("second response: {response_2:?}");
    let (protocol_2, counter_2) = parse_txt_records(&response_2.answer)?;

    println!("{}", resolver.logs()?);

    assert_eq!(response_2.status, DigStatus::NOERROR);

    // Check that we got a cached response.
    assert_eq!(protocol_2.as_deref(), Some("TCP"));
    assert_eq!(counter_1, counter_2);

    Ok(())
}

/// Verify that resolvers will not cache a truncated response received via UDP if the authoritative
/// server does not reply to TCP fallback queries.
#[test]
fn truncated_response_caching_udp_only() -> Result<()> {
    let target_fqdn = FQDN("example.testing.")?;
    let (resolver, client, _graph) = setup("src/resolver/dns/rfc1035/truncated_udp_only.py")?;

    let dig_settings = *DigSettings::default().recurse().timeout(7);

    let result_1 = client.dig(
        dig_settings,
        resolver.ipv4_addr(),
        RecordType::TXT,
        &target_fqdn,
    );
    let response_1 = result_1
        .unwrap_or_else(|e| panic!("error {e:?} resolver logs: {}", resolver.logs().unwrap()));
    println!("first response: {response_1:?}");
    let (_protocol_1, counter_1) = parse_txt_records(&response_1.answer)?;

    if response_1.status == DigStatus::SERVFAIL {
        // Unbound and BIND return an error instead of returning the truncated UDP response, if there's no
        // reply via TCP.
        return Ok(());
    }

    assert_eq!(response_1.status, DigStatus::NOERROR);

    let result_2 = client.dig(
        dig_settings,
        resolver.ipv4_addr(),
        RecordType::TXT,
        &target_fqdn,
    );
    let response_2 = result_2
        .unwrap_or_else(|e| panic!("error {e:?} resolver logs: {}", resolver.logs().unwrap()));
    println!("second response: {response_2:?}");
    let (_protocol_2, counter_2) = parse_txt_records(&response_2.answer)?;

    println!("{}", resolver.logs()?);

    assert_eq!(response_2.status, DigStatus::NOERROR);

    // Check that the resolver did not cache the truncated response.
    assert_ne!(counter_1, counter_2);

    Ok(())
}

fn setup(script_path: &str) -> Result<(Resolver, Client, Graph)> {
    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let leaf_ns = NameServer::new(&Implementation::Dnslib, FQDN::TEST_TLD, &network)?;
    let script = fs::read_to_string(script_path)?;
    leaf_ns.cp("/script.py", &script)?;

    root_ns.referral_nameserver(&leaf_ns);

    let root_hint = root_ns.root_hint();
    let resolver = Resolver::new(&network, root_hint.clone()).start()?;

    let client = Client::new(resolver.network())?;

    let root_ns = root_ns.start()?;
    let leaf_ns = leaf_ns.start()?;

    thread::sleep(Duration::from_secs(2));

    let graph = Graph {
        nameservers: vec![root_ns, leaf_ns],
        root: root_hint,
        trust_anchor: None,
    };

    Ok((resolver, client, graph))
}

/// Parse the protocol name and counter value from the dnslib-based name server's response.
fn parse_txt_records(records: &[Record]) -> Result<(Option<String>, Option<u64>)> {
    let mut protocol = None;
    let mut counter = None;
    for record in records.iter() {
        let Record::TXT(text) = record else {
            continue;
        };
        for string in text.character_strings.iter() {
            if let Some(protocol_str) = string.strip_prefix("protocol=") {
                protocol = Some(protocol_str.to_string());
            }
            if let Some(counter_str) = string.strip_prefix("counter=") {
                counter = Some(counter_str.parse::<u64>().unwrap());
            }
        }
    }
    Ok((protocol, counter))
}
