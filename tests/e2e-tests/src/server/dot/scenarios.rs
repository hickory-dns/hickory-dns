/// Tests related to the authoritative server implementation DoT support.
use std::time::Duration;

use dns_test::client::{Client, DigSettings};
use dns_test::name_server::{Graph, NameServer, Sign};
use dns_test::record::RecordType;
use dns_test::tshark::{Capture, Direction, Protocol, ProtocolFilter, Tshark};
use dns_test::{Error, FQDN, Implementation, Network, Pki, Resolver};

/// Test the pdns recursive resolver RFC 9539 opportunistic DoT support works with Hickory.
///
/// This tests the scenario where a client recursively queries through a pdns-recursor set up
/// with DoT probing. After the recursor successfully discovers the Hickory DNS auth servers support
/// DoT it should start upgrading its requests to use DoT instead of Do53.
///
/// We can observe this by making recursive queries and interrogating the traffic that arrives
/// at the auth server.
#[test]
fn pdns_opportunistic_dot_success() -> Result<(), Error> {
    let network = &Network::new()?;
    let leaf_ns = NameServer::builder(
        Implementation::hickory(),
        FQDN::TEST_DOMAIN,
        network.clone(),
    )
    .pki(Pki::new()?.into())
    .build()?;

    let Graph {
        root: root_info,
        nameservers,
        ..
    } = Graph::build(leaf_ns, Sign::No)?;

    // TODO(XXX): Presently auth. hickory servers do not send referrals properly,
    //   and so only the root NS sees queries. Once #2810 is fixed we should switch
    //   this test to ensure the other 2 auth. nameservers see expected traffic.
    let root_ns = nameservers.last().unwrap();

    // Capture nameserver traffic on UDP 53 and TCP 853 to get both plaintext DNS
    // and DoT requests/responses.
    let mut tshark = Tshark::builder()
        .filters(vec![
            ProtocolFilter::default(),
            ProtocolFilter::default()
                .protocol(Protocol::Tcp)
                .port(DOT_PORT),
        ])
        .ssl_keylog_file("/tmp/sslkeys.log") // See hickory.Dockerfile
        .build(root_ns.container())?;

    // Create a PDNS resolver configured for DoT probing.
    let resolver = Resolver::new(network, root_info)
        .custom_config(PDNS_RECURSOR_PROBE_CONFIG.to_string())
        .start_with_subject(&Implementation::Pdns)?;

    // Make a recursive query for the root FQDN A record using the resolver instance.
    let client = Client::new(network)?;
    let query_settings = *DigSettings::default().recurse();
    let resolver_ip = resolver.ipv4_addr();
    let resp = client.dig(query_settings, resolver_ip, RecordType::A, &FQDN::ROOT)?;
    assert!(resp.status.is_noerror());

    // Then, make a second recursive query for a different record type to provoke DoT probing.
    // The pdns-recursor implementation won't do this based on the first query alone.
    let resp = client.dig(query_settings, resolver_ip, RecordType::AAAA, &FQDN::ROOT)?;
    assert!(resp.status.is_noerror());

    // Wait until we've captured at least one incoming DoT probe at the nameserver.
    tshark.wait_until(
        |captures| {
            captures.iter().any(|c| {
                matches!(c.direction, Direction::Incoming { .. }) && c.dst_port == DOT_PORT
            })
        },
        Duration::from_secs(10),
    )?;

    // Now, make a final query for yet another record type. The recursor should use DoT to satisfy
    // the request based on its prior probing success.
    let resp = client.dig(query_settings, resolver_ip, RecordType::MX, &FQDN::ROOT)?;
    assert!(resp.status.is_noerror());

    // Wait until we've seen an incoming DoT query for the correct record name and type.
    // This is the query from the resolver that was upgraded to DoT opportunistically.
    tshark.wait_until(
        |captures| {
            captures.iter().any(|c| {
                matches!(c.direction, Direction::Incoming { .. })
                    && c.dst_port == DOT_PORT
                    && query_name_and_type(c) == ("<Root>", record_types::MX)
            })
        },
        Duration::from_secs(10),
    )?;

    // Partition the captured incoming queries based on their dest port.
    let (dot_queries, udp_queries) = tshark
        .terminate()?
        .into_iter()
        .filter(|c| matches!(c.direction, Direction::Incoming { .. }))
        .partition::<Vec<_>, _>(|m| m.dst_port == DOT_PORT);

    // We should have received 2 UDP queries:
    //  * Our very first query, a lookup for the root A record.
    //  * Our second query, a lookup for the testing root AAAA record.
    assert_eq!(udp_queries.len(), 2);
    assert_eq!(
        query_name_and_type(&udp_queries[0]),
        ("<Root>", record_types::A)
    );
    assert_eq!(
        query_name_and_type(&udp_queries[1]),
        ("<Root>", record_types::AAAA)
    );

    // We should have received at least 2 DoT queries:
    //  * At least one probe lookup from the recursor opportunistically checking us out after our
    //    second query.
    //  * Our third and final query, a lookup for the root's MX record. We verified
    //    its presence in the last `wait_until()`.
    assert!(dot_queries.len() >= 2);

    Ok(())
}

// Perform serde_json::Value acrobatics to extract the qry name and rr type from capture's first query.
fn query_name_and_type(c: &Capture) -> (&str, u16) {
    let message_map = c.message.as_value().as_object().unwrap();
    let queries_map = message_map.get("Queries").unwrap().as_object().unwrap();
    let first_query = queries_map.values().next().unwrap().as_object().unwrap();
    let name = first_query.get("dns.qry.name").unwrap().as_str().unwrap();
    let r#type = first_query
        .get("dns.qry.type")
        .unwrap()
        .as_str()
        .unwrap()
        .parse::<u16>()
        .unwrap();
    (name, r#type)
}

// Custom config based on `pdns.resolver.conf.jinja` that sets the 'max_busy_dot_probes'
// setting. See https://doc.powerdns.com/recursor/yamlsettings.html#outgoing-max-busy-dot-probes
// for more information.
static PDNS_RECURSOR_PROBE_CONFIG: &str = r#"
recursor:
  write_pid: false
  socket_dir: /var/run/pdns-recursor
  hint_file: /etc/root.hints
  security_poll_suffix: ""

dnssec:
  validation: off

outgoing:
  dont_query: []
  max_busy_dot_probes: 10

incoming:
  listen:
    - 0.0.0.0
  allow_from:
    - 0.0.0.0/0

logging:
  loglevel: 9
  trace: true
  quiet: false
"#;

const DOT_PORT: u16 = 853;

/// An internal module for record type constants.
///
/// Wireshark exposes query types as their integer value, and we don't want a dependency
/// on hickory-proto just for matching to expected.
mod record_types {
    pub(super) const A: u16 = 1;
    pub(super) const AAAA: u16 = 28;
    pub(super) const MX: u16 = 15;
}
