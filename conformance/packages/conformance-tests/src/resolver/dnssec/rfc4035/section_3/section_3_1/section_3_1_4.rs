use dns_test::{
    client::{Client, DigSettings},
    name_server::{Graph, NameServer, Sign},
    record::RecordType,
    tshark::{Capture, Direction},
    zone_file::SignSettings,
    Network, Resolver, Result, FQDN,
};

#[test]
fn on_clients_ds_query_it_queries_the_parent_zone() -> Result<()> {
    let network = Network::new()?;

    let leaf_ns = NameServer::new(&dns_test::PEER, FQDN::NAMESERVERS, &network)?;

    let Graph {
        nameservers,
        root,
        trust_anchor,
    } = Graph::build(
        leaf_ns,
        Sign::Yes {
            settings: SignSettings::default(),
        },
    )?;

    let mut com_ns_addr = None;
    for nameserver in &nameservers {
        if nameserver.zone() == &FQDN::COM {
            com_ns_addr = Some(nameserver.ipv4_addr());
        }
    }
    let com_ns_addr = com_ns_addr.expect("com. NS not found");

    let trust_anchor = &trust_anchor.unwrap();
    let resolver = Resolver::new(&network, root)
        .trust_anchor(trust_anchor)
        .start()?;

    let mut tshark = resolver.eavesdrop()?;

    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse();
    let output = client.dig(settings, resolver_addr, RecordType::DS, &FQDN::NAMESERVERS)?;

    tshark.wait_for_capture()?;

    let captures = tshark.terminate()?;

    // check that we were able to retrieve the DS record
    assert!(output.status.is_noerror());
    let [record] = output.answer.try_into().unwrap();
    let ds = record.try_into_ds().unwrap();
    assert_eq!(ds.zone, FQDN::NAMESERVERS);

    // check that DS query was forwarded to the `com.` (parent zone) nameserver
    let client_addr = client.ipv4_addr();
    let mut outgoing_ds_query_count = 0;
    for Capture { message, direction } in captures {
        if let Direction::Outgoing { destination } = direction {
            if destination != client_addr {
                let queries = message.as_value()["Queries"]
                    .as_object()
                    .expect("expected Object");
                for query in queries.keys() {
                    if query.contains("type DS") {
                        assert!(query.contains("nameservers.com"));
                        assert_eq!(com_ns_addr, destination);

                        outgoing_ds_query_count += 1;
                    }
                }
            }
        }
    }

    assert_eq!(1, outgoing_ds_query_count);

    Ok(())
}
