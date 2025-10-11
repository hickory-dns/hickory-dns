//! Test how resolvers respond to packet loss.

use std::{net::Ipv4Addr, time::Instant};

use dns_test::{
    Error, FQDN, Implementation, Network, PEER, Resolver,
    client::{Client, DigSettings, DigStatus},
    name_server::NameServer,
    record::RecordType,
    tshark::{Capture, Direction},
};

#[test]
fn packet_loss_udp() -> Result<(), Error> {
    let target_fqdn = FQDN("example.testing.")?;
    let network = Network::new()?;

    let mut root_ns = NameServer::new(&PEER, FQDN::ROOT, &network)?;
    let leaf_ns = NameServer::new(
        &Implementation::test_server("packet_loss", "udp"),
        FQDN::TEST_TLD,
        &network,
    )?;

    root_ns.referral_nameserver(&leaf_ns);

    let root_hint = root_ns.root_hint();
    let resolver = Resolver::new(&network, root_hint).start()?;
    let client = Client::new(resolver.network())?;
    let dig_settings = *DigSettings::default().recurse().timeout(10);

    let _root_ns = root_ns.start()?;
    let _leaf_ns = leaf_ns.start()?;

    let mut tshark = resolver.eavesdrop_udp()?;

    let start_time = Instant::now();
    let result = client.dig(
        dig_settings,
        resolver.ipv4_addr(),
        RecordType::A,
        &target_fqdn,
    );
    let response = result
        .unwrap_or_else(|e| panic!("error {e:?} resolver logs: {}", resolver.logs().unwrap()));

    let query_time = (Instant::now() - start_time).as_millis();

    assert_eq!(response.status, DigStatus::NOERROR);
    assert_eq!(response.answer.len(), 1, "{:?}", response.answer);
    assert_eq!(
        response.answer[0].clone().try_into_a().unwrap().ipv4_addr,
        Ipv4Addr::new(192, 0, 2, 1)
    );

    tshark.wait_for_capture()?;
    let captures = tshark.terminate()?;

    // The default Hickory retry timer is 333ms; the query must have taken at least that long
    // Also verify that we sent 2 queries to Hickory and received 1 response back.  This should
    // work on other DNS test subjects, but doesn't.
    if dns_test::SUBJECT.is_hickory() {
        assert!(query_time >= 333);

        let leaf_ip = _leaf_ns.ipv4_addr();
        let mut query_count = 0;
        let mut response_count = 0;
        for Capture {
            message, direction, ..
        } in captures.iter()
        {
            let queries = message.as_value()["Queries"]
                .as_object()
                .expect("not an object");

            match direction {
                Direction::Outgoing { destination } if *destination == leaf_ip => {
                    for query in queries.keys() {
                        if query.contains("example.testing: type A, class IN") {
                            query_count += 1;
                        }
                    }
                }
                Direction::Incoming { source } if *source == leaf_ip => {
                    let answers = message.as_value()["Answers"]
                        .as_object()
                        .expect("not an object");

                    for query in queries.keys() {
                        for answer in answers.keys() {
                            if query.contains("example.testing: type A, class IN")
                                && answer
                                    .contains("example.testing: type A, class IN, addr 192.0.2.1")
                            {
                                response_count += 1;
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        assert_eq!(query_count, 2);
        assert_eq!(response_count, 1);
    }

    Ok(())
}
