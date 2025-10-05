use std::net::Ipv4Addr;

use dns_test::{
    Error, FQDN, Implementation, Network, Resolver,
    client::{Client, DigOutput, DigSettings, DigStatus},
    name_server::NameServer,
    record::{Record, RecordType},
};

// Test the do not answer / answer filter functionality in the Hickory recursor
//
// test zone:
//
// nofilter.testing.      IN A 1.1.1.1
// filtersome.testing.    IN A 1.1.1.1
// filtersome.testing.    IN A 192.0.2.2
// filterall.testing.     IN A 192.0.2.2
// exception.testing.     IN A 192.0.2.1
// exceptionsome.testing. IN A 192.0.2.1
// exceptionsome.testing. IN A 192.0.2.2
#[test]
fn do_not_answer_test() -> Result<(), Error> {
    let config = include_str!("do_not_answer.toml").to_string();

    let network = Network::new()?;
    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let hint = root_ns.root_hint();

    let mut leaf_ns = NameServer::new(&Implementation::test_peer(), FQDN::TEST_TLD, &network)?;

    root_ns.referral(
        FQDN::TEST_TLD,
        FQDN("primary.testing.")?,
        leaf_ns.ipv4_addr(),
    );

    for rec in [
        ("nofilter", [1, 1, 1, 1]),
        ("filtersome", [1, 1, 1, 1]),
        ("filtersome", [192, 0, 2, 2]),
        ("filterall", [192, 0, 2, 2]),
        ("exception", [192, 0, 2, 1]),
        ("exceptionsome", [192, 0, 2, 1]),
        ("exceptionsome", [192, 0, 2, 2]),
    ] {
        leaf_ns.add(Record::a(FQDN::TEST_TLD.push_label(rec.0), rec.1.into()));
    }

    let _root_ns = root_ns.start()?;
    let _leaf_ns = leaf_ns.start()?;

    let resolver = Resolver::new(&network, hint)
        .custom_config(config)
        .start_with_subject(&Implementation::hickory())?;

    let client = Client::new(&network)?;

    let query = |name: &FQDN| {
        let settings = *DigSettings::default().recurse();
        client.dig(settings, resolver.ipv4_addr(), RecordType::A, name)
    };

    let tester = |output: DigOutput, status: DigStatus, addrs: &[Ipv4Addr]| {
        assert_eq!(output.status, status);
        assert_eq!(output.answer.len(), addrs.len());
        for (i, addr) in addrs.iter().enumerate() {
            assert_eq!(
                output.answer[i].clone().try_into_a().unwrap().ipv4_addr,
                *addr,
            );
        }
    };

    let output = query(&FQDN::TEST_TLD.push_label("nofilter"))?;
    tester(output, DigStatus::NOERROR, &[[1, 1, 1, 1].into()]);

    let output = query(&FQDN::TEST_TLD.push_label("filtersome"))?;
    tester(output, DigStatus::NOERROR, &[[1, 1, 1, 1].into()]);

    let output = query(&FQDN::TEST_TLD.push_label("filterall"))?;
    tester(output, DigStatus::NXDOMAIN, &[]);

    let output = query(&FQDN::TEST_TLD.push_label("exception"))?;
    tester(output, DigStatus::NOERROR, &[[192, 0, 2, 1].into()]);

    let output = query(&FQDN::TEST_TLD.push_label("exceptionsome"))?;
    tester(output, DigStatus::NOERROR, &[[192, 0, 2, 1].into()]);

    Ok(())
}
