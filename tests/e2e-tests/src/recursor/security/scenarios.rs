/// These scenarios use a Dnslib-based server which returns invalid answers that should be dropped
use std::fs;

use dns_test::{
    client::{Client, DigSettings},
    name_server::NameServer,
    record::RecordType,
    zone_file::Root,
    Implementation, Network, Resolver, Result, FQDN,
};

/// Transaction ID check - verify that Hickory will drop an invalidate transaction id.
#[test]
fn tx_id_validation_test() -> Result<()> {
    let target_fqdn = FQDN("www.example.testing.")?;

    let network = Network::new()?;

    let mut root_ns = NameServer::new(&Implementation::test_peer(), FQDN::ROOT, &network)?;
    let leaf_ns = NameServer::new(&Implementation::Dnslib, FQDN::TEST_TLD, &network)?;

    let script = fs::read_to_string("src/recursor/security/bad_txid.py")?;

    leaf_ns.cp("/script.py", &script[..])?;

    root_ns.referral(
        FQDN::TEST_TLD,
        FQDN("primary.tld-server.testing.")?,
        leaf_ns.ipv4_addr(),
    );

    let root_hint: Root = root_ns.root_hint();

    let resolver =
        Resolver::new(&network, root_hint).start_with_subject(&Implementation::hickory())?;

    let client = Client::new(resolver.network())?;

    let _root_ns = root_ns.start()?;
    let _leaf_ns = leaf_ns.start()?;

    let a_settings = *DigSettings::default().recurse().authentic_data();
    let res = client.dig(
        a_settings,
        resolver.ipv4_addr(),
        RecordType::A,
        &target_fqdn,
    );

    if let Ok(res) = &res {
        // FIXME This should be servfail; need the error propagation fix from #2522
        assert!(res.status.is_noerror());
        assert_eq!(res.answer.len(), 0);
    } else {
        panic!("error");
    }

    assert!(resolver.logs().unwrap().contains("expected message id:"));

    Ok(())
}
