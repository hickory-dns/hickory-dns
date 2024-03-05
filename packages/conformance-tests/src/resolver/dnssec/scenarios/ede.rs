use std::net::Ipv4Addr;

use dns_test::client::{Client, DigSettings, ExtendedDnsError};
use dns_test::name_server::NameServer;
use dns_test::record::{Record, RecordType};
use dns_test::zone_file::Root;
use dns_test::{Network, Resolver, Result, FQDN};

#[ignore]
#[test]
fn dnskey_missing() -> Result<()> {
    let subject = dns_test::subject();
    let supports_ede = subject.supports_ede();

    let expected_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let needle_fqdn = FQDN("example.nameservers.com.")?;

    let network = Network::new()?;
    let peer = dns_test::peer();
    let mut root_ns = NameServer::new(&peer, FQDN::ROOT, &network)?;
    let mut com_ns = NameServer::new(&peer, FQDN::COM, &network)?;

    let mut nameservers_ns = NameServer::new(&peer, FQDN("nameservers.com.")?, &network)?;
    nameservers_ns
        .add(Record::a(root_ns.fqdn().clone(), root_ns.ipv4_addr()))
        .add(Record::a(com_ns.fqdn().clone(), com_ns.ipv4_addr()))
        .add(Record::a(needle_fqdn.clone(), expected_ipv4_addr));
    let mut nameservers_ns = nameservers_ns.sign()?;

    // remove the ZSK DNSKEY record
    let records = &mut nameservers_ns.signed_zone_file_mut().records;
    let mut remove_count = 0;
    *records = records
        .drain(..)
        .filter(|record| {
            let remove = if let Record::DNSKEY(dnskey) = record {
                dnskey.is_zone_signing_key()
            } else {
                false
            };

            if remove {
                remove_count += 1;
            }

            !remove
        })
        .collect();
    assert_eq!(1, remove_count);

    let nameservers_ds = nameservers_ns.ds().clone();
    let nameservers_ns = nameservers_ns.start()?;

    com_ns
        .referral(
            nameservers_ns.zone().clone(),
            nameservers_ns.fqdn().clone(),
            nameservers_ns.ipv4_addr(),
        )
        .add(nameservers_ds);
    let com_ns = com_ns.sign()?;
    let com_ds = com_ns.ds().clone();
    let com_ns = com_ns.start()?;

    root_ns
        .referral(FQDN::COM, com_ns.fqdn().clone(), com_ns.ipv4_addr())
        .add(com_ds);
    let root_ns = root_ns.sign()?;
    let root_ksk = root_ns.key_signing_key().clone();
    let root_zsk = root_ns.zone_signing_key().clone();

    let root_ns = root_ns.start()?;

    let mut resolver = Resolver::new(
        &network,
        Root::new(root_ns.fqdn().clone(), root_ns.ipv4_addr()),
    );

    if supports_ede {
        resolver.extended_dns_errors();
    }

    let resolver = resolver
        .trust_anchor_key(root_ksk)
        .trust_anchor_key(root_zsk)
        .start(&subject)?;
    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(&network)?;

    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(settings, resolver_addr, RecordType::A, &needle_fqdn)?;

    assert!(output.status.is_servfail());

    if supports_ede {
        assert_eq!(Some(ExtendedDnsError::DnskeyMissing), output.ede);
    }

    Ok(())
}
