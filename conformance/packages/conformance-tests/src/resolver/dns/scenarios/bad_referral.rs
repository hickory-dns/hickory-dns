//! recursive resolution fails because a referral ("glue record") includes
//! a private IP address where no server is running

use std::net::Ipv4Addr;

use dns_test::client::{Client, DigOutput, DigSettings};
use dns_test::name_server::NameServer;
use dns_test::record::{Record, RecordType};
use dns_test::{FQDN, Network, Resolver, Result};

#[test]
fn v4_this_host() -> Result<()> {
    if dns_test::SUBJECT.is_unbound() {
        // unbound does not answer and `dig` times out
        return Ok(());
    }

    let (output, logs) = fixture("v4-this-host", Ipv4Addr::UNSPECIFIED)?;
    dbg!(&output);

    assert!(output.status.is_servfail());

    if dns_test::SUBJECT.is_hickory()
        && !logs.lines().any(|line| {
            line.contains("ignoring address due to do_not_query") && line.contains("0.0.0.0")
        })
    {
        panic!("did not find ignored referral to 0.0.0.0");
    }

    Ok(())
}

#[test]
fn v4_loopback() -> Result<()> {
    let (output, logs) = fixture("v4-loopback", Ipv4Addr::LOCALHOST)?;
    dbg!(&output);

    assert!(output.status.is_servfail());

    if dns_test::SUBJECT.is_hickory()
        && !logs.lines().any(|line| {
            line.contains("ignoring address due to do_not_query") && line.contains("127.0.0.1")
        })
    {
        panic!("did not find ignored referral to 127.0.0.1");
    }

    Ok(())
}

#[test]
fn v4_broadcast() -> Result<()> {
    let (output, logs) = fixture("v4-broadcast", Ipv4Addr::BROADCAST)?;
    dbg!(&output);

    assert!(output.status.is_servfail());

    if dns_test::SUBJECT.is_hickory()
        && !logs.lines().any(|line| {
            line.contains("ignoring address due to do_not_query")
                && line.contains("255.255.255.255")
        })
    {
        panic!("did not find ignored referral to 255.255.255.255");
    }

    Ok(())
}

fn fixture(label: &str, addr: Ipv4Addr) -> Result<(DigOutput, String)> {
    let network = Network::new()?;

    let leaf_zone = FQDN::TEST_TLD.push_label(label);
    let needle_fqdn = leaf_zone.push_label("example");

    let mut root_ns = NameServer::new(&dns_test::PEER, FQDN::ROOT, &network)?;
    let mut tld_ns = NameServer::new(&dns_test::PEER, FQDN::TEST_TLD, &network)?;
    let mut sibling_ns = NameServer::new(&dns_test::PEER, FQDN::TEST_DOMAIN, &network)?;
    let mut leaf_ns = NameServer::new(&dns_test::PEER, leaf_zone.clone(), &network)?;

    sibling_ns.add(root_ns.a());
    sibling_ns.add(tld_ns.a());
    sibling_ns.add(leaf_ns.a());

    leaf_ns.add(Record::a(needle_fqdn.clone(), Ipv4Addr::new(1, 2, 3, 4)));

    root_ns.referral_nameserver(&tld_ns);
    tld_ns.referral_nameserver(&sibling_ns);
    // IMPORTANT! here we do a wrong/incorrect referral on purporse
    tld_ns.referral(leaf_zone.clone(), leaf_ns.fqdn().clone(), addr);

    let root_hint = root_ns.root_hint();
    let _nameservers = [
        root_ns.start()?,
        tld_ns.start()?,
        sibling_ns.start()?,
        leaf_ns.start()?,
    ];

    let mut resolver = Resolver::new(&network, root_hint);
    if dns_test::SUBJECT.is_unbound() {
        resolver.extended_dns_errors();
    }
    let resolver = resolver.start()?;

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse().timeout(7);
    let output = client.dig(settings, resolver.ipv4_addr(), RecordType::A, &needle_fqdn)?;

    Ok((output, resolver.logs().unwrap()))
}
