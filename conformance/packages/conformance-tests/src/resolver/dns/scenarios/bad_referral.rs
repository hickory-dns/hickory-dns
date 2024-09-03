//! recursive resolution fails because a referral ("glue record") includes
//! a private IP address where no server is running

use std::net::Ipv4Addr;

use dns_test::client::{Client, DigOutput, DigSettings};
use dns_test::name_server::NameServer;
use dns_test::record::{Record, RecordType};
use dns_test::{Network, Resolver, Result, FQDN};

#[test]
#[ignore = "hickory-dns times out `dig`"]
fn v4_this_host() -> Result<()> {
    if dns_test::SUBJECT.is_unbound() {
        // unbound does not answer and `dig` times out
        return Ok(());
    }

    let output = fixture("v4-this-host", Ipv4Addr::new(0, 0, 0, 0))?;
    dbg!(&output);

    assert!(output.status.is_servfail());

    Ok(())
}

// as per RFC5737, `198.51.100.0/24` is an IANA reserved subnet that SHOULD not be used
#[test]
#[ignore = "hickory-dns answers with NOERROR"]
fn v4_doc() -> Result<()> {
    let output = fixture("v4-doc", Ipv4Addr::new(198, 51, 100, 0))?;
    dbg!(&output);

    assert!(output.status.is_servfail());

    Ok(())
}

#[test]
#[ignore = "hickory-dns answers with NOERROR"]
fn v4_reserved() -> Result<()> {
    let output = fixture("v4-reserved", Ipv4Addr::new(240, 0, 0, 0))?;
    dbg!(&output);

    assert!(output.status.is_servfail());

    Ok(())
}

#[test]
#[ignore = "hickory-dns answers with NOERROR"]
fn v4_link_local() -> Result<()> {
    let output = fixture("v4-link-local", Ipv4Addr::new(169, 254, 0, 1))?;

    assert!(output.status.is_servfail());

    Ok(())
}

#[test]
#[ignore = "hickory-dns answers with NOERROR"]
fn v4_loopback() -> Result<()> {
    let output = fixture("v4-loopback", Ipv4Addr::new(127, 0, 0, 1))?;
    dbg!(&output);

    assert!(output.status.is_servfail());

    Ok(())
}

#[test]
#[ignore = "hickory-dns answers with NOERROR"]
fn v4_private_10() -> Result<()> {
    let output = fixture("v4-private-10", Ipv4Addr::new(10, 0, 0, 1))?;
    dbg!(&output);

    assert!(output.status.is_servfail());

    Ok(())
}

#[test]
#[ignore = "hickory-dns answers with NOERROR"]
fn v4_private_172() -> Result<()> {
    let output = fixture("v4-private-172", Ipv4Addr::new(172, 16, 0, 1))?;
    dbg!(&output);

    assert!(output.status.is_servfail());

    Ok(())
}

#[test]
#[ignore = "hickory-dns answers with NOERROR"]
fn v4_private_192() -> Result<()> {
    let output = fixture("v4-private-192", Ipv4Addr::new(192, 168, 0, 1))?;
    dbg!(&output);

    assert!(output.status.is_servfail());

    Ok(())
}

fn fixture(label: &str, addr: Ipv4Addr) -> Result<DigOutput> {
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
    let settings = *DigSettings::default().recurse();
    client.dig(settings, resolver.ipv4_addr(), RecordType::A, &needle_fqdn)
}
