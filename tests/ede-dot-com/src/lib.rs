//! Tests that rely on public infrastructure
//!
//! Eventually all these tests should be rewritten to not rely on public infrastructure

#![cfg(test)]

use dns_test::{
    FQDN, Implementation, Network, Resolver, Result, TrustAnchor,
    client::{Client, DigOutput, DigSettings},
    name_server::{Graph, NameServer},
    record::{DS, RecordType},
    zone_file::{Root, SignSettings},
};

mod sanity_check;

#[test]
fn allow_query_localhost() -> Result<()> {
    compare("allow-query-localhost").map(drop)
}

#[test]
fn hermetic_allow_query_localhost() -> Result<()> {
    hermetic_compare("allow-query-localhost").map(drop)
}

#[test]
fn allow_query_none() -> Result<()> {
    compare("allow-query-none").map(drop)
}

#[test]
fn hermetic_allow_query_none() -> Result<()> {
    hermetic_compare("allow-query-none").map(drop)
}

#[test]
fn bad_ksk() -> Result<()> {
    compare("bad-ksk").map(drop)
}

#[test]
fn hermetic_bad_ksk() -> Result<()> {
    hermetic_compare("bad-ksk").map(drop)
}

#[test]
fn bad_nsec3_hash() -> Result<()> {
    compare("bad-nsec3-hash").map(drop)
}

#[test]
fn hermetic_bad_nsec3_hash() -> Result<()> {
    hermetic_compare("bad-nsec3-hash").map(drop)
}

#[test]
fn bad_nsec3_next() -> Result<()> {
    compare("bad-nsec3-next").map(drop)
}

#[test]
fn hermetic_bad_nsec3_next() -> Result<()> {
    hermetic_compare("bad-nsec3-next").map(drop)
}

#[test]
fn bad_nsec3_rrsig() -> Result<()> {
    compare("bad-nsec3-rrsig").map(drop)
}

#[test]
fn hermetic_bad_nsec3_rrsig() -> Result<()> {
    hermetic_compare("bad-nsec3-rrsig").map(drop)
}

#[test]
fn bad_nsec3param_salt() -> Result<()> {
    compare("bad-nsec3param-salt").map(drop)
}

#[test]
fn hermetic_bad_nsec3param_salt() -> Result<()> {
    hermetic_compare("bad-nsec3param-salt").map(drop)
}

#[test]
fn bad_rrsig_dnskey() -> Result<()> {
    compare("bad-rrsig-dnskey").map(drop)
}

#[test]
fn hermetic_bad_rrsig_dnskey() -> Result<()> {
    hermetic_compare("bad-rrsig-dnskey").map(drop)
}

#[test]
fn bad_rrsig_ksk() -> Result<()> {
    compare("bad-rrsig-ksk").map(drop)
}

#[test]
fn hermetic_bad_rrsig_ksk() -> Result<()> {
    hermetic_compare("bad-rrsig-ksk").map(drop)
}

#[test]
fn bad_zsk() -> Result<()> {
    compare("bad-zsk").map(drop)
}

#[test]
fn hermetic_bad_zsk() -> Result<()> {
    hermetic_compare("bad-zsk").map(drop)
}

#[test]
fn bad_zsk_algo() -> Result<()> {
    compare("bad-zsk-algo").map(drop)
}

#[test]
fn hermetic_bad_zsk_algo() -> Result<()> {
    hermetic_compare("bad-zsk-algo").map(drop)
}

#[test]
fn ds_bad_key_algo() -> Result<()> {
    compare("ds-bad-key-algo").map(drop)
}

#[test]
fn hermetic_ds_bad_key_algo() -> Result<()> {
    hermetic_compare("ds-bad-key-algo").map(drop)
}

#[test]
fn ds_bad_tag() -> Result<()> {
    compare("ds-bad-tag").map(drop)
}

#[test]
fn hermetic_ds_bad_tag() -> Result<()> {
    hermetic_compare("ds-bad-tag").map(drop)
}

#[test]
fn ds_bogus_digest_value() -> Result<()> {
    compare("ds-bogus-digest-value").map(drop)
}

#[test]
fn hermetic_ds_bogus_digest_value() -> Result<()> {
    hermetic_compare("ds-bogus-digest-value").map(drop)
}

#[test]
fn ds_reserved_key_algo() -> Result<()> {
    compare("ds-reserved-key-algo").map(drop)
}

#[test]
fn hermetic_ds_reserved_key_algo() -> Result<()> {
    hermetic_compare("ds-reserved-key-algo").map(drop)
}

#[test]
fn ds_unassigned_digest_algo() -> Result<()> {
    compare("ds-unassigned-digest-algo").map(drop)
}

#[test]
fn hermetic_ds_unassigned_digest_algo() -> Result<()> {
    hermetic_compare("ds-unassigned-digest-algo").map(drop)
}

#[test]
fn ds_unassigned_key_algo() -> Result<()> {
    compare("ds-unassigned-key-algo").map(drop)
}

#[test]
fn hermetic_ds_unassigned_key_algo() -> Result<()> {
    hermetic_compare("ds-unassigned-key-algo").map(drop)
}

#[test]
fn dsa() -> Result<()> {
    compare("dsa").map(drop)
}

#[test]
fn hermetic_dsa() -> Result<()> {
    hermetic_compare("dsa").map(drop)
}

#[test]
#[ignore = "hickory doesn't support ED448"]
fn ed448() -> Result<()> {
    compare("ed448").map(drop)
}

#[test]
#[ignore = "hickory doesn't support ED448"]
fn hermetic_ed448() -> Result<()> {
    hermetic_compare("ed448").map(drop)
}

#[test]
fn no_dnskey_256() -> Result<()> {
    compare("no-dnskey-256").map(drop)
}

#[test]
fn hermetic_no_dnskey_256() -> Result<()> {
    hermetic_compare("no-dnskey-256").map(drop)
}

#[test]
fn no_dnskey_256_257() -> Result<()> {
    compare("no-dnskey-256-257").map(drop)
}

#[test]
fn hermetic_no_dnskey_256_257() -> Result<()> {
    hermetic_compare("no-dnskey-256-257").map(drop)
}

#[test]
fn no_dnskey_257() -> Result<()> {
    compare("no-dnskey-257").map(drop)
}

#[test]
fn hermetic_no_dnskey_257() -> Result<()> {
    hermetic_compare("no-dnskey-257").map(drop)
}

#[test]
fn no_ds() -> Result<()> {
    compare("no-ds").map(drop)
}

#[test]
fn hermetic_no_ds() -> Result<()> {
    hermetic_compare("no-ds").map(drop)
}

#[test]
fn no_ksk() -> Result<()> {
    compare("no-ksk").map(drop)
}

#[test]
fn hermetic_no_ksk() -> Result<()> {
    hermetic_compare("no-ksk").map(drop)
}

#[test]
fn no_nsec3param_nsec3() -> Result<()> {
    compare("no-nsec3param-nsec3").map(drop)
}

#[test]
fn hermetic_no_nsec3param_nsec3() -> Result<()> {
    hermetic_compare("no-nsec3param-nsec3").map(drop)
}

#[test]
fn no_rrsig_dnskey() -> Result<()> {
    compare("no-rrsig-dnskey").map(drop)
}

#[test]
fn hermetic_no_rrsig_dnskey() -> Result<()> {
    hermetic_compare("no-rrsig-dnskey").map(drop)
}

#[test]
fn no_rrsig_ksk() -> Result<()> {
    compare("no-rrsig-ksk").map(drop)
}

#[test]
fn hermetic_no_rrsig_ksk() -> Result<()> {
    hermetic_compare("no-rrsig-ksk").map(drop)
}

#[test]
fn no_zsk() -> Result<()> {
    compare("no-zsk").map(drop)
}

#[test]
fn hermetic_no_zsk() -> Result<()> {
    hermetic_compare("no-zsk").map(drop)
}

#[test]
fn not_auth() -> Result<()> {
    compare("not-auth").map(drop)
}

#[test]
fn hermetic_not_auth() -> Result<()> {
    hermetic_compare("not-auth").map(drop)
}

#[test]
fn nsec3_iter_1() -> Result<()> {
    compare("nsec3-iter-1").map(drop)
}

#[test]
fn hermetic_nsec3_iter_1() -> Result<()> {
    hermetic_compare("nsec3-iter-1").map(drop)
}

#[test]
fn nsec3_iter_51() -> Result<()> {
    compare("nsec3-iter-51").map(drop)
}

#[test]
fn hermetic_nsec3_iter_51() -> Result<()> {
    hermetic_compare("nsec3-iter-51").map(drop)
}

#[test]
fn nsec3_iter_101() -> Result<()> {
    compare("nsec3-iter-101").map(drop)
}

#[test]
fn hermetic_nsec3_iter_101() -> Result<()> {
    hermetic_compare("nsec3-iter-101").map(drop)
}

#[test]
fn nsec3_iter_151() -> Result<()> {
    compare("nsec3-iter-151").map(drop)
}

#[test]
fn hermetic_nsec3_iter_151() -> Result<()> {
    hermetic_compare("nsec3-iter-151").map(drop)
}

#[test]
fn nsec3_iter_200() -> Result<()> {
    compare("nsec3-iter-200").map(drop)
}

#[test]
fn hermetic_nsec3_iter_200() -> Result<()> {
    hermetic_compare("nsec3-iter-200").map(drop)
}

#[test]
fn nsec3_missing() -> Result<()> {
    compare("nsec3-missing").map(drop)
}

#[test]
fn hermetic_nsec3_missing() -> Result<()> {
    hermetic_compare("nsec3-missing").map(drop)
}

#[test]
fn nsec3_rrsig_missing() -> Result<()> {
    compare("nsec3-rrsig-missing").map(drop)
}

#[test]
fn hermetic_nsec3_rrsig_missing() -> Result<()> {
    hermetic_compare("nsec3-rrsig-missing").map(drop)
}

#[test]
fn nsec3param_missing() -> Result<()> {
    compare("nsec3param-missing").map(drop)
}

#[test]
fn hermetic_nsec3param_missing() -> Result<()> {
    hermetic_compare("nsec3param-missing").map(drop)
}

#[test]
fn reserved_zsk_algo() -> Result<()> {
    compare("reserved-zsk-algo").map(drop)
}

#[test]
fn hermetic_reserved_zsk_algo() -> Result<()> {
    hermetic_compare("reserved-zsk-algo").map(drop)
}

#[test]
fn rrsig_exp_a() -> Result<()> {
    compare("rrsig-exp-a").map(drop)
}

#[test]
fn hermetic_rrsig_exp_a() -> Result<()> {
    hermetic_compare("rrsig-exp-a").map(drop)
}

#[test]
fn rrsig_exp_all() -> Result<()> {
    compare("rrsig-exp-all").map(drop)
}

#[test]
fn hermetic_rrsig_exp_all() -> Result<()> {
    hermetic_compare("rrsig-exp-all").map(drop)
}

#[test]
fn rrsig_exp_before_a() -> Result<()> {
    compare("rrsig-exp-before-a").map(drop)
}

#[test]
fn hermetic_rrsig_exp_before_a() -> Result<()> {
    hermetic_compare("rrsig-exp-before-a").map(drop)
}

#[test]
fn rrsig_exp_before_all() -> Result<()> {
    compare("rrsig-exp-before-all").map(drop)
}

#[test]
fn hermetic_rrsig_exp_before_all() -> Result<()> {
    hermetic_compare("rrsig-exp-before-all").map(drop)
}

#[test]
fn rrsig_no_a() -> Result<()> {
    compare("rrsig-no-a").map(drop)
}

#[test]
fn hermetic_rrsig_no_a() -> Result<()> {
    hermetic_compare("rrsig-no-a").map(drop)
}

#[test]
fn rrsig_no_all() -> Result<()> {
    compare("rrsig-no-all").map(drop)
}

#[test]
fn hermetic_rrsig_no_all() -> Result<()> {
    hermetic_compare("rrsig-no-all").map(drop)
}

#[test]
fn rrsig_not_yet_a() -> Result<()> {
    compare("rrsig-not-yet-a").map(drop)
}

#[test]
fn hermetic_rrsig_not_yet_a() -> Result<()> {
    hermetic_compare("rrsig-not-yet-a").map(drop)
}

#[test]
fn rrsig_not_yet_all() -> Result<()> {
    compare("rrsig-not-yet-all").map(drop)
}

#[test]
fn hermetic_rrsig_not_yet_all() -> Result<()> {
    hermetic_compare("rrsig-not-yet-all").map(drop)
}

#[test]
fn rsamd5() -> Result<()> {
    compare("rsamd5").map(drop)
}

#[test]
fn hermetic_rsamd5() -> Result<()> {
    hermetic_compare("rsamd5").map(drop)
}

#[test]
fn unassigned_zsk_algo() -> Result<()> {
    compare("unassigned-zsk-algo").map(drop)
}

#[test]
fn hermetic_unassigned_zsk_algo() -> Result<()> {
    hermetic_compare("unassigned-zsk-algo").map(drop)
}

#[test]
fn unsigned() -> Result<()> {
    compare("unsigned").map(drop)
}

#[test]
fn hermetic_unsigned() -> Result<()> {
    hermetic_compare("unsigned").map(drop)
}

#[test]
fn v4_doc() -> Result<()> {
    compare("v4-doc").map(drop)
}

#[test]
fn hermetic_v4_doc() -> Result<()> {
    hermetic_compare("v4-doc").map(drop)
}

#[test]
fn v6_doc() -> Result<()> {
    compare("v6-doc").map(drop)
}

#[test]
fn hermetic_v6_doc() -> Result<()> {
    hermetic_compare("v6-doc").map(drop)
}

#[test]
fn valid() -> Result<()> {
    compare("valid").map(drop)
}

#[test]
fn hermetic_valid() -> Result<()> {
    hermetic_compare("valid").map(drop)
}

/// compares hickory's response to unbound's response, using internet nameservers
///
/// this compares RCODE and flags but not EDE
fn compare(subdomain: &str) -> Result<DigOutput> {
    let network = Network::with_internet_access()?;
    let domain = FQDN(format!("{subdomain}.extended-dns-errors.com."))?;

    let unbound = Resolver::new(&network, Root::public_dns())
        .trust_anchor(&TrustAnchor::public_dns())
        .start_with_subject(&Implementation::Unbound)?;

    let hickory = Resolver::new(&network, Root::public_dns())
        .trust_anchor(&TrustAnchor::public_dns())
        .start_with_subject(&Implementation::hickory())?;

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse().authentic_data();
    // we expect this to never time out
    let hickory_response = client.dig(settings, hickory.ipv4_addr(), RecordType::A, &domain)?;

    let Ok(unbound_response) = client.dig(settings, unbound.ipv4_addr(), RecordType::A, &domain)
    else {
        // unbound timed out so we cannot compare
        // XXX unclear if we want to assert this
        // assert!(hickory_response.status.is_servfail());
        return Ok(hickory_response);
    };

    dbg!(&unbound_response);
    dbg!(&hickory_response);

    assert_eq!(unbound_response.status, hickory_response.status);
    assert_eq!(unbound_response.flags, hickory_response.flags);

    Ok(unbound_response)
}

/// compares hickory's response to unbound's response, using local nameservers
///
/// this compares RCODE and flags but not EDE
fn hermetic_compare(subdomain: &str) -> Result<DigOutput> {
    let network = Network::new()?;
    let (subdomain_fqdn, graph) = setup_hermetic_network(subdomain, &network)?;

    let unbound = Resolver::new(&network, graph.root.clone())
        .trust_anchor(graph.trust_anchor.as_ref().unwrap())
        .start_with_subject(&Implementation::Unbound)?;
    let hickory = Resolver::new(&network, graph.root.clone())
        .trust_anchor(graph.trust_anchor.as_ref().unwrap())
        .start_with_subject(&Implementation::hickory())?;

    let client = Client::new(&network)?;
    let settings = *DigSettings::default().recurse().authentic_data();
    let hickory_response = client.dig(
        settings,
        hickory.ipv4_addr(),
        RecordType::A,
        &subdomain_fqdn,
    )?;
    let unbound_response = client.dig(
        settings,
        unbound.ipv4_addr(),
        RecordType::A,
        &subdomain_fqdn,
    )?;

    dbg!(&unbound_response);
    dbg!(&hickory_response);

    assert_eq!(unbound_response.status, hickory_response.status);
    assert_eq!(unbound_response.flags, hickory_response.flags);

    Ok(unbound_response)
}

/// Creates a Docker network with nameservers for *.extended-dns-errors.com and all parent zones.
fn setup_hermetic_network(subdomain: &str, network: &Network) -> Result<(FQDN, Graph)> {
    let subdomain_fqdn = FQDN(format!("{subdomain}.extended-dns-errors.com."))?;

    let mut root_ns = NameServer::new(&Implementation::Bind, FQDN::ROOT, network)?;
    let mut tld_ns = NameServer::new(&Implementation::Bind, FQDN::COM_TLD, network)?;
    let parent_ns = NameServer::new(&Implementation::EdeDotCom, FQDN::EDE_DOT_COM, network)?;
    let child_ns = NameServer::new(&Implementation::EdeDotCom, subdomain_fqdn.clone(), network)?;

    let child_output = child_ns.container().output(&[
        "/configure_child.sh",
        &format!("{}", child_ns.ipv4_addr()),
        "extended-dns-errors.com",
        "65.21.183.116",
        "2a01:4f9:c012:6b60::1",
        subdomain,
    ])?;
    if !child_output.status.success() {
        panic!(
            "configuring child server failed\nSTDOUT:\n{}\nSTDERR:\n{}",
            child_output.stdout, child_output.stderr
        );
    }
    let mut child_dsset = child_ns
        .container()
        .stdout(&["cat", "/dsset_for_parent.txt"])?;
    let mut glues = child_ns.container().stdout(&["cat", "/glues.txt"])?;
    // Add back newlines stripped by `Output`.
    child_dsset.push('\n');
    glues.push('\n');

    parent_ns.cp("/dsset_for_parent.txt", &child_dsset)?;
    parent_ns.cp("/glues.txt", &glues)?;
    let parent_output = parent_ns.container().output(&[
        "/configure_parent.sh",
        &format!("{}", parent_ns.ipv4_addr()),
        "extended-dns-errors.com",
        "65.21.183.116",
        "2a01:4f9:c012:6b60::1",
    ])?;
    if !parent_output.status.success() {
        panic!(
            "configuring parent server failed\nSTDOUT:\n{}\nSTDERR:\n{}",
            parent_output.stdout, parent_output.stderr
        );
    }
    let parent_dsset = parent_ns.container().stdout(&[
        "cat",
        "/etc/bind/zone_ede/extended-dns-errors.com/dsset-extended-dns-errors.com.",
    ])?;

    tld_ns.referral(
        FQDN::EDE_DOT_COM,
        FQDN("ns1.extended-dns-errors.com.")?,
        parent_ns.ipv4_addr(),
    );
    for parent_ds in parse_dnssec_signzone_dsset(&parent_dsset)? {
        tld_ns.add(parent_ds);
    }

    let tld_ns = tld_ns.sign(SignSettings::default())?;

    root_ns.referral(
        FQDN::COM_TLD,
        FQDN("primary.nameservers.com.")?,
        tld_ns.ipv4_addr(),
    );
    root_ns.add(tld_ns.ds().ksk.clone());

    let root_ns = root_ns.sign(SignSettings::default())?;
    let trust_anchor = Some(root_ns.trust_anchor());

    let root_ns = root_ns.start()?;
    let tld_ns = tld_ns.start()?;
    let parent_ns = parent_ns.start()?;
    let child_ns = child_ns.start()?;

    let root = root_ns.root_hint();

    let nameservers = vec![child_ns, parent_ns, tld_ns, root_ns];

    Ok((
        subdomain_fqdn,
        Graph {
            nameservers,
            root,
            trust_anchor,
        },
    ))
}

fn parse_dnssec_signzone_dsset(input: &str) -> Result<Vec<DS>> {
    let mut ds_records = Vec::new();
    for line in input.split('\n') {
        if line.trim().is_empty() {
            continue;
        }
        let mut tokens = line.split_ascii_whitespace().collect::<Vec<_>>();
        // Insert a TTL, since dnssec-signzone does not include one in DS records, and our FromStr
        // implementations do not support this.
        tokens.insert(1, "86400");
        let ds: DS = tokens.join(" ").parse()?;
        ds_records.push(ds);
    }
    Ok(ds_records)
}
