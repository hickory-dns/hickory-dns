//! Tests that rely on public infrastructure
//!
//! Eventually all these tests should be rewritten to not rely on public infrastructure

#![cfg(test)]

use dns_test::{
    Error, FQDN, Implementation, Network, Resolver, TrustAnchor,
    client::{Client, DigOutput, DigSettings},
    name_server::{Graph, NameServer},
    record::{DS, RecordType},
    zone_file::{Root, SignSettings},
};

mod sanity_check;

#[test]
fn allow_query_localhost_dnssec() -> Result<(), Error> {
    compare("allow-query-localhost", true).map(drop)
}

#[test]
fn hermetic_allow_query_localhost_dnssec() -> Result<(), Error> {
    hermetic_compare("allow-query-localhost", true).map(drop)
}

#[test]
fn allow_query_localhost_no_dnssec() -> Result<(), Error> {
    compare("allow-query-localhost", false).map(drop)
}

#[test]
fn hermetic_allow_query_localhost_no_dnssec() -> Result<(), Error> {
    hermetic_compare("allow-query-localhost", false).map(drop)
}

#[test]
fn allow_query_none_dnssec() -> Result<(), Error> {
    compare("allow-query-none", true).map(drop)
}

#[test]
fn hermetic_allow_query_none_dnssec() -> Result<(), Error> {
    hermetic_compare("allow-query-none", true).map(drop)
}

#[test]
fn allow_query_none_no_dnssec() -> Result<(), Error> {
    compare("allow-query-none", false).map(drop)
}

#[test]
fn hermetic_allow_query_none_no_dnssec() -> Result<(), Error> {
    hermetic_compare("allow-query-none", false).map(drop)
}

#[test]
fn bad_ksk() -> Result<(), Error> {
    compare("bad-ksk", true).map(drop)
}

#[test]
fn hermetic_bad_ksk() -> Result<(), Error> {
    hermetic_compare("bad-ksk", true).map(drop)
}

#[test]
fn bad_nsec3_hash() -> Result<(), Error> {
    compare("bad-nsec3-hash", true).map(drop)
}

#[test]
fn hermetic_bad_nsec3_hash() -> Result<(), Error> {
    hermetic_compare("bad-nsec3-hash", true).map(drop)
}

#[test]
fn bad_nsec3_next() -> Result<(), Error> {
    compare("bad-nsec3-next", true).map(drop)
}

#[test]
fn hermetic_bad_nsec3_next() -> Result<(), Error> {
    hermetic_compare("bad-nsec3-next", true).map(drop)
}

#[test]
fn bad_nsec3_rrsig() -> Result<(), Error> {
    compare("bad-nsec3-rrsig", true).map(drop)
}

#[test]
fn hermetic_bad_nsec3_rrsig() -> Result<(), Error> {
    hermetic_compare("bad-nsec3-rrsig", true).map(drop)
}

#[test]
fn bad_nsec3param_salt() -> Result<(), Error> {
    compare("bad-nsec3param-salt", true).map(drop)
}

#[test]
fn hermetic_bad_nsec3param_salt() -> Result<(), Error> {
    hermetic_compare("bad-nsec3param-salt", true).map(drop)
}

#[test]
fn bad_rrsig_dnskey() -> Result<(), Error> {
    compare("bad-rrsig-dnskey", true).map(drop)
}

#[test]
fn hermetic_bad_rrsig_dnskey() -> Result<(), Error> {
    hermetic_compare("bad-rrsig-dnskey", true).map(drop)
}

#[test]
fn bad_rrsig_ksk() -> Result<(), Error> {
    compare("bad-rrsig-ksk", true).map(drop)
}

#[test]
fn hermetic_bad_rrsig_ksk() -> Result<(), Error> {
    hermetic_compare("bad-rrsig-ksk", true).map(drop)
}

#[test]
fn bad_zsk() -> Result<(), Error> {
    compare("bad-zsk", true).map(drop)
}

#[test]
fn hermetic_bad_zsk() -> Result<(), Error> {
    hermetic_compare("bad-zsk", true).map(drop)
}

#[test]
fn bad_zsk_algo() -> Result<(), Error> {
    compare("bad-zsk-algo", true).map(drop)
}

#[test]
fn hermetic_bad_zsk_algo() -> Result<(), Error> {
    hermetic_compare("bad-zsk-algo", true).map(drop)
}

#[test]
fn ds_bad_key_algo() -> Result<(), Error> {
    compare("ds-bad-key-algo", true).map(drop)
}

#[test]
fn hermetic_ds_bad_key_algo() -> Result<(), Error> {
    hermetic_compare("ds-bad-key-algo", true).map(drop)
}

#[test]
fn ds_bad_tag() -> Result<(), Error> {
    compare("ds-bad-tag", true).map(drop)
}

#[test]
fn hermetic_ds_bad_tag() -> Result<(), Error> {
    hermetic_compare("ds-bad-tag", true).map(drop)
}

#[test]
fn ds_bogus_digest_value() -> Result<(), Error> {
    compare("ds-bogus-digest-value", true).map(drop)
}

#[test]
fn hermetic_ds_bogus_digest_value() -> Result<(), Error> {
    hermetic_compare("ds-bogus-digest-value", true).map(drop)
}

#[test]
fn ds_reserved_key_algo() -> Result<(), Error> {
    compare("ds-reserved-key-algo", true).map(drop)
}

#[test]
fn hermetic_ds_reserved_key_algo() -> Result<(), Error> {
    hermetic_compare("ds-reserved-key-algo", true).map(drop)
}

#[test]
fn ds_unassigned_digest_algo() -> Result<(), Error> {
    compare("ds-unassigned-digest-algo", true).map(drop)
}

#[test]
fn hermetic_ds_unassigned_digest_algo() -> Result<(), Error> {
    hermetic_compare("ds-unassigned-digest-algo", true).map(drop)
}

#[test]
fn ds_unassigned_key_algo() -> Result<(), Error> {
    compare("ds-unassigned-key-algo", true).map(drop)
}

#[test]
fn hermetic_ds_unassigned_key_algo() -> Result<(), Error> {
    hermetic_compare("ds-unassigned-key-algo", true).map(drop)
}

#[test]
fn dsa() -> Result<(), Error> {
    compare("dsa", true).map(drop)
}

#[test]
fn hermetic_dsa() -> Result<(), Error> {
    hermetic_compare("dsa", true).map(drop)
}

#[test]
#[ignore = "hickory doesn't support ED448"]
fn ed448() -> Result<(), Error> {
    compare("ed448", true).map(drop)
}

#[test]
#[ignore = "hickory doesn't support ED448"]
fn hermetic_ed448() -> Result<(), Error> {
    hermetic_compare("ed448", true).map(drop)
}

#[test]
fn no_dnskey_256() -> Result<(), Error> {
    compare("no-dnskey-256", true).map(drop)
}

#[test]
fn hermetic_no_dnskey_256() -> Result<(), Error> {
    hermetic_compare("no-dnskey-256", true).map(drop)
}

#[test]
fn no_dnskey_256_257() -> Result<(), Error> {
    compare("no-dnskey-256-257", true).map(drop)
}

#[test]
fn hermetic_no_dnskey_256_257() -> Result<(), Error> {
    hermetic_compare("no-dnskey-256-257", true).map(drop)
}

#[test]
fn no_dnskey_257() -> Result<(), Error> {
    compare("no-dnskey-257", true).map(drop)
}

#[test]
fn hermetic_no_dnskey_257() -> Result<(), Error> {
    hermetic_compare("no-dnskey-257", true).map(drop)
}

#[test]
fn no_ds() -> Result<(), Error> {
    compare("no-ds", true).map(drop)
}

#[test]
fn hermetic_no_ds() -> Result<(), Error> {
    hermetic_compare("no-ds", true).map(drop)
}

#[test]
fn no_ksk() -> Result<(), Error> {
    compare("no-ksk", true).map(drop)
}

#[test]
fn hermetic_no_ksk() -> Result<(), Error> {
    hermetic_compare("no-ksk", true).map(drop)
}

#[test]
fn no_nsec3param_nsec3() -> Result<(), Error> {
    compare("no-nsec3param-nsec3", true).map(drop)
}

#[test]
fn hermetic_no_nsec3param_nsec3() -> Result<(), Error> {
    hermetic_compare("no-nsec3param-nsec3", true).map(drop)
}

#[test]
fn no_rrsig_dnskey() -> Result<(), Error> {
    compare("no-rrsig-dnskey", true).map(drop)
}

#[test]
fn hermetic_no_rrsig_dnskey() -> Result<(), Error> {
    hermetic_compare("no-rrsig-dnskey", true).map(drop)
}

#[test]
fn no_rrsig_ksk() -> Result<(), Error> {
    compare("no-rrsig-ksk", true).map(drop)
}

#[test]
fn hermetic_no_rrsig_ksk() -> Result<(), Error> {
    hermetic_compare("no-rrsig-ksk", true).map(drop)
}

#[test]
fn no_zsk() -> Result<(), Error> {
    compare("no-zsk", true).map(drop)
}

#[test]
fn hermetic_no_zsk() -> Result<(), Error> {
    hermetic_compare("no-zsk", true).map(drop)
}

#[test]
fn not_auth_dnssec() -> Result<(), Error> {
    compare("not-auth", true).map(drop)
}

#[test]
fn hermetic_not_auth_dnssec() -> Result<(), Error> {
    hermetic_compare("not-auth", true).map(drop)
}

#[test]
fn not_auth_no_dnssec() -> Result<(), Error> {
    compare("not-auth", false).map(drop)
}

#[test]
fn hermetic_not_auth_no_dnssec() -> Result<(), Error> {
    hermetic_compare("not-auth", false).map(drop)
}

#[test]
fn nsec3_iter_1() -> Result<(), Error> {
    compare("nsec3-iter-1", true).map(drop)
}

#[test]
fn hermetic_nsec3_iter_1() -> Result<(), Error> {
    hermetic_compare("nsec3-iter-1", true).map(drop)
}

#[test]
fn nsec3_iter_51() -> Result<(), Error> {
    compare("nsec3-iter-51", true).map(drop)
}

#[test]
fn hermetic_nsec3_iter_51() -> Result<(), Error> {
    hermetic_compare("nsec3-iter-51", true).map(drop)
}

#[test]
fn nsec3_iter_101() -> Result<(), Error> {
    compare("nsec3-iter-101", true).map(drop)
}

#[test]
fn hermetic_nsec3_iter_101() -> Result<(), Error> {
    hermetic_compare("nsec3-iter-101", true).map(drop)
}

#[test]
fn nsec3_iter_151() -> Result<(), Error> {
    compare("nsec3-iter-151", true).map(drop)
}

#[test]
fn hermetic_nsec3_iter_151() -> Result<(), Error> {
    hermetic_compare("nsec3-iter-151", true).map(drop)
}

#[test]
fn nsec3_iter_200() -> Result<(), Error> {
    compare("nsec3-iter-200", true).map(drop)
}

#[test]
fn hermetic_nsec3_iter_200() -> Result<(), Error> {
    hermetic_compare("nsec3-iter-200", true).map(drop)
}

#[test]
fn nsec3_missing() -> Result<(), Error> {
    compare("nsec3-missing", true).map(drop)
}

#[test]
fn hermetic_nsec3_missing() -> Result<(), Error> {
    hermetic_compare("nsec3-missing", true).map(drop)
}

#[test]
fn nsec3_rrsig_missing() -> Result<(), Error> {
    compare("nsec3-rrsig-missing", true).map(drop)
}

#[test]
fn hermetic_nsec3_rrsig_missing() -> Result<(), Error> {
    hermetic_compare("nsec3-rrsig-missing", true).map(drop)
}

#[test]
fn nsec3param_missing() -> Result<(), Error> {
    compare("nsec3param-missing", true).map(drop)
}

#[test]
fn hermetic_nsec3param_missing() -> Result<(), Error> {
    hermetic_compare("nsec3param-missing", true).map(drop)
}

#[test]
fn reserved_zsk_algo() -> Result<(), Error> {
    compare("reserved-zsk-algo", true).map(drop)
}

#[test]
fn hermetic_reserved_zsk_algo() -> Result<(), Error> {
    hermetic_compare("reserved-zsk-algo", true).map(drop)
}

#[test]
fn rrsig_exp_a() -> Result<(), Error> {
    compare("rrsig-exp-a", true).map(drop)
}

#[test]
fn hermetic_rrsig_exp_a() -> Result<(), Error> {
    hermetic_compare("rrsig-exp-a", true).map(drop)
}

#[test]
fn rrsig_exp_all() -> Result<(), Error> {
    compare("rrsig-exp-all", true).map(drop)
}

#[test]
fn hermetic_rrsig_exp_all() -> Result<(), Error> {
    hermetic_compare("rrsig-exp-all", true).map(drop)
}

#[test]
fn rrsig_exp_before_a() -> Result<(), Error> {
    compare("rrsig-exp-before-a", true).map(drop)
}

#[test]
fn hermetic_rrsig_exp_before_a() -> Result<(), Error> {
    hermetic_compare("rrsig-exp-before-a", true).map(drop)
}

#[test]
fn rrsig_exp_before_all() -> Result<(), Error> {
    compare("rrsig-exp-before-all", true).map(drop)
}

#[test]
fn hermetic_rrsig_exp_before_all() -> Result<(), Error> {
    hermetic_compare("rrsig-exp-before-all", true).map(drop)
}

#[test]
fn rrsig_no_a() -> Result<(), Error> {
    compare("rrsig-no-a", true).map(drop)
}

#[test]
fn hermetic_rrsig_no_a() -> Result<(), Error> {
    hermetic_compare("rrsig-no-a", true).map(drop)
}

#[test]
fn rrsig_no_all() -> Result<(), Error> {
    compare("rrsig-no-all", true).map(drop)
}

#[test]
fn hermetic_rrsig_no_all() -> Result<(), Error> {
    hermetic_compare("rrsig-no-all", true).map(drop)
}

#[test]
fn rrsig_not_yet_a() -> Result<(), Error> {
    compare("rrsig-not-yet-a", true).map(drop)
}

#[test]
fn hermetic_rrsig_not_yet_a() -> Result<(), Error> {
    hermetic_compare("rrsig-not-yet-a", true).map(drop)
}

#[test]
fn rrsig_not_yet_all() -> Result<(), Error> {
    compare("rrsig-not-yet-all", true).map(drop)
}

#[test]
fn hermetic_rrsig_not_yet_all() -> Result<(), Error> {
    hermetic_compare("rrsig-not-yet-all", true).map(drop)
}

#[test]
fn rsamd5() -> Result<(), Error> {
    compare("rsamd5", true).map(drop)
}

#[test]
fn hermetic_rsamd5() -> Result<(), Error> {
    hermetic_compare("rsamd5", true).map(drop)
}

#[test]
fn unassigned_zsk_algo() -> Result<(), Error> {
    compare("unassigned-zsk-algo", true).map(drop)
}

#[test]
fn hermetic_unassigned_zsk_algo() -> Result<(), Error> {
    hermetic_compare("unassigned-zsk-algo", true).map(drop)
}

#[test]
fn unsigned() -> Result<(), Error> {
    compare("unsigned", true).map(drop)
}

#[test]
fn hermetic_unsigned() -> Result<(), Error> {
    hermetic_compare("unsigned", true).map(drop)
}

#[test]
fn v4_doc_dnssec() -> Result<(), Error> {
    compare("v4-doc", true).map(drop)
}

#[test]
fn hermetic_v4_doc_dnssec() -> Result<(), Error> {
    hermetic_compare("v4-doc", true).map(drop)
}

#[test]
fn v4_doc_no_dnssec() -> Result<(), Error> {
    compare("v4-doc", false).map(drop)
}

#[test]
fn hermetic_v4_doc_no_dnssec() -> Result<(), Error> {
    hermetic_compare("v4-doc", false).map(drop)
}

#[test]
fn v6_doc_dnssec() -> Result<(), Error> {
    compare("v6-doc", true).map(drop)
}

#[test]
fn hermetic_v6_doc_dnssec() -> Result<(), Error> {
    hermetic_compare("v6-doc", true).map(drop)
}

#[test]
fn v6_doc_no_dnssec() -> Result<(), Error> {
    compare("v6-doc", false).map(drop)
}

#[test]
fn hermetic_v6_doc_no_dnssec() -> Result<(), Error> {
    hermetic_compare("v6-doc", false).map(drop)
}

#[test]
fn valid_dnssec() -> Result<(), Error> {
    compare("valid", true).map(drop)
}

#[test]
fn hermetic_valid_dnssec() -> Result<(), Error> {
    hermetic_compare("valid", true).map(drop)
}

#[test]
fn valid_no_dnssec() -> Result<(), Error> {
    compare("valid", false).map(drop)
}

#[test]
fn hermetic_valid_no_dnssec() -> Result<(), Error> {
    hermetic_compare("valid", false).map(drop)
}

/// compares hickory's response to unbound's response, using internet nameservers
///
/// this compares RCODE and flags but not EDE
fn compare(subdomain: &str, dnssec: bool) -> Result<DigOutput, Error> {
    let network = Network::with_internet_access()?;
    let domain = FQDN(format!("{subdomain}.extended-dns-errors.com."))?;

    let mut unbound = Resolver::new(&network, Root::public_dns());
    let mut hickory = Resolver::new(&network, Root::public_dns());
    if dnssec {
        unbound.trust_anchor(&TrustAnchor::public_dns());
        hickory.trust_anchor(&TrustAnchor::public_dns());
    }
    let unbound = unbound.start_with_subject(&Implementation::Unbound)?;
    let hickory = hickory.start_with_subject(&Implementation::hickory())?;

    let client = Client::new(&network)?;
    let mut settings = *DigSettings::default().recurse();
    if dnssec {
        settings = *settings.authentic_data();
    }
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
fn hermetic_compare(subdomain: &str, dnssec: bool) -> Result<DigOutput, Error> {
    let network = Network::new()?;
    let (subdomain_fqdn, graph) = setup_hermetic_network(subdomain, &network)?;

    let mut unbound = Resolver::new(&network, graph.root.clone());
    let mut hickory = Resolver::new(&network, graph.root.clone());
    if dnssec {
        unbound.trust_anchor(graph.trust_anchor.as_ref().unwrap());
        hickory.trust_anchor(graph.trust_anchor.as_ref().unwrap());
    }
    let unbound = unbound.start_with_subject(&Implementation::Unbound)?;
    let hickory = hickory.start_with_subject(&Implementation::hickory())?;

    let client = Client::new(&network)?;
    let mut settings = *DigSettings::default().recurse();
    if dnssec {
        settings = *settings.authentic_data();
    }
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
fn setup_hermetic_network(subdomain: &str, network: &Network) -> Result<(FQDN, Graph), Error> {
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

fn parse_dnssec_signzone_dsset(input: &str) -> Result<Vec<DS>, Error> {
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
