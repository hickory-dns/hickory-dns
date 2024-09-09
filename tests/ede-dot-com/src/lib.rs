//! Tests that rely on public infrastructure
//!
//! Eventually all these tests should be rewritten to not rely on public infrastructure

#![cfg(test)]

use dns_test::{
    client::{Client, DigOutput, DigSettings},
    record::RecordType,
    zone_file::Root,
    Implementation, Network, Resolver, Result, TrustAnchor, FQDN,
};

mod sanity_check;

#[test]
#[ignore]
fn allow_query_localhost() -> Result<()> {
    compare("allow-query-localhost").map(drop)
}

#[test]
#[ignore]
fn allow_query_none() -> Result<()> {
    compare("allow-query-none").map(drop)
}

#[test]
fn bad_ksk() -> Result<()> {
    compare("bad-ksk").map(drop)
}

#[test]
fn bad_nsec3_hash() -> Result<()> {
    compare("bad-nsec3-hash").map(drop)
}

#[test]
fn bad_nsec3_next() -> Result<()> {
    compare("bad-nsec3-next").map(drop)
}

#[test]
fn bad_nsec3_rrsig() -> Result<()> {
    compare("bad-nsec3-rrsig").map(drop)
}

#[test]
fn bad_nsec3param_salt() -> Result<()> {
    compare("bad-nsec3param-salt").map(drop)
}

#[test]
fn bad_rrsig_dnskey() -> Result<()> {
    compare("bad-rrsig-dnskey").map(drop)
}

#[test]
fn bad_rrsig_ksk() -> Result<()> {
    compare("bad-rrsig-ksk").map(drop)
}

#[test]
fn bad_zsk() -> Result<()> {
    compare("bad-zsk").map(drop)
}

#[test]
fn bad_zsk_algo() -> Result<()> {
    compare("bad-zsk-algo").map(drop)
}

#[test]
fn ds_bad_key_algo() -> Result<()> {
    compare("ds-bad-key-algo").map(drop)
}

#[test]
fn ds_bad_tag() -> Result<()> {
    compare("ds-bad-tag").map(drop)
}

#[test]
fn ds_bogus_digest_value() -> Result<()> {
    compare("ds-bogus-digest-value").map(drop)
}

#[test]
fn ds_reserved_key_algo() -> Result<()> {
    compare("ds-reserved-key-algo").map(drop)
}

#[test]
fn ds_unassigned_digest_algo() -> Result<()> {
    compare("ds-unassigned-digest-algo").map(drop)
}

#[test]
fn ds_unassigned_key_algo() -> Result<()> {
    compare("ds-unassigned-key-algo").map(drop)
}

#[test]
fn dsa() -> Result<()> {
    compare("dsa").map(drop)
}

#[test]
#[ignore]
fn ed448() -> Result<()> {
    compare("ed448").map(drop)
}

#[test]
fn no_dnskey_256() -> Result<()> {
    compare("no-dnskey-256").map(drop)
}

#[test]
fn no_dnskey_256_257() -> Result<()> {
    compare("no-dnskey-256-257").map(drop)
}

#[test]
fn no_dnskey_257() -> Result<()> {
    compare("no-dnskey-257").map(drop)
}

#[test]
#[ignore]
fn no_ds() -> Result<()> {
    compare("no-ds").map(drop)
}

#[test]
fn no_ksk() -> Result<()> {
    compare("no-ksk").map(drop)
}

#[test]
fn no_nsec3param_nsec3() -> Result<()> {
    compare("no-nsec3param-nsec3").map(drop)
}

#[test]
fn no_rrsig_dnskey() -> Result<()> {
    compare("no-rrsig-dnskey").map(drop)
}

#[test]
fn no_rrsig_ksk() -> Result<()> {
    compare("no-rrsig-ksk").map(drop)
}

#[test]
fn no_zsk() -> Result<()> {
    compare("no-zsk").map(drop)
}

#[test]
fn nsec3_iter_200() -> Result<()> {
    compare("nsec3-iter-200").map(drop)
}

#[test]
fn nsec3_missing() -> Result<()> {
    compare("nsec3-missing").map(drop)
}

#[test]
fn nsec3_rrsig_missing() -> Result<()> {
    compare("nsec3-rrsig-missing").map(drop)
}

#[test]
fn nsec3param_missing() -> Result<()> {
    compare("nsec3param-missing").map(drop)
}

#[test]
fn reserved_zsk_algo() -> Result<()> {
    compare("reserved-zsk-algo").map(drop)
}

#[test]
fn rrsig_exp_a() -> Result<()> {
    compare("rrsig-exp-a").map(drop)
}

#[test]
fn rrsig_exp_all() -> Result<()> {
    compare("rrsig-exp-all").map(drop)
}

#[test]
fn rrsig_exp_before_a() -> Result<()> {
    compare("rrsig-exp-before-a").map(drop)
}

#[test]
fn rrsig_exp_before_all() -> Result<()> {
    compare("rrsig-exp-before-all").map(drop)
}

#[test]
fn rrsig_no_a() -> Result<()> {
    compare("rrsig-no-a").map(drop)
}

#[test]
fn rrsig_no_all() -> Result<()> {
    compare("rrsig-no-all").map(drop)
}

#[test]
fn rrsig_not_yet_a() -> Result<()> {
    compare("rrsig-not-yet-a").map(drop)
}

#[test]
fn rrsig_not_yet_all() -> Result<()> {
    compare("rrsig-not-yet-all").map(drop)
}

#[test]
fn rsamd5() -> Result<()> {
    compare("rsamd5").map(drop)
}

#[test]
fn unassigned_zsk_algo() -> Result<()> {
    compare("unassigned-zsk-algo").map(drop)
}

#[test]
#[ignore]
fn unsigned() -> Result<()> {
    compare("unsigned").map(drop)
}

#[test]
#[ignore]
fn v4_doc() -> Result<()> {
    compare("v4-doc").map(drop)
}

#[test]
#[ignore]
fn v4_hex() -> Result<()> {
    compare("v4-hex").map(drop)
}

#[test]
#[ignore]
fn v4_link_local() -> Result<()> {
    compare("v4-link-local").map(drop)
}

#[test]
#[ignore]
fn v4_loopback() -> Result<()> {
    compare("v4-loopback").map(drop)
}

#[test]
#[ignore]
fn v4_private_10() -> Result<()> {
    compare("v4-private-10").map(drop)
}

#[test]
#[ignore]
fn v4_private_172() -> Result<()> {
    compare("v4-private-172").map(drop)
}

#[test]
#[ignore]
fn v4_private_192() -> Result<()> {
    compare("v4-private-192").map(drop)
}

#[test]
#[ignore]
fn v4_reserved() -> Result<()> {
    compare("v4-reserved").map(drop)
}

#[test]
#[ignore]
fn v4_this_host() -> Result<()> {
    compare("v4-this-host").map(drop)
}

#[test]
#[ignore]
fn v6_doc() -> Result<()> {
    compare("v6-doc").map(drop)
}

#[test]
#[ignore]
fn v6_link_local() -> Result<()> {
    compare("v6-link-local").map(drop)
}

#[test]
#[ignore]
fn v6_localhost() -> Result<()> {
    compare("v6-localhost").map(drop)
}

#[test]
#[ignore]
fn v6_mapped() -> Result<()> {
    compare("v6-mapped").map(drop)
}

#[test]
#[ignore]
fn v6_mapped_dep() -> Result<()> {
    compare("v6-mapped-dep").map(drop)
}

#[test]
#[ignore]
fn v6_multicast() -> Result<()> {
    compare("v6-multicast").map(drop)
}

#[test]
#[ignore]
fn v6_nat64() -> Result<()> {
    compare("v6-nat64").map(drop)
}

#[test]
#[ignore]
fn v6_unique_local() -> Result<()> {
    compare("v6-unique-local").map(drop)
}

#[test]
#[ignore]
fn v6_unspecified() -> Result<()> {
    compare("v6-unspecified").map(drop)
}

#[test]
fn valid() -> Result<()> {
    compare("valid").map(drop)
}

/// compares hickory's response to unbound's response
///
/// this compares STATUS and flags but not EDE
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
