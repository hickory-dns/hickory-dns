//! These tests use a proxy in front of authoritative name servers to exclude specific DNSSEC RRs,
//! and confirm that their absence causes validation to return "bogus".

use dns_test::{
    Error, FQDN, Implementation, Network, PEER, Resolver,
    client::{Client, DigOutput, DigSettings, DigStatus},
    name_server::{NameServer, Signed, Stopped},
    record::RecordType,
    zone_file::SignSettings,
};

mod rfc_5155_appendix_b;

/// This runs multiple tests to confirm that validation fails when specific records are excluded.
///
/// Tests are run against the provided name servers, along with a root name server, and resolvers.
/// First, a baseline query is performed, where no records are excluded. Then, for each name and
/// record type in `knockout_rrsets`, proxy servers are used to exclude records from that specific
/// RRset, and recursive queries are repeated. If any of the responses does not have a SERVFAIL
/// response code, that is treated as a test failure. The response from the baseline query is
/// returned, so that the enclosing test can also ensure the resolver works correctly in the absence
/// of any interference.
fn test_record_removal_validation_failure(
    signed_leaf_servers: Vec<NameServer<Signed>>,
    unsigned_leaf_servers: Vec<NameServer<Stopped>>,
    query_name: FQDN,
    query_type: RecordType,
    knockout_rrsets: &[(FQDN, RecordType)],
    network: &Network,
) -> Result<DigOutput, Error> {
    let client = Client::new(network)?;
    let dig_settings = *DigSettings::default().recurse().dnssec().authentic_data();

    let mut leaf_servers;
    let unmodified_response;
    let mut ds_records = Vec::new();
    {
        let mut root_ns_unmodified = NameServer::new(&PEER, FQDN::ROOT, network)?;
        for ns in signed_leaf_servers.iter() {
            root_ns_unmodified.referral_nameserver(ns);
            root_ns_unmodified.add(ns.ds().ksk.clone());
            ds_records.push(ns.ds().ksk.clone());
        }
        for ns in unsigned_leaf_servers.iter() {
            root_ns_unmodified.referral_nameserver(ns);
        }
        let root_ns_unmodified = root_ns_unmodified.sign(SignSettings::default())?;
        let trust_anchor = root_ns_unmodified.trust_anchor();
        let root_ns_unmodified = root_ns_unmodified.start()?;

        leaf_servers = Vec::with_capacity(signed_leaf_servers.len() + unsigned_leaf_servers.len());
        for ns in signed_leaf_servers.into_iter() {
            leaf_servers.push(ns.start()?);
        }
        for ns in unsigned_leaf_servers.into_iter() {
            leaf_servers.push(ns.start()?);
        }

        let resolver_unmodified = Resolver::new(network, root_ns_unmodified.root_hint())
            .trust_anchor(&trust_anchor)
            .start()?;
        unmodified_response = client.dig(
            dig_settings,
            resolver_unmodified.ipv4_addr(),
            query_type,
            &query_name,
        )?;
        for (knockout_name, knockout_type) in knockout_rrsets.iter() {
            let mut seen = false;
            for section in [
                &unmodified_response.answer,
                &unmodified_response.authority,
                &unmodified_response.additional,
            ] {
                for record in section {
                    if record.name().as_str().to_lowercase()
                        == knockout_name.as_str().to_lowercase()
                        && record.record_type() == *knockout_type
                    {
                        seen = true;
                        break;
                    }
                }
                if seen {
                    break;
                }
            }
            assert!(
                seen,
                "expected record {knockout_name} {knockout_type} was not present in original \
                response\n{unmodified_response:#?}"
            );
        }
    }

    for (knockout_name, knockout_type) in knockout_rrsets.iter() {
        let mut proxies = Vec::with_capacity(leaf_servers.len());
        let mut root_ns = NameServer::new(&PEER, FQDN::ROOT, network)?;
        for ns in leaf_servers.iter() {
            let proxy_ns = NameServer::builder(
                Implementation::test_server(
                    "drop_rrset",
                    vec![
                        ns.ipv4_addr().to_string(),
                        knockout_name.to_string(),
                        knockout_type.to_string(),
                    ],
                    "both",
                ),
                ns.zone().clone(),
                network.clone(),
            )
            .nameserver_fqdn(ns.zone_file().soa.nameserver.clone())
            .rname_fqdn(ns.zone_file().soa.admin.clone())
            .build()?;
            root_ns.referral_nameserver(&proxy_ns);
            proxies.push(proxy_ns.start()?);
        }
        for ds in ds_records.iter() {
            root_ns.add(ds.clone());
        }
        let root_ns = root_ns.sign(SignSettings::default())?;
        let trust_anchor = root_ns.trust_anchor();
        let root_ns = root_ns.start()?;

        let resolver = Resolver::new(network, root_ns.root_hint())
            .trust_anchor(&trust_anchor)
            .start()?;
        let response = client.dig(dig_settings, resolver.ipv4_addr(), query_type, &query_name)?;

        println!("{}", resolver.logs()?);

        assert_eq!(
            response.status,
            DigStatus::SERVFAIL,
            "did not get SERVFAIL when excluding {knockout_name} {knockout_type} from \
            responses\n{response:#?}"
        );
    }

    Ok(unmodified_response)
}
