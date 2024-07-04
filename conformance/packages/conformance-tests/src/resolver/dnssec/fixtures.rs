use std::net::Ipv4Addr;

use base64::prelude::*;
use dns_test::{
    name_server::{Graph, NameServer, Running, Sign},
    record::Record,
    zone_file::SignSettings,
    Network, Resolver, Result, TrustAnchor, FQDN,
};

pub fn bad_signature_in_leaf_nameserver(
    leaf_fqdn: &FQDN,
    leaf_ipv4_addr: Ipv4Addr,
) -> Result<(Resolver, Graph)> {
    assert_eq!(Some(FQDN::NAMESERVERS), leaf_fqdn.parent());

    let network = Network::new()?;

    let mut leaf_ns = NameServer::new(&dns_test::PEER, FQDN::NAMESERVERS, &network)?;
    leaf_ns.add(Record::a(leaf_fqdn.clone(), leaf_ipv4_addr));

    let graph = Graph::build(
        leaf_ns,
        Sign::AndAmend {
            settings: SignSettings::default(),
            mutate: &|zone, records| {
                if zone == &FQDN::NAMESERVERS {
                    let mut modified = 0;
                    for record in records {
                        if let Record::RRSIG(rrsig) = record {
                            if rrsig.fqdn == *leaf_fqdn {
                                let mut signature =
                                    BASE64_STANDARD.decode(&rrsig.signature).unwrap();
                                let last = signature.last_mut().expect("empty signature");
                                *last = !*last;

                                rrsig.signature = BASE64_STANDARD.encode(&signature);
                                modified += 1;
                            }
                        }
                    }

                    assert_eq!(modified, 1, "sanity check");
                }
            },
        },
    )?;

    let trust_anchor = graph.trust_anchor.as_ref().unwrap();
    let resolver = Resolver::new(&network, graph.root.clone())
        .trust_anchor(trust_anchor)
        .start()?;

    Ok((resolver, graph))
}

pub fn minimally_secure(
    leaf_fqdn: FQDN,
    leaf_ipv4_addr: Ipv4Addr,
) -> Result<(Resolver, Vec<NameServer<Running>>, TrustAnchor)> {
    assert_eq!(Some(FQDN::NAMESERVERS), leaf_fqdn.parent());

    let network = Network::new()?;

    let mut leaf_ns = NameServer::new(&dns_test::PEER, FQDN::NAMESERVERS, &network)?;
    leaf_ns.add(Record::a(leaf_fqdn.clone(), leaf_ipv4_addr));

    let Graph {
        nameservers,
        root,
        trust_anchor,
    } = Graph::build(
        leaf_ns,
        Sign::Yes {
            settings: SignSettings::default(),
        },
    )?;

    let trust_anchor = trust_anchor.unwrap();
    let resolver = Resolver::new(&network, root)
        .trust_anchor(&trust_anchor)
        .start()?;

    Ok((resolver, nameservers, trust_anchor))
}
