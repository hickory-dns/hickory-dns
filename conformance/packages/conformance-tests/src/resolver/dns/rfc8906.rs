use dns_test::{
    FQDN, Network, Resolver, Result,
    client::Client,
    name_server::{Graph, NameServer},
    zone_file::SignSettings,
};

mod basic;
mod extended;

fn setup() -> Result<(Network, Graph, Resolver, Client)> {
    let network = Network::new()?;
    let leaf_ns = NameServer::new(&dns_test::PEER, FQDN::TEST_DOMAIN, &network)?;
    let graph = Graph::build(
        leaf_ns,
        dns_test::name_server::Sign::Yes {
            settings: SignSettings::default(),
        },
    )?;
    let resolver = Resolver::new(&network, graph.root.clone()).start()?;
    let client = Client::new(&network)?;
    Ok((network, graph, resolver, client))
}
