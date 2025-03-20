use dns_test::{
    FQDN, Network, Result,
    client::Client,
    name_server::{NameServer, Running},
    zone_file::SignSettings,
};

mod basic;
mod extended;

fn setup() -> Result<(Network, NameServer<Running>, Client)> {
    setup_with_sign_settings(SignSettings::default())
}

fn setup_with_sign_settings(
    settings: SignSettings,
) -> Result<(Network, NameServer<Running>, Client)> {
    let network = Network::new()?;
    let ns = NameServer::new(&dns_test::SUBJECT, FQDN::TEST_DOMAIN, &network)?;
    let ns = ns.sign(settings)?;
    let ns = ns.start()?;
    let client = Client::new(&network)?;
    Ok((network, ns, client))
}
