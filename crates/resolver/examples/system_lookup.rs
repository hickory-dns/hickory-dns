//! Compare a system-configured resolver with an explicit DNS configuration.

use hickory_resolver::{Resolver, net::runtime::TokioRuntimeProvider, system_conf};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::args().nth(1).ok_or("provide a hostname")?;
    let (mut config, options) = system_conf::read_system_conf()?;
    println!("System name servers: {:?}", config.name_servers);
    let routes = std::mem::take(&mut config.domain_routes);
    let explicit =
        Resolver::builder_with_config(config.clone(), TokioRuntimeProvider::default()).build()?;
    config.domain_routes = routes;
    let mut builder = Resolver::builder_with_config(config, TokioRuntimeProvider::default());
    *builder.options_mut() = options;
    let system = builder.build()?;
    for (label, resolver) in [("explicit", explicit), ("system", system)] {
        match resolver.lookup_ip(host.as_str()).await {
            Ok(lookup) => println!("{label}: {:?}", lookup.iter().collect::<Vec<_>>()),
            Err(error) => println!("{label}: {error}"),
        }
    }
    Ok(())
}
