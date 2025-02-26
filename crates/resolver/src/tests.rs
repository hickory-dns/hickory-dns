#[cfg(feature = "tokio")]
use test_support::subscribe;

// Keep this in sync with the example in the README.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn readme_example() {
    subscribe();

    use crate::Resolver;
    use crate::config::*;
    use crate::name_server::TokioConnectionProvider;

    // Construct a new Resolver with default configuration options
    let resolver = Resolver::new(
        ResolverConfig::default(),
        ResolverOpts::default(),
        TokioConnectionProvider::default(),
    );

    // On Unix/Posix systems, this will read the /etc/resolv.conf
    // let resolver = Resolver::from_system_conf(TokioConnectionProvider::default()).unwrap();

    // Lookup the IP addresses associated with a name.
    let response = resolver.lookup_ip("www.example.com.").await.unwrap();

    // There can be many addresses associated with the name,
    //  this can return IPv4 and/or IPv6 addresses
    let _address = response.iter().next().expect("no addresses returned!");
}

// Keep this in sync with the example in the README.
#[cfg(feature = "__tls")]
#[test]
fn readme_tls() {
    use crate::Resolver;
    use crate::config::*;
    use crate::name_server::TokioConnectionProvider;

    // Construct a new Resolver with default configuration options
    let resolver = Resolver::new(
        ResolverConfig::cloudflare_tls(),
        ResolverOpts::default(),
        TokioConnectionProvider::default(),
    );

    let _ = resolver;
}
