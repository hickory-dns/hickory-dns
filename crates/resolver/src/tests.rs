// Keep this in sync with the example in the README.
#[cfg(feature = "tokio-runtime")]
#[tokio::test]
async fn readme_example() {
    use std::net::*;

    use crate::config::*;
    use crate::name_server::TokioConnectionProvider;
    use crate::Resolver;

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
    let address = response.iter().next().expect("no addresses returned!");
    if address.is_ipv4() {
        assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)));
    } else {
        assert_eq!(
            address,
            IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c
            ))
        );
    }
}

// Keep this in sync with the example in the README.
#[cfg(all(feature = "tokio-runtime", feature = "dns-over-tls"))]
#[test]
fn readme_tls() {
    use crate::config::*;
    use crate::name_server::TokioConnectionProvider;
    use crate::Resolver;

    // Construct a new Resolver with default configuration options
    let resolver = Resolver::new(
        ResolverConfig::cloudflare_tls(),
        ResolverOpts::default(),
        TokioConnectionProvider::default(),
    );

    let _ = resolver;
}
