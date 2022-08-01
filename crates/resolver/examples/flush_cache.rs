#![recursion_limit = "128"]

#[cfg(feature = "tokio-runtime")]
fn main() {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio_main().await;
        });
}

#[cfg(feature = "tokio-runtime")]
async fn tokio_main() {
    use trust_dns_resolver::{TokioAsyncResolver, TokioHandle};

    let resolver = {
        // To make this independent, if targeting macOS, BSD, Linux, or Windows, we can use the system's configuration:
        #[cfg(any(unix, windows))]
        {
            // use the system resolver configuration
            TokioAsyncResolver::from_system_conf(TokioHandle)
        }

        // For other operating systems, we can use one of the preconfigured definitions
        #[cfg(not(any(unix, windows)))]
        {
            // Directly reference the config types
            use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

            // Get a new resolver with the google nameservers as the upstream recursive resolvers
            AsyncResolver::tokio(
                ResolverConfig::quad9(),
                ResolverOpts::default(),
                //runtime.handle().clone(),
            )
        }
    }
    .map(std::sync::Arc::new)
    .expect("failed to create resolver");

    // Create some futures representing name lookups.
    let names = ["trust-dns.org.", "estada.ch.", "wikipedia.org."];

    let first_resolve = resolve_list(&names, &*resolver).await;
    let cached_resolve = resolve_list(&names, &*resolver).await;

    resolver.clear_cache();
    let second_resolve = resolve_list(&names, &*resolver).await;

    println!("first_resolve: {first_resolve:?}");
    println!("cached_resolve: {cached_resolve:?}");
    println!("second_resolve: {second_resolve:?}");

    // Drop the resolver, which means that the runtime will become idle.
    drop(resolver);
}

#[cfg(feature = "tokio-runtime")]
async fn resolve_list<
    C: trust_dns_proto::DnsHandle<Error = trust_dns_resolver::error::ResolveError>,
    P: trust_dns_resolver::ConnectionProvider<Conn = C>,
>(
    names: &[&str],
    resolver: &trust_dns_resolver::AsyncResolver<C, P>,
) -> tokio::time::Duration {
    use tokio::time::Instant;
    let start_time = Instant::now();

    // Create the resolve requests first
    let futures = names
        .iter()
        .map(|name: &&str| {
            let name: String = name.to_string();
            let resolver = resolver.clone();
            let future = {
                let name = name.clone();
                tokio::spawn(async move { resolver.txt_lookup(name).await })
            };
            (name, future)
        })
        .collect::<Vec<_>>();

    // Go through the list of resolution operations in parallel and wait for them to complete.
    for (name, lookup) in futures {
        let txts = lookup.await.expect("unable to spawn resolver").map(|txt| {
            txt.iter()
                .map(|rdata| rdata.to_string())
                .collect::<Vec<_>>()
        });
        println!("  {} returned to {:?}", name, txts);
    }
    println!();
    start_time.elapsed()
}

#[cfg(not(feature = "tokio-runtime"))]
fn main() {
    println!("tokio-runtime feature must be enabled")
}
