#![recursion_limit = "128"]

use std::sync::Arc;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    tokio_main().await;
}

async fn tokio_main() {
    let resolver = {
        // To make this independent, if targeting macOS, BSD, Linux, or Windows, we can use the system's configuration:
        #[cfg(any(unix, windows))]
        {
            use hickory_resolver::{TokioResolver, name_server::TokioConnectionProvider};

            // use the system resolver configuration
            TokioResolver::from_system_conf(TokioConnectionProvider::default())
                .map(Arc::new)
                .expect("failed to create resolver")
        }

        // For other operating systems, we can use one of the preconfigured definitions
        #[cfg(not(any(unix, windows)))]
        {
            // Directly reference the config types
            use hickory_resolver::{
                Resolver,
                config::{ResolverConfig, ResolverOpts},
            };

            // Get a new resolver with the google nameservers as the upstream recursive resolvers
            Arc::new(Resolver::tokio(
                ResolverConfig::quad9(),
                ResolverOpts::default(),
            ))
        }
    };

    // Create some futures representing name lookups.
    let names = ["hickory-dns.org.", "estada.ch.", "wikipedia.org."];

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

async fn resolve_list<P: hickory_resolver::name_server::ConnectionProvider>(
    names: &[&str],
    resolver: &hickory_resolver::Resolver<P>,
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
        println!("  {name} returned to {txts:?}");
    }
    println!();
    start_time.elapsed()
}

#[tokio::test]
async fn test_flush_cache() {
    test_support::subscribe();
    tokio_main().await;
}
