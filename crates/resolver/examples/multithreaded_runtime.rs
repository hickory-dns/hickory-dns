#![recursion_limit = "128"]

//! This example shows how to create a resolver that uses the tokio multithreaded runtime. This is how
//! you might integrate the resolver into a more complex application.

fn main() {
    use hickory_resolver::{name_server::TokioConnectionProvider, TokioAsyncResolver};
    use tokio::runtime::Runtime;

    tracing_subscriber::fmt::init();

    // Set up the standard tokio runtime (multithreaded by default).
    let runtime = Runtime::new().expect("Failed to create runtime");

    let resolver = {
        // To make this independent, if targeting macOS, BSD, Linux, or Windows, we can use the system's configuration:
        #[cfg(any(unix, windows))]
        {
            // use the system resolver configuration
            TokioAsyncResolver::from_system_conf(TokioConnectionProvider::default())
        }

        // For other operating systems, we can use one of the preconfigured definitions
        #[cfg(not(any(unix, windows)))]
        {
            // Directly reference the config types
            use hickory_resolver::config::{ResolverConfig, ResolverOpts};

            // Get a new resolver with the google nameservers as the upstream recursive resolvers
            AsyncResolver::new(
                ResolverConfig::google(),
                ResolverOpts::default(),
                runtime.handle().clone(),
            )
        }
    }
    .expect("failed to create resolver");

    // Create some futures representing name lookups.
    let names = &["www.google.com", "www.reddit.com", "www.wikipedia.org"];
    let mut futures = names
        .iter()
        .map(|name| (name, resolver.lookup_ip(*name)))
        .collect::<Vec<_>>();

    // Go through the list of resolution operations and wait for them to complete.
    for (name, lookup) in futures.drain(..) {
        let ips = runtime
            .block_on(lookup)
            .expect("Failed completing lookup future")
            .iter()
            .collect::<Vec<_>>();
        println!("{name} resolved to {ips:?}");
    }

    // Drop the resolver, which means that the runtime will become idle.
    drop(futures);
    drop(resolver);
}

#[test]
fn test_multithreaded_runtime() {
    main()
}
