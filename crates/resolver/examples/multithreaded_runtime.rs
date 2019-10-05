#![recursion_limit = "128"]

//! This example shows how to create a resolver that uses the tokio multithreaded runtime. This is how
//! you might integrate the resolver into a more complex application.

extern crate env_logger;
extern crate futures;
extern crate tokio;
extern crate trust_dns_resolver;

use tokio::runtime::Runtime;
use trust_dns_resolver::AsyncResolver;

fn main() {
    env_logger::init();

    // Set up the standard tokio runtime (multithreaded by default).
    let runtime = Runtime::new().expect("Failed to create runtime");

    let (resolver, bg) = {
        // To make this independent, if targeting macOS, BSD, Linux, or Windows, we can use the system's configuration:
        #[cfg(any(unix, windows))]
        {
            // use the system resolver configuration
            AsyncResolver::from_system_conf().expect("Failed to create AsyncResolver")
        }

        // For other operating systems, we can use one of the preconfigured definitions
        #[cfg(not(any(unix, windows)))]
        {
            // Directly reference the config types
            use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

            // Get a new resolver with the google nameservers as the upstream recursive resolvers
            AsyncResolver::new(ResolverConfig::google(), ResolverOpts::default())
        }
    };

    // The resolver background task needs to be created in the runtime so it can
    // connect to the reactor.
    runtime.spawn(bg);

    // Create some futures representing name lookups.
    let names = &["www.google.com", "www.reddit.com", "www.wikipedia.org"];
    let mut futures = names
        .iter()
        .map(|name| (name, resolver.lookup_ip(*name)))
        .collect::<Vec<_>>();

    // Go through the list of resolution operations and wait for them to complete.
    for (name, lookup) in futures.drain(..) {
        let ips = runtime.block_on(lookup)
            .expect("Failed completing lookup future")
            .iter()
            .collect::<Vec<_>>();
        println!("{} resolved to {:?}", name, ips);
    }

    // Drop the resolver, which means that the runtime will become idle.
    drop(resolver);

    // Once we have finished using the runtime, we can ask it to shut down when it's done (this blocks).
    runtime.shutdown_on_idle();
}
