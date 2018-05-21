//! This example shows how to create a resolver that uses the tokio multithreaded runtime. This is how
//! you might integrate the resolver into a more complex application.

extern crate futures;
extern crate tokio;
extern crate trust_dns_resolver;

use futures::Future;
use futures::sync::oneshot::channel;
use tokio::runtime::Runtime;
use trust_dns_resolver::ResolverFuture;
use trust_dns_resolver::error::ResolveError;

fn main() {
    // Set up the standard tokio runtime (multithreaded by default).
    let mut runtime = Runtime::new().expect("Failed to create runtime");

    let future;
    // To make this independent, if targeting macOS, BSD, Linux, or Windows, we can use the system's configuration:
    #[cfg(any(unix, windows))]
    {
        future = ResolverFuture::from_system_conf().expect("Failed to create ResolverFuture");
    }
    // For other operating systems, we can use one of the preconfigured definitions
    #[cfg(not(any(unix, windows)))]
    {
        use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
        future = ResolverFuture::new(ResolverConfig::google(), ResolverOpts::default());
    }

    // The resolver needs to be created in the runtime so it can connect to the reactor. The tokio multithreaded
    // runtime doesn't provide a mechanism to return the result of future out of the reactor. Create a oneshot
    // channel that can be used to send the created resolver out.
    let (sender, receiver) = channel::<Result<ResolverFuture, ResolveError>>();
    runtime.spawn(future.then(|result| {
        sender
            .send(result)
            .map_err(|_| println!("Failed to send resolver"))
    }));
    // Once the resolver is created, we can ask the runtime to shut down when it's done.
    let shutdown = runtime.shutdown_on_idle();
    // Wait unti the resolver has been created and fetch it from the oneshot channel.
    let resolver = receiver
        .wait()
        .expect("Failed to retrieve resolver")
        .expect("Failed to create resolver");

    // Create some futures representing name lookups.
    let names = &["www.google.com", "www.reddit.com", "www.wikipedia.org"];
    let mut futures = names
        .iter()
        .map(|name| (name, resolver.lookup_ip(*name)))
        .collect::<Vec<_>>();

    // Go through the list of resolution operations and wait for them to complete.
    for (name, lookup) in futures.drain(..) {
        let ips = lookup
            .wait()
            .expect("Failed completing lookup future")
            .iter()
            .collect::<Vec<_>>();
        println!("{} resolved to {:?}", name, ips);
    }

    // Drop the resolver, which means that the runtime will become idle.
    drop(resolver);

    // Wait for the runtime to complete shutting down.
    shutdown.wait().expect("Failed when shutting down runtime");
}
