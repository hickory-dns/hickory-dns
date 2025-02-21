#![recursion_limit = "128"]

use std::{fmt::Display, future::pending, io, net::SocketAddr};

use hickory_resolver::{IntoName, TokioResolver, name_server::TokioConnectionProvider};
use once_cell::sync::Lazy;

// This is an example of registering a static global resolver into any system.
//
// We may want to create a GlobalResolver as part of the Resolver library
//   in the mean time, this example has the necessary steps to do so.
//
// Thank you to @zonyitoo for the original example.
// TODO: this example can probably be made much simpler with `Resolver`.
// First we need to setup the global Resolver
static GLOBAL_DNS_RESOLVER: Lazy<TokioResolver> = Lazy::new(|| {
    use std::sync::{Arc, Condvar, Mutex};
    use std::thread;

    // We'll be using this condvar to get the Resolver from the thread...
    let pair = Arc::new((Mutex::new(None::<TokioResolver>), Condvar::new()));
    let pair2 = pair.clone();

    // Spawn the runtime to a new thread...
    //
    // This thread will manage the actual resolution runtime
    thread::spawn(move || {
        // A runtime for this new thread
        let runtime = tokio::runtime::Runtime::new().expect("failed to launch Runtime");

        // our platform independent future, result, see next blocks
        let resolver = {
            // To make this independent, if targeting macOS, BSD, Linux, or Windows, we can use the system's configuration:
            #[cfg(any(unix, windows))]
            {
                // use the system resolver configuration
                TokioResolver::from_system_conf(TokioConnectionProvider::default())
            }

            // For other operating systems, we can use one of the preconfigured definitions
            #[cfg(not(any(unix, windows)))]
            {
                // Directly reference the config types
                use hickory_resolver::config::{ResolverConfig, ResolverOpts};

                // Get a new resolver with the google nameservers as the upstream recursive resolvers
                TokioResolver::new(
                    ResolverConfig::google(),
                    ResolverOpts::default(),
                    runtime.handle().clone(),
                )
            }
        };

        let (lock, cvar) = &*pair2;
        let mut started = lock.lock().unwrap();

        let resolver = resolver.expect("failed to create hickory-resolver");

        *started = Some(resolver);
        cvar.notify_one();
        drop(started);

        runtime.block_on(pending::<()>())
    });

    // Wait for the thread to start up.
    let (lock, cvar) = &*pair;
    let mut resolver = lock.lock().unwrap();
    while resolver.is_none() {
        resolver = cvar.wait(resolver).unwrap();
    }

    // take the started resolver
    let resolver = resolver.take();

    // set the global resolver
    resolver.expect("resolver should not be none")
});

/// Provide a general purpose resolution function.
///
/// This looks up the `host` (a `&str` or `String` is good), and combines that with the provided port
///   this mimics the lookup functions of `std::net`.
pub async fn resolve<N: IntoName + Display + 'static>(
    host: N,
    port: u16,
) -> io::Result<Vec<SocketAddr>> {
    // Now we use the global resolver to perform a lookup_ip.
    let name = host.to_string();
    let result = GLOBAL_DNS_RESOLVER.lookup_ip(host).await;
    // map the result into what we want...
    result
        .map_err(move |err| {
            // we transform the error into a standard IO error for convenience
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("dns resolution error for {name}: {err}"),
            )
        })
        .map(move |lookup_ip| {
            // we take all the IPs returned, and then send back the set of IPs
            lookup_ip
                .iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect::<Vec<_>>()
        })
}

fn main() {
    tracing_subscriber::fmt::init();
    run();
}

fn run() {
    use std::thread;

    // Let's resolve some names, we should be able to do it across threads
    let names = &["www.google.com", "www.reddit.com", "www.wikipedia.org"];

    // spawn all the threads to do the lookups
    let threads = names
        .iter()
        .map(|name| {
            let join = thread::spawn(move || {
                let runtime = tokio::runtime::Runtime::new().expect("failed to launch Runtime");
                runtime.block_on(resolve(*name, 443))
            });

            (name, join)
        })
        .collect::<Vec<_>>();

    // print the resolved IPs
    for (name, join) in threads {
        let result = join
            .join()
            .expect("resolution thread failed")
            .expect("resolution failed");
        println!("{name} resolved to {result:?}");
    }
}

#[test]
fn test_global_resolver() {
    test_support::subscribe();
    run()
}
