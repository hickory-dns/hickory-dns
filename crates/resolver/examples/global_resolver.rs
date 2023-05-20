#![recursion_limit = "128"]

#[cfg(all(feature = "tokio-runtime", feature = "system-config"))]
use {
    futures_util::future,
    once_cell::sync::Lazy,
    std::fmt::Display,
    std::io,
    std::net::SocketAddr,
    std::task::Poll,
    trust_dns_resolver::name_server::TokioConnectionProvider,
    trust_dns_resolver::TokioAsyncResolver,
    trust_dns_resolver::{IntoName, TryParseIp},
};

// This is an example of registering a static global resolver into any system.
//
// We may want to create a GlobalResolver as part of the Resolver library
//   in the mean time, this example has the necessary steps to do so.
//
// Thank you to @zonyitoo for the original example.
// TODO: this example can probably be made much simpler with the new
//      `AsyncResolver`.
#[cfg(all(feature = "tokio-runtime", feature = "system-config"))]
// First we need to setup the global Resolver
static GLOBAL_DNS_RESOLVER: Lazy<TokioAsyncResolver> = Lazy::new(|| {
    use std::sync::{Arc, Condvar, Mutex};
    use std::thread;

    // We'll be using this condvar to get the Resolver from the thread...
    let pair = Arc::new((Mutex::new(None::<TokioAsyncResolver>), Condvar::new()));
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
                TokioAsyncResolver::from_system_conf(TokioConnectionProvider::default())
            }

            // For other operating systems, we can use one of the preconfigured definitions
            #[cfg(not(any(unix, windows)))]
            {
                // Directly reference the config types
                use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

                // Get a new resolver with the google nameservers as the upstream recursive resolvers
                TokioAsyncResolver::new(
                    ResolverConfig::google(),
                    ResolverOpts::default(),
                    runtime.handle().clone(),
                )
            }
        };

        let (lock, cvar) = &*pair2;
        let mut started = lock.lock().unwrap();

        let resolver = resolver.expect("failed to create trust-dns-resolver");

        *started = Some(resolver);
        cvar.notify_one();
        drop(started);

        runtime.block_on(future::poll_fn(|_cx| Poll::<()>::Pending))
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
#[cfg(all(feature = "tokio-runtime", feature = "system-config"))]
#[cfg_attr(
    docsrs,
    doc(cfg(all(feature = "tokio-runtime", feature = "system-config")))
)]
pub async fn resolve<N: IntoName + Display + TryParseIp + 'static>(
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

#[cfg(all(feature = "tokio-runtime", feature = "system-config"))]
fn main() {
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

#[cfg(not(all(feature = "tokio-runtime", feature = "system-config")))]
fn main() {
    println!("tokio-runtime and system-config feature must be enabled")
}

#[test]
fn test_global_resolver() {
    main()
}
