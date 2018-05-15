#[macro_use]
extern crate lazy_static;
extern crate futures;
extern crate tokio;
extern crate tokio_io;
extern crate trust_dns_resolver;

use std::io;
use std::net::SocketAddr;

use futures::Future;
use tokio_io::IoFuture;
use trust_dns_resolver::{IntoName, ResolverFuture, TryParseIp};

// This is an example of registering a static global resolver into any system.
//
// We may want to create a GlobalResolver as part of the Resolver library
//   in the mean time, this example has the necessary steps to do so.
//
// Thank you to @zonyitoo for the original example.

lazy_static! {
    // First we need to setup the global Resolver
    static ref GLOBAL_DNS_RESOLVER: ResolverFuture = {
        use std::sync::{Arc, Mutex, Condvar};
        use std::thread;

        // We'll be using this condvar to get the Resolver from the thread...
        let pair = Arc::new((Mutex::new(None::<ResolverFuture>), Condvar::new()));
        let pair2 = pair.clone();


        // Spawn the runtime to a new thread...
        //
        // This thread will manage the actual resolution runtime
        thread::spawn(move || {
            // A runtime for this new thread
            let mut runtime = tokio::runtime::current_thread::Runtime::new().expect("failed to launch Runtime");

            // our platform independent future, result, see next blocks
            let future;

            // To make this independent, if targeting macOS, BSD, Linux, or Windows, we can use the system's configuration:
            #[cfg(any(unix, windows))]
            {
                // use the system resolver configuration
                future = ResolverFuture::from_system_conf().expect("Failed to create ResolverFuture");
            }

            // For other operating systems, we can use one of the preconfigured definitions
            #[cfg(not(any(unix, windows)))]
            {
                // Directly reference the config types
                use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

                // Get a new resolver with the google nameservers as the upstream recursive resolvers
                future = ResolverFuture::new(ResolverConfig::google(), ResolverOpts::default());
            }

            // this will block the thread until the Resolver is constructed with the above configuration
            let resolver = runtime.block_on(future).expect("Failed to create DNS resolver");

            let &(ref lock, ref cvar) = &*pair2;
            let mut started = lock.lock().unwrap();
            *started = Some(resolver);
            cvar.notify_one();
            drop(started);

            runtime.run().expect("Resolver Thread shutdown!");
        });

        // Wait for the thread to start up.
        let &(ref lock, ref cvar) = &*pair;
        let mut resolver = lock.lock().unwrap();
        while resolver.is_none() {
            resolver = cvar.wait(resolver).unwrap();
        }

        // take the started resolver
        let resolver = std::mem::replace(&mut *resolver, None);

        // set the global resolver
        resolver.expect("resolver should not be none")
    };
}

/// Provide a general purpose resolution function.
///
/// This looks up the `host` (a &str or String is good), and combines that with the provided port
///   this mimics the lookup functions of std::net.
pub fn resolve<N: IntoName + TryParseIp>(host: N, port: u16) -> IoFuture<Vec<SocketAddr>> {
    // Now we use the global resolver to perform a lookup_ip.
    let resolve_future = GLOBAL_DNS_RESOLVER.lookup_ip(host).then(move |result| {
        // map the result into what we want...
        result
            .map_err(move |err| {
                // we transform the error into a standard IO error for convenience
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("dns resolution error: {}", err),
                )
            })
            .map(move |lookup_ip| {
                // we take all the IPs returned, and then send back the set of IPs
                lookup_ip
                    .iter()
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect::<Vec<_>>()
            })
    });

    // Now return the boxed future
    Box::new(resolve_future)
}

fn main() {
    use std::thread;

    // Let's resolve some names, we should be able to do it across threads
    let names = &["www.google.com", "www.reddit.com", "www.wikipedia.org"];

    // spawn all the threads to do the lookups
    let threads = names
        .iter()
        .map(|name| {
            let join = thread::spawn(move || {
                let mut runtime = tokio::runtime::current_thread::Runtime::new()
                    .expect("failed to launch Runtime");
                runtime.block_on(resolve(*name, 443))
            });

            (name, join)
        })
        .collect::<Vec<_>>();

    // print the resolved IPs
    for (name, join) in threads {
        let result = join.join().expect(&format!("error resolving: {}", name));
        println!("{} resolved to {:?}", name, result);
    }
}
