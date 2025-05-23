#![recursion_limit = "128"]

use std::{fmt::Display, future::pending, io, net::IpAddr};

use hickory_resolver::{
    IntoName, TokioResolver, config::ResolverConfig, name_server::TokioConnectionProvider,
};
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
        let resolver = TokioResolver::builder_with_config(
            ResolverConfig::mdns(),
            TokioConnectionProvider::default(),
        )
        .build();

        let (lock, cvar) = &*pair2;
        let mut started = lock.lock().unwrap();

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
pub async fn resolve<N: IntoName + Display + 'static>(host: N) -> io::Result<Vec<IpAddr>> {
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
            lookup_ip.iter().map(|ip| ip).collect::<Vec<_>>()
        })
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    run().await;
}

async fn run() {
    // Let's resolve some names, we should be able to do it across threads
    let names = ["openwrt.local"];

    for name in names.into_iter() {
        let result = resolve(name).await;
        // print the resolved IPs
        println!("{name} resolved to {result:?}");
    }
}

#[tokio::test]
async fn test_global_resolver() {
    test_support::subscribe();
    run().await
}
