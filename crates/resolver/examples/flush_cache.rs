use hickory_resolver::{Resolver, net::runtime::TokioRuntimeProvider, proto::rr::RData};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    tokio_main().await;
}

async fn tokio_main() {
    // use the system resolver configuration
    let resolver = Resolver::builder_tokio()
        .expect("failed to create resolver")
        .build()
        .unwrap();

    // Create some futures representing name lookups.
    let names = ["hickory-dns.org.", "estada.ch.", "wikipedia.org."];

    let first_resolve = resolve_list(&names, &resolver).await;
    let cached_resolve = resolve_list(&names, &resolver).await;

    resolver.clear_cache();
    let second_resolve = resolve_list(&names, &resolver).await;

    println!("first_resolve: {first_resolve:?}");
    println!("cached_resolve: {cached_resolve:?}");
    println!("second_resolve: {second_resolve:?}");

    // Drop the resolver, which means that the runtime will become idle.
    drop(resolver);
}

async fn resolve_list(
    names: &[&str],
    resolver: &Resolver<TokioRuntimeProvider>,
) -> tokio::time::Duration {
    use tokio::time::Instant;
    let start_time = Instant::now();

    // Create the resolve requests first
    let futures = names
        .iter()
        .map(|name: &&str| {
            let name = name.to_string();
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
        let txts = lookup
            .await
            .expect("unable to spawn resolver")
            .map(|lookup| {
                lookup
                    .answers()
                    .iter()
                    .filter_map(|record| match record.data() {
                        RData::TXT(txt) => Some(txt.to_string()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            });
        println!("  {name} returned to {txts:?}");
    }
    println!();
    start_time.elapsed()
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_flush_cache() {
        test_support::subscribe();
        super::tokio_main().await;
    }
}
