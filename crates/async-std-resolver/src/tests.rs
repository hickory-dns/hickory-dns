#![allow(clippy::extra_unused_type_parameters)]

use hickory_resolver::name_server::GenericConnection;
use hickory_resolver::testing;

use crate::config::{ResolverConfig, ResolverOpts};
use crate::lookup::LookupFuture;
use crate::lookup_ip::LookupIpFuture;
use crate::proto::xfer::DnsRequest;
use crate::proto::Executor;
use crate::runtime::AsyncStdConnectionProvider;
use crate::AsyncStdResolver;

fn is_send_t<T: Send>() -> bool {
    true
}

fn is_sync_t<T: Sync>() -> bool {
    true
}

#[test]
fn test_send_sync() {
    assert!(is_send_t::<ResolverConfig>());
    assert!(is_sync_t::<ResolverConfig>());
    assert!(is_send_t::<ResolverOpts>());
    assert!(is_sync_t::<ResolverOpts>());

    assert!(is_send_t::<AsyncStdResolver>());
    assert!(is_sync_t::<AsyncStdResolver>());

    assert!(is_send_t::<DnsRequest>());
    assert!(is_send_t::<LookupIpFuture<GenericConnection>>());
    assert!(is_send_t::<LookupFuture<GenericConnection>>());
}

#[test]
fn test_lookup_google() {
    use testing::lookup_test;
    let io_loop = AsyncStdConnectionProvider::new();

    lookup_test::<AsyncStdConnectionProvider, AsyncStdConnectionProvider>(
        ResolverConfig::google(),
        io_loop.clone(),
        io_loop,
    )
}

#[test]
fn test_lookup_cloudflare() {
    use testing::lookup_test;
    let io_loop = AsyncStdConnectionProvider::new();
    lookup_test::<AsyncStdConnectionProvider, AsyncStdConnectionProvider>(
        ResolverConfig::cloudflare(),
        io_loop.clone(),
        io_loop,
    )
}

#[test]
fn test_lookup_quad9() {
    use testing::lookup_test;
    let io_loop = AsyncStdConnectionProvider::new();
    lookup_test::<AsyncStdConnectionProvider, AsyncStdConnectionProvider>(
        ResolverConfig::quad9(),
        io_loop.clone(),
        io_loop,
    )
}

#[test]
fn test_ip_lookup() {
    use testing::ip_lookup_test;
    let io_loop = AsyncStdConnectionProvider::new();
    ip_lookup_test::<AsyncStdConnectionProvider, AsyncStdConnectionProvider>(
        io_loop.clone(),
        io_loop,
    )
}

#[test]
fn test_ip_lookup_across_threads() {
    use testing::ip_lookup_across_threads_test;
    let io_loop = AsyncStdConnectionProvider::new();
    ip_lookup_across_threads_test::<AsyncStdConnectionProvider, AsyncStdConnectionProvider>(io_loop)
}

#[test]
#[cfg(feature = "dnssec")]
fn test_sec_lookup() {
    use testing::sec_lookup_test;
    let io_loop = AsyncStdConnectionProvider::new();
    sec_lookup_test::<AsyncStdConnectionProvider, AsyncStdConnectionProvider>(
        io_loop.clone(),
        io_loop,
    );
}

#[test]
#[cfg(feature = "dnssec")]
fn test_sec_lookup_fails() {
    use testing::sec_lookup_fails_test;
    let io_loop = AsyncStdConnectionProvider::new();
    sec_lookup_fails_test::<AsyncStdConnectionProvider, AsyncStdConnectionProvider>(
        io_loop.clone(),
        io_loop,
    );
}

#[test]
#[ignore]
#[cfg(any(unix, target_os = "windows"))]
#[cfg(feature = "system-config")]
fn test_system_lookup() {
    use testing::system_lookup_test;
    let io_loop = AsyncStdConnectionProvider::new();
    system_lookup_test::<AsyncStdConnectionProvider, AsyncStdConnectionProvider>(
        io_loop.clone(),
        io_loop,
    );
}

#[test]
#[ignore]
#[cfg(feature = "system-config")]
// these appear to not work on CI, test on macos with `10.1.0.104  a.com`
#[cfg(unix)]
fn test_hosts_lookup() {
    use testing::hosts_lookup_test;
    let io_loop = AsyncStdConnectionProvider::new();
    hosts_lookup_test::<AsyncStdConnectionProvider, AsyncStdConnectionProvider>(
        io_loop.clone(),
        io_loop,
    );
}

#[test]
fn test_fqdn() {
    use testing::fqdn_test;
    let io_loop = AsyncStdConnectionProvider::new();
    fqdn_test::<AsyncStdConnectionProvider, AsyncStdConnectionProvider>(io_loop.clone(), io_loop);
}

#[test]
fn test_ndots() {
    use testing::ndots_test;
    let io_loop = AsyncStdConnectionProvider::new();
    ndots_test::<AsyncStdConnectionProvider, AsyncStdConnectionProvider>(io_loop.clone(), io_loop);
}

#[test]
fn test_large_ndots() {
    use testing::large_ndots_test;
    let io_loop = AsyncStdConnectionProvider::new();
    large_ndots_test::<AsyncStdConnectionProvider, AsyncStdConnectionProvider>(
        io_loop.clone(),
        io_loop,
    );
}

#[test]
fn test_domain_search() {
    use testing::domain_search_test;
    let io_loop = AsyncStdConnectionProvider::new();
    domain_search_test::<AsyncStdConnectionProvider, AsyncStdConnectionProvider>(
        io_loop.clone(),
        io_loop,
    );
}

#[test]
fn test_search_list() {
    use testing::search_list_test;
    let io_loop = AsyncStdConnectionProvider::new();
    search_list_test::<AsyncStdConnectionProvider, AsyncStdConnectionProvider>(
        io_loop.clone(),
        io_loop,
    );
}

#[test]
fn test_idna() {
    use testing::idna_test;
    let io_loop = AsyncStdConnectionProvider::new();
    idna_test::<AsyncStdConnectionProvider, AsyncStdConnectionProvider>(io_loop.clone(), io_loop);
}

#[test]
fn test_localhost_ipv4() {
    use testing::localhost_ipv4_test;
    let io_loop = AsyncStdConnectionProvider::new();

    localhost_ipv4_test::<AsyncStdConnectionProvider, AsyncStdConnectionProvider>(
        io_loop.clone(),
        io_loop,
    );
}

#[test]
fn test_localhost_ipv6() {
    use testing::localhost_ipv6_test;
    let io_loop = AsyncStdConnectionProvider::new();

    localhost_ipv6_test::<AsyncStdConnectionProvider, AsyncStdConnectionProvider>(
        io_loop.clone(),
        io_loop,
    );
}

#[test]
fn test_search_ipv4_large_ndots() {
    use testing::search_ipv4_large_ndots_test;
    let io_loop = AsyncStdConnectionProvider::new();

    search_ipv4_large_ndots_test::<AsyncStdConnectionProvider, AsyncStdConnectionProvider>(
        io_loop.clone(),
        io_loop,
    );
}

#[test]
fn test_search_ipv6_large_ndots() {
    use testing::search_ipv6_large_ndots_test;
    let io_loop = AsyncStdConnectionProvider::new();

    search_ipv6_large_ndots_test::<AsyncStdConnectionProvider, AsyncStdConnectionProvider>(
        io_loop.clone(),
        io_loop,
    );
}

#[test]
fn test_search_ipv6_name_parse_fails() {
    use testing::search_ipv6_name_parse_fails_test;
    let io_loop = AsyncStdConnectionProvider::new();

    search_ipv6_name_parse_fails_test::<AsyncStdConnectionProvider, AsyncStdConnectionProvider>(
        io_loop.clone(),
        io_loop,
    );
}
