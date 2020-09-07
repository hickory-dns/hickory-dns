use trust_dns_resolver::testing;

use crate::config::{ResolverConfig, ResolverOpts};
use crate::lookup::LookupFuture;
use crate::lookup_ip::LookupIpFuture;
use crate::proto::xfer::DnsRequest;
use crate::proto::Executor;
use crate::runtime::{AsyncStdConnection, AsyncStdRuntime};
use crate::AsyncStdResolver;
use crate::ResolveError;

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
    assert!(is_send_t::<LookupIpFuture<AsyncStdConnection, ResolveError>>());
    assert!(is_send_t::<LookupFuture<AsyncStdConnection, ResolveError>>());
}

#[test]
fn test_lookup_google() {
    use testing::lookup_test;
    let io_loop = AsyncStdRuntime::new();
    let handle = io_loop.handle();
    lookup_test::<AsyncStdRuntime, AsyncStdRuntime>(ResolverConfig::google(), io_loop, handle)
}

#[test]
fn test_lookup_cloudflare() {
    use testing::lookup_test;
    let io_loop = AsyncStdRuntime::new();
    let handle = io_loop.handle();
    lookup_test::<AsyncStdRuntime, AsyncStdRuntime>(ResolverConfig::cloudflare(), io_loop, handle)
}

#[test]
fn test_lookup_quad9() {
    use testing::lookup_test;
    let io_loop = AsyncStdRuntime::new();
    let handle = io_loop.handle();
    lookup_test::<AsyncStdRuntime, AsyncStdRuntime>(ResolverConfig::quad9(), io_loop, handle)
}

#[test]
fn test_ip_lookup() {
    use testing::ip_lookup_test;
    let io_loop = AsyncStdRuntime::new();
    let handle = io_loop.handle();
    ip_lookup_test::<AsyncStdRuntime, AsyncStdRuntime>(io_loop, handle)
}

#[test]
fn test_ip_lookup_across_threads() {
    use testing::ip_lookup_across_threads_test;
    let io_loop = AsyncStdRuntime::new();
    let handle = io_loop.handle();
    ip_lookup_across_threads_test::<AsyncStdRuntime, AsyncStdRuntime>(handle)
}

#[test]
#[cfg(feature = "dnssec")]
fn test_sec_lookup() {
    use testing::sec_lookup_test;
    let io_loop = AsyncStdRuntime::new();
    let handle = io_loop.handle();
    sec_lookup_test::<AsyncStdRuntime, AsyncStdRuntime>(io_loop, handle);
}

#[test]
#[cfg(feature = "dnssec")]
fn test_sec_lookup_fails() {
    use testing::sec_lookup_fails_test;
    let io_loop = AsyncStdRuntime::new();
    let handle = io_loop.handle();
    sec_lookup_fails_test::<AsyncStdRuntime, AsyncStdRuntime>(io_loop, handle);
}

#[test]
#[ignore]
#[cfg(any(unix, target_os = "windows"))]
#[cfg(feature = "system-config")]
fn test_system_lookup() {
    use testing::system_lookup_test;
    let io_loop = AsyncStdRuntime::new();
    let handle = io_loop.handle();
    system_lookup_test::<AsyncStdRuntime, AsyncStdRuntime>(io_loop, handle);
}

#[test]
#[ignore]
#[cfg(feature = "system-config")]
// these appear to not work on CI, test on macos with `10.1.0.104  a.com`
#[cfg(unix)]
fn test_hosts_lookup() {
    use testing::hosts_lookup_test;
    let io_loop = AsyncStdRuntime::new();
    let handle = io_loop.handle();
    hosts_lookup_test::<AsyncStdRuntime, AsyncStdRuntime>(io_loop, handle);
}

#[test]
fn test_fqdn() {
    use testing::fqdn_test;
    let io_loop = AsyncStdRuntime::new();
    let handle = io_loop.handle();
    fqdn_test::<AsyncStdRuntime, AsyncStdRuntime>(io_loop, handle);
}

#[test]
fn test_ndots() {
    use testing::ndots_test;
    let io_loop = AsyncStdRuntime::new();
    let handle = io_loop.handle();
    ndots_test::<AsyncStdRuntime, AsyncStdRuntime>(io_loop, handle);
}

#[test]
fn test_large_ndots() {
    use testing::large_ndots_test;
    let io_loop = AsyncStdRuntime::new();
    let handle = io_loop.handle();
    large_ndots_test::<AsyncStdRuntime, AsyncStdRuntime>(io_loop, handle);
}

#[test]
fn test_domain_search() {
    use testing::domain_search_test;
    let io_loop = AsyncStdRuntime::new();
    let handle = io_loop.handle();
    domain_search_test::<AsyncStdRuntime, AsyncStdRuntime>(io_loop, handle);
}

#[test]
fn test_search_list() {
    use testing::search_list_test;
    let io_loop = AsyncStdRuntime::new();
    let handle = io_loop.handle();
    search_list_test::<AsyncStdRuntime, AsyncStdRuntime>(io_loop, handle);
}

#[test]
fn test_idna() {
    use testing::idna_test;
    let io_loop = AsyncStdRuntime::new();
    let handle = io_loop.handle();
    idna_test::<AsyncStdRuntime, AsyncStdRuntime>(io_loop, handle);
}

#[test]
fn test_localhost_ipv4() {
    use testing::localhost_ipv4_test;
    let io_loop = AsyncStdRuntime::new();
    let handle = io_loop.handle();
    localhost_ipv4_test::<AsyncStdRuntime, AsyncStdRuntime>(io_loop, handle);
}

#[test]
fn test_localhost_ipv6() {
    use testing::localhost_ipv6_test;
    let io_loop = AsyncStdRuntime::new();
    let handle = io_loop.handle();
    localhost_ipv6_test::<AsyncStdRuntime, AsyncStdRuntime>(io_loop, handle);
}

#[test]
fn test_search_ipv4_large_ndots() {
    use testing::search_ipv4_large_ndots_test;
    let io_loop = AsyncStdRuntime::new();
    let handle = io_loop.handle();
    search_ipv4_large_ndots_test::<AsyncStdRuntime, AsyncStdRuntime>(io_loop, handle);
}

#[test]
fn test_search_ipv6_large_ndots() {
    use testing::search_ipv6_large_ndots_test;
    let io_loop = AsyncStdRuntime::new();
    let handle = io_loop.handle();
    search_ipv6_large_ndots_test::<AsyncStdRuntime, AsyncStdRuntime>(io_loop, handle);
}

#[test]
fn test_search_ipv6_name_parse_fails() {
    use testing::search_ipv6_name_parse_fails_test;
    let io_loop = AsyncStdRuntime::new();
    let handle = io_loop.handle();
    search_ipv6_name_parse_fails_test::<AsyncStdRuntime, AsyncStdRuntime>(io_loop, handle);
}
