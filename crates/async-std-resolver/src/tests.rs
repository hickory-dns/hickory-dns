#![allow(clippy::extra_unused_type_parameters)]

use hickory_resolver::name_server::GenericConnection;
use hickory_resolver::testing::{
    domain_search_test, fqdn_test, idna_test, ip_lookup_across_threads_test, ip_lookup_test,
    large_ndots_test, localhost_ipv4_test, localhost_ipv6_test, lookup_test, ndots_test,
    search_ipv4_large_ndots_test, search_ipv6_large_ndots_test, search_ipv6_name_parse_fails_test,
    search_list_test,
};
#[cfg(feature = "system-config")]
use hickory_resolver::testing::{hosts_lookup_test, system_lookup_test};
use hickory_resolver::LookupFuture;
use test_support::subscribe;

use crate::config::{ResolverConfig, ResolverOpts};
use crate::lookup_ip::LookupIpFuture;
use crate::proto::runtime::Executor;
use crate::proto::xfer::DnsRequest;
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

#[async_std::test]
async fn test_lookup_google() {
    subscribe();
    lookup_test(ResolverConfig::google(), AsyncStdConnectionProvider::new()).await;
}

#[async_std::test]
async fn test_lookup_cloudflare() {
    subscribe();
    lookup_test(
        ResolverConfig::cloudflare(),
        AsyncStdConnectionProvider::new(),
    )
    .await;
}

#[async_std::test]
async fn test_ip_lookup() {
    subscribe();
    ip_lookup_test(AsyncStdConnectionProvider::new()).await;
}

#[test]
fn test_ip_lookup_across_threads() {
    subscribe();
    ip_lookup_across_threads_test::<AsyncStdConnectionProvider, _>(
        AsyncStdConnectionProvider::new(),
    );
}

#[async_std::test]
#[ignore]
#[cfg(any(unix, target_os = "windows"))]
#[cfg(feature = "system-config")]
async fn test_system_lookup() {
    subscribe();
    system_lookup_test(AsyncStdConnectionProvider::new()).await;
}

#[async_std::test]
#[ignore]
#[cfg(feature = "system-config")]
// these appear to not work on CI, test on macos with `10.1.0.104  a.com`
#[cfg(unix)]
async fn test_hosts_lookup() {
    subscribe();
    hosts_lookup_test(AsyncStdConnectionProvider::new()).await;
}

#[async_std::test]
async fn test_fqdn() {
    subscribe();
    fqdn_test(AsyncStdConnectionProvider::new()).await;
}

#[async_std::test]
async fn test_ndots() {
    subscribe();
    ndots_test(AsyncStdConnectionProvider::new()).await;
}

#[async_std::test]
async fn test_large_ndots() {
    subscribe();
    large_ndots_test(AsyncStdConnectionProvider::new()).await;
}

#[async_std::test]
async fn test_domain_search() {
    subscribe();
    domain_search_test(AsyncStdConnectionProvider::new()).await;
}

#[async_std::test]
async fn test_search_list() {
    subscribe();
    search_list_test(AsyncStdConnectionProvider::new()).await;
}

#[async_std::test]
async fn test_idna() {
    subscribe();
    idna_test(AsyncStdConnectionProvider::new()).await;
}

#[async_std::test]
async fn test_localhost_ipv4() {
    subscribe();
    localhost_ipv4_test(AsyncStdConnectionProvider::new()).await;
}

#[async_std::test]
async fn test_localhost_ipv6() {
    subscribe();
    localhost_ipv6_test(AsyncStdConnectionProvider::new()).await;
}

#[async_std::test]
async fn test_search_ipv4_large_ndots() {
    subscribe();
    search_ipv4_large_ndots_test(AsyncStdConnectionProvider::new()).await;
}

#[async_std::test]
async fn test_search_ipv6_large_ndots() {
    subscribe();
    search_ipv6_large_ndots_test(AsyncStdConnectionProvider::new()).await;
}

#[async_std::test]
async fn test_search_ipv6_name_parse_fails() {
    subscribe();
    search_ipv6_name_parse_fails_test(AsyncStdConnectionProvider::new()).await;
}
