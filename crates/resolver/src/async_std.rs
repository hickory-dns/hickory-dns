//! async-std connection provider.

use std::{future::Future, io};

use crate::proto::{async_std::AsyncStdRuntimeProvider, runtime::Executor};
use crate::{
    config::{NameServerConfig, ResolverOpts},
    name_server::{ConnectionProvider, GenericConnector},
};

/// async-std connection provider.
#[derive(Clone, Default)]
pub struct AsyncStdConnectionProvider {
    runtime_provider: AsyncStdRuntimeProvider,
    connection_provider: GenericConnector<AsyncStdRuntimeProvider>,
}

impl Executor for AsyncStdConnectionProvider {
    fn new() -> Self {
        let p = AsyncStdRuntimeProvider::new();
        Self {
            runtime_provider: p,
            connection_provider: GenericConnector::new(p),
        }
    }

    fn block_on<F: Future>(&mut self, future: F) -> F::Output {
        self.runtime_provider.block_on(future)
    }
}

impl ConnectionProvider for AsyncStdConnectionProvider {
    type Conn = <GenericConnector<AsyncStdRuntimeProvider> as ConnectionProvider>::Conn;
    type FutureConn = <GenericConnector<AsyncStdRuntimeProvider> as ConnectionProvider>::FutureConn;
    type RuntimeProvider = AsyncStdRuntimeProvider;

    fn new_connection(
        &self,
        config: &NameServerConfig,
        options: &ResolverOpts,
    ) -> Result<Self::FutureConn, io::Error> {
        self.connection_provider.new_connection(config, options)
    }
}

#[cfg(test)]
mod tests {
    use test_support::subscribe;

    use super::AsyncStdConnectionProvider;
    #[cfg(feature = "system-config")]
    use crate::resolver::testing::{hosts_lookup_test, system_lookup_test};
    use crate::{
        config::ResolverConfig,
        proto::runtime::Executor,
        resolver::testing::{
            domain_search_test, fqdn_test, idna_test, ip_lookup_across_threads_test,
            ip_lookup_test, large_ndots_test, localhost_ipv4_test, localhost_ipv6_test,
            lookup_test, ndots_test, search_ipv4_large_ndots_test, search_ipv6_large_ndots_test,
            search_ipv6_name_parse_fails_test, search_list_test,
        },
    };

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
}
