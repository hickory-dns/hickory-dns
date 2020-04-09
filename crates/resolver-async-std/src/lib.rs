use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::AsyncResolver;

use crate::runtime::AsyncStdConnection;
use crate::runtime::AsyncStdConnectionProvider;
use crate::runtime::AsyncStdRuntimeHandle;

mod net;
mod runtime;
mod time;

/// An AsyncResolver used with async_std
pub type AsyncStdAsyncResolver = AsyncResolver<AsyncStdConnection, AsyncStdConnectionProvider>;

/// Construct a new async-std based `AsyncResolver` with the provided configuration.
///
/// # Arguments
///
/// * `config` - configuration, name_servers, etc. for the Resolver
/// * `options` - basic lookup options for the resolver
///
/// # Returns
///
/// A tuple containing the new `AsyncResolver` and a future that drives the
/// background task that runs resolutions for the `AsyncResolver`. See the
/// documentation for `AsyncResolver` for more information on how to use
/// the background future.
pub async fn async_std_resolver(
    config: ResolverConfig,
    options: ResolverOpts,
) -> Result<AsyncStdAsyncResolver, ResolveError> {
    AsyncStdAsyncResolver::new(config, options, AsyncStdRuntimeHandle).await
}

/// Constructs a new async-std based Resolver with the system configuration.
///
/// This will use `/etc/resolv.conf` on Unix OSes and the registry on Windows.
#[cfg(any(unix, target_os = "windows"))]
pub async fn async_std_resolver_from_system_conf() -> Result<AsyncStdAsyncResolver, ResolveError> {
    AsyncStdAsyncResolver::from_system_conf(AsyncStdRuntimeHandle).await
}
