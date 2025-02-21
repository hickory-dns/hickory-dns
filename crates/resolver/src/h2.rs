// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::proto::h2::{HttpsClientConnect, HttpsClientStream, HttpsClientStreamBuilder};
use crate::proto::runtime::{RuntimeProvider, TokioTime};
use crate::proto::tcp::DnsTcpStream;
use crate::proto::xfer::{DnsExchange, DnsExchangeConnect};

#[allow(clippy::type_complexity)]
#[allow(unused)]
pub(crate) fn new_https_stream<P: RuntimeProvider>(
    socket_addr: SocketAddr,
    bind_addr: Option<SocketAddr>,
    dns_name: String,
    http_endpoint: String,
    tls_config: Arc<rustls::ClientConfig>,
    provider: P,
) -> DnsExchangeConnect<HttpsClientConnect<P::Tcp>, HttpsClientStream, TokioTime> {
    let mut https_builder = HttpsClientStreamBuilder::with_client_config(tls_config, provider);
    if let Some(bind_addr) = bind_addr {
        https_builder.bind_addr(bind_addr);
    }
    DnsExchange::connect(https_builder.build(socket_addr, dns_name, http_endpoint))
}

#[allow(clippy::type_complexity)]
pub(crate) fn new_https_stream_with_future<S, F>(
    future: F,
    socket_addr: SocketAddr,
    dns_name: String,
    http_endpoint: String,
    tls_config: Arc<rustls::ClientConfig>,
) -> DnsExchangeConnect<HttpsClientConnect<S>, HttpsClientStream, TokioTime>
where
    S: DnsTcpStream + Send + 'static,
    F: Future<Output = std::io::Result<S>> + Send + Unpin + 'static,
{
    DnsExchange::connect(HttpsClientConnect::new(
        future,
        tls_config,
        socket_addr,
        dns_name,
        http_endpoint,
    ))
}

#[cfg(any(feature = "webpki-roots", feature = "rustls-platform-verifier"))]
#[cfg(test)]
mod tests {
    use test_support::subscribe;

    use crate::TokioResolver;
    use crate::config::{ResolverConfig, ResolverOpts};
    use crate::name_server::TokioConnectionProvider;

    async fn https_test(config: ResolverConfig) {
        let resolver = TokioResolver::new(
            config,
            ResolverOpts {
                try_tcp_on_error: true,
                ..ResolverOpts::default()
            },
            TokioConnectionProvider::default(),
        );

        let response = resolver
            .lookup_ip("www.example.com.")
            .await
            .expect("failed to run lookup");

        assert_ne!(response.iter().count(), 0);

        // check if there is another connection created
        let response = resolver
            .lookup_ip("www.example.com.")
            .await
            .expect("failed to run lookup");

        assert_ne!(response.iter().count(), 0);
    }

    #[tokio::test]
    async fn test_google_https() {
        subscribe();
        https_test(ResolverConfig::google_https()).await
    }

    #[tokio::test]
    async fn test_cloudflare_https() {
        subscribe();
        https_test(ResolverConfig::cloudflare_https()).await
    }
}
