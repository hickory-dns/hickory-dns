// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::proto::h2::{HttpsClientConnect, HttpsClientStream};
use crate::proto::runtime::TokioTime;
use crate::proto::tcp::DnsTcpStream;
use crate::proto::xfer::{DnsExchange, DnsExchangeConnect};

pub(crate) fn new_https_stream_with_future<S, F>(
    future: F,
    socket_addr: SocketAddr,
    server_name: Arc<str>,
    path: Arc<str>,
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
        server_name,
        path,
    ))
}

#[cfg(any(feature = "webpki-roots", feature = "rustls-platform-verifier"))]
#[cfg(test)]
mod tests {
    use test_support::subscribe;

    use crate::TokioResolver;
    use crate::config::ResolverConfig;
    use crate::name_server::TokioConnectionProvider;

    async fn https_test(config: ResolverConfig) {
        let mut resolver_builder =
            TokioResolver::builder_with_config(config, TokioConnectionProvider::default());
        resolver_builder.options_mut().try_tcp_on_error = true;
        let resolver = resolver_builder.build();

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
