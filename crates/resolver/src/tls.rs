// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use crate::proto::rustls::tls_client_stream::tls_client_connect_with_future;
use crate::proto::rustls::TlsClientStream;
use crate::proto::tcp::DnsTcpStream;
use crate::proto::BufDnsStreamHandle;
use crate::proto::ProtoError;

#[allow(clippy::type_complexity)]
pub(crate) fn new_tls_stream_with_future<S, F>(
    future: F,
    socket_addr: SocketAddr,
    dns_name: String,
    mut tls_config: rustls::ClientConfig,
) -> (
    Pin<Box<dyn Future<Output = Result<TlsClientStream<S>, ProtoError>> + Send>>,
    BufDnsStreamHandle,
)
where
    S: DnsTcpStream,
    F: Future<Output = io::Result<S>> + Send + Unpin + 'static,
{
    // The port (853) of DOT is for dns dedicated, SNI is unnecessary. (ISP block by the SNI name)
    tls_config.enable_sni = false;

    let (stream, handle) =
        tls_client_connect_with_future(future, socket_addr, dns_name, Arc::new(tls_config));
    (Box::pin(stream), handle)
}

#[cfg(feature = "dns-over-rustls")]
#[cfg(any(feature = "webpki-roots", feature = "rustls-platform-verifier"))]
#[cfg(test)]
mod tests {
    use crate::config::{ResolverConfig, ResolverOpts};
    use crate::name_server::TokioConnectionProvider;
    use crate::TokioResolver;

    async fn tls_test(config: ResolverConfig) {
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
    }

    #[tokio::test]
    async fn test_google_tls() {
        tls_test(ResolverConfig::google_tls()).await
    }

    #[tokio::test]
    async fn test_cloudflare_tls() {
        tls_test(ResolverConfig::cloudflare_tls()).await
    }
}
