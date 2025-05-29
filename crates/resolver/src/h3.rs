// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::proto::h3::{H3ClientConnect, H3ClientStream};
use crate::proto::runtime::TokioTime;
use crate::proto::xfer::{DnsExchange, DnsExchangeConnect};

pub(crate) fn new_h3_stream_with_future(
    socket: Arc<dyn quinn::AsyncUdpSocket>,
    socket_addr: SocketAddr,
    server_name: Arc<str>,
    path: Arc<str>,
    crypto_config: rustls::ClientConfig,
) -> DnsExchangeConnect<H3ClientConnect, H3ClientStream, TokioTime> {
    let mut h3_builder = H3ClientStream::builder();
    // TODO: normalize the crypto config settings, can we just use common ALPN settings?
    h3_builder.crypto_config(crypto_config);
    DnsExchange::connect(h3_builder.build_with_future(socket, socket_addr, server_name, path))
}

#[cfg(all(
    test,
    any(feature = "rustls-platform-verifier", feature = "webpki-roots")
))]
mod tests {
    use test_support::subscribe;

    use crate::TokioResolver;
    use crate::config::ResolverConfig;
    use crate::name_server::TokioConnectionProvider;

    async fn h3_test(config: ResolverConfig) {
        let resolver =
            TokioResolver::builder_with_config(config, TokioConnectionProvider::default()).build();

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
    async fn test_google_h3() {
        subscribe();
        h3_test(ResolverConfig::google_h3()).await
    }
}
