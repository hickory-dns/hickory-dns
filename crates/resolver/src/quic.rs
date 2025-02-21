// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::proto::quic::{QuicClientConnect, QuicClientStream};
use crate::proto::runtime::TokioTime;
use crate::proto::xfer::{DnsExchange, DnsExchangeConnect};

#[allow(clippy::type_complexity)]
#[allow(unused)]
pub(crate) fn new_quic_stream(
    socket_addr: SocketAddr,
    bind_addr: Option<SocketAddr>,
    dns_name: String,
    crypto_config: rustls::ClientConfig,
) -> DnsExchangeConnect<QuicClientConnect, QuicClientStream, TokioTime> {
    let mut quic_builder = QuicClientStream::builder();
    // TODO: normalize the crypto config settings, can we just use common ALPN settings?
    quic_builder.crypto_config(crypto_config);
    if let Some(bind_addr) = bind_addr {
        quic_builder.bind_addr(bind_addr);
    }
    DnsExchange::connect(quic_builder.build(socket_addr, dns_name))
}

#[allow(clippy::type_complexity)]
pub(crate) fn new_quic_stream_with_future(
    socket: Arc<dyn quinn::AsyncUdpSocket>,
    socket_addr: SocketAddr,
    dns_name: String,
    crypto_config: rustls::ClientConfig,
) -> DnsExchangeConnect<QuicClientConnect, QuicClientStream, TokioTime> {
    let mut quic_builder = QuicClientStream::builder();
    // TODO: normalize the crypto config settings, can we just use common ALPN settings?
    quic_builder.crypto_config(crypto_config);
    DnsExchange::connect(quic_builder.build_with_future(socket, socket_addr, dns_name))
}

#[cfg(all(
    test,
    any(feature = "rustls-platform-verifier", feature = "webpki-roots")
))]
mod tests {
    use std::net::IpAddr;

    use hickory_proto::rustls::client_config;

    use test_support::subscribe;

    use crate::TokioResolver;
    use crate::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
    use crate::name_server::TokioConnectionProvider;

    async fn quic_test(config: ResolverConfig, tls_config: rustls::ClientConfig) {
        let resolver = TokioResolver::new(
            config,
            ResolverOpts {
                try_tcp_on_error: true,
                tls_config,
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
    async fn test_adguard_quic() {
        subscribe();

        // AdGuard requires SNI.
        let config = client_config();

        let name_servers = NameServerConfigGroup::from_ips_quic(
            &[
                IpAddr::from([94, 140, 14, 140]),
                IpAddr::from([94, 140, 15, 141]),
                IpAddr::from([0x2a10, 0x50c0, 0, 0, 0, 0, 0x1, 0xff]),
                IpAddr::from([0x2a10, 0x50c0, 0, 0, 0, 0, 0x2, 0xff]),
            ],
            853,
            String::from("unfiltered.adguard-dns.com"),
            true,
        );
        quic_test(
            ResolverConfig::from_parts(None, Vec::new(), name_servers),
            config,
        )
        .await
    }
}
