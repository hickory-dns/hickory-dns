// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::future::Future;
use std::net::SocketAddr;

use crate::tls::CLIENT_CONFIG;

use proto::https::{HttpsClientConnect, HttpsClientStream, HttpsClientStreamBuilder};
use proto::tcp::{Connect, DnsTcpStream};
use proto::xfer::{DnsExchange, DnsExchangeConnect};
use proto::TokioTime;

use crate::config::TlsClientConfig;

#[allow(clippy::type_complexity)]
#[allow(unused)]
pub(crate) fn new_https_stream<S>(
    socket_addr: SocketAddr,
    bind_addr: Option<SocketAddr>,
    dns_name: String,
    client_config: Option<TlsClientConfig>,
) -> DnsExchangeConnect<HttpsClientConnect<S>, HttpsClientStream, TokioTime>
where
    S: Connect,
{
    let client_config = client_config.map_or_else(
        || CLIENT_CONFIG.clone(),
        |TlsClientConfig(client_config)| client_config,
    );

    let mut https_builder = HttpsClientStreamBuilder::with_client_config(client_config);
    if let Some(bind_addr) = bind_addr {
        https_builder.bind_addr(bind_addr);
    }
    DnsExchange::connect(https_builder.build::<S>(socket_addr, dns_name))
}

#[allow(clippy::type_complexity)]
pub(crate) fn new_https_stream_with_future<S, F>(
    future: F,
    socket_addr: SocketAddr,
    dns_name: String,
    client_config: Option<TlsClientConfig>,
) -> DnsExchangeConnect<HttpsClientConnect<S>, HttpsClientStream, TokioTime>
where
    S: DnsTcpStream,
    F: Future<Output = std::io::Result<S>> + Send + Unpin + 'static,
{
    let client_config = client_config.map_or_else(
        || CLIENT_CONFIG.clone(),
        |TlsClientConfig(client_config)| client_config,
    );

    DnsExchange::connect(HttpsClientStreamBuilder::build_with_future(
        future,
        client_config,
        socket_addr,
        dns_name,
    ))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use tokio::runtime::Runtime;

    use crate::config::{ResolverConfig, ResolverOpts};
    use crate::name_server::TokioConnectionProvider;
    use crate::TokioAsyncResolver;

    fn https_test(config: ResolverConfig) {
        let io_loop = Runtime::new().unwrap();

        let resolver = TokioAsyncResolver::new(
            config,
            ResolverOpts {
                try_tcp_on_error: true,
                ..ResolverOpts::default()
            },
            TokioConnectionProvider::default(),
        );

        let response = io_loop
            .block_on(resolver.lookup_ip("www.example.com."))
            .expect("failed to run lookup");

        assert_eq!(response.iter().count(), 1);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            } else {
                assert_eq!(
                    address,
                    IpAddr::V6(Ipv6Addr::new(
                        0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
                    ))
                );
            }
        }

        // check if there is another connection created
        let response = io_loop
            .block_on(resolver.lookup_ip("www.example.com."))
            .expect("failed to run lookup");

        assert_eq!(response.iter().count(), 1);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            } else {
                assert_eq!(
                    address,
                    IpAddr::V6(Ipv6Addr::new(
                        0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
                    ))
                );
            }
        }
    }

    #[test]
    fn test_google_https() {
        https_test(ResolverConfig::google_https())
    }

    #[test]
    fn test_cloudflare_https() {
        https_test(ResolverConfig::cloudflare_https())
    }
}
