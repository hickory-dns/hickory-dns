// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use rustls::ClientConfig as CryptoConfig;
use std::future::Future;
use std::net::SocketAddr;
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::udp::QuicLocalAddr;

use proto::udp::DnsUdpSocket;
use proto::xfer::{DnsExchange, DnsExchangeConnect};
use proto::TokioTime;
use rustls::ClientConfig;
use trust_dns_proto::quic::{QuicClientConnect, QuicClientStream};

use crate::config::TlsClientConfig;

const ALPN_DOQ: &[u8] = b"doq";

pub(crate) fn quic_client_config() -> Result<ClientConfig, ProtoError> {
    let mut client_config = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(crate::tls::root_store()?)
        .with_no_client_auth();

    // The port (853) of DOQ is for dns dedicated, SNI is unnecessary. (ISP block by the SNI name)
    client_config.enable_sni = false;

    client_config.alpn_protocols.push(ALPN_DOQ.to_vec());

    Ok(client_config)
}

#[allow(clippy::type_complexity)]
#[allow(unused)]
pub(crate) fn new_quic_stream(
    socket_addr: SocketAddr,
    bind_addr: Option<SocketAddr>,
    dns_name: String,
    client_config: TlsClientConfig,
) -> DnsExchangeConnect<QuicClientConnect, QuicClientStream, TokioTime> {
    let mut quic_builder = QuicClientStream::builder();

    // TODO: normalize the crypto config settings, can we just use common ALPN settings?
    let crypto_config: CryptoConfig = (*client_config.0).clone();

    quic_builder.crypto_config(crypto_config);
    if let Some(bind_addr) = bind_addr {
        quic_builder.bind_addr(bind_addr);
    }
    DnsExchange::connect(quic_builder.build(socket_addr, dns_name))
}

#[allow(clippy::type_complexity)]
pub(crate) fn new_quic_stream_with_future<S, F>(
    future: F,
    socket_addr: SocketAddr,
    dns_name: String,
    client_config: TlsClientConfig,
) -> DnsExchangeConnect<QuicClientConnect, QuicClientStream, TokioTime>
where
    S: DnsUdpSocket + QuicLocalAddr + 'static,
    F: Future<Output = std::io::Result<S>> + Send + 'static,
{
    let mut quic_builder = QuicClientStream::builder();

    // TODO: normalize the crypto config settings, can we just use common ALPN settings?
    let crypto_config: CryptoConfig = (*client_config.0).clone();

    quic_builder.crypto_config(crypto_config);
    DnsExchange::connect(quic_builder.build_with_future(future, socket_addr, dns_name))
}

#[cfg(any(feature = "webpki-roots", feature = "native-certs"))]
#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    use tokio::runtime::Runtime;

    use crate::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
    use crate::name_server::TokioConnectionProvider;
    use crate::TokioAsyncResolver;

    fn quic_test(config: ResolverConfig) {
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
    fn test_adguard_quic() {
        // AdGuard requires SNI.
        let mut config = super::quic_client_config().unwrap();
        config.enable_sni = true;

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
        )
        .with_client_config(Arc::new(config));
        quic_test(ResolverConfig::from_parts(None, Vec::new(), name_servers))
    }
}
