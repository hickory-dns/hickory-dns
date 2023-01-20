// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use rustls::ClientConfig as CryptoConfig;
use std::future::Future;
use std::net::SocketAddr;
use trust_dns_proto::udp::QuicLocalAddr;

use proto::udp::DnsUdpSocket;
use proto::xfer::{DnsExchange, DnsExchangeConnect};
use proto::TokioTime;
use trust_dns_proto::quic::{QuicClientConnect, QuicClientStream};

use crate::config::TlsClientConfig;
use crate::tls::CLIENT_CONFIG;

#[allow(clippy::type_complexity)]
#[allow(unused)]
pub(crate) fn new_quic_stream(
    socket_addr: SocketAddr,
    bind_addr: Option<SocketAddr>,
    dns_name: String,
    client_config: Option<TlsClientConfig>,
) -> DnsExchangeConnect<QuicClientConnect, QuicClientStream, TokioTime> {
    let client_config = client_config.map_or_else(
        || CLIENT_CONFIG.clone(),
        |TlsClientConfig(client_config)| client_config,
    );

    let mut quic_builder = QuicClientStream::builder();

    // TODO: normalize the crypto config settings, can we just use common ALPN settings?
    let crypto_config: CryptoConfig = (*client_config).clone();

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
    client_config: Option<TlsClientConfig>,
) -> DnsExchangeConnect<QuicClientConnect, QuicClientStream, TokioTime>
where
    S: DnsUdpSocket + QuicLocalAddr + 'static,
    F: Future<Output = std::io::Result<S>> + Send + 'static,
{
    let client_config = client_config.map_or_else(
        || CLIENT_CONFIG.clone(),
        |TlsClientConfig(client_config)| client_config,
    );

    let mut quic_builder = QuicClientStream::builder();

    // TODO: normalize the crypto config settings, can we just use common ALPN settings?
    let crypto_config: CryptoConfig = (*client_config).clone();

    quic_builder.crypto_config(crypto_config);
    DnsExchange::connect(quic_builder.build_with_future(future, socket_addr, dns_name))
}
