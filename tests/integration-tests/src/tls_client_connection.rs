// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TLS based DNS client connection for Client impls
//! TODO: This modules was moved from hickory-dns-rustls, it really doesn't need to exist if tests are refactored...

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use futures::Future;
use rustls::ClientConfig;

use hickory_client::client::{ClientConnection, Signer};
use hickory_proto::error::ProtoError;
use hickory_proto::runtime::RuntimeProvider;
use hickory_proto::rustls::{tls_client_connect_with_bind_addr, TlsClientStream};
use hickory_proto::xfer::{DnsMultiplexer, DnsMultiplexerConnect};

/// Tls client connection
///
/// Use with `hickory_client::client::Client` impls
pub struct TlsClientConnection<P> {
    provider: P,
    name_server: SocketAddr,
    bind_addr: Option<SocketAddr>,
    dns_name: String,
    client_config: Arc<ClientConfig>,
}

impl<P> TlsClientConnection<P> {
    pub fn new(
        name_server: SocketAddr,
        bind_addr: Option<SocketAddr>,
        dns_name: String,
        client_config: Arc<ClientConfig>,
        provider: P,
    ) -> Self {
        TlsClientConnection {
            provider,
            name_server,
            bind_addr,
            dns_name,
            client_config,
        }
    }
}

#[allow(clippy::type_complexity)]
impl<P: RuntimeProvider> ClientConnection for TlsClientConnection<P> {
    type Sender = DnsMultiplexer<TlsClientStream<P::Tcp>, Signer>;
    type SenderFuture = DnsMultiplexerConnect<
        Pin<Box<dyn Future<Output = Result<TlsClientStream<P::Tcp>, ProtoError>> + Send>>,
        TlsClientStream<P::Tcp>,
        Signer,
    >;

    fn new_stream(&self, signer: Option<Arc<Signer>>) -> Self::SenderFuture {
        let (tls_client_stream, handle) = tls_client_connect_with_bind_addr(
            self.name_server,
            self.bind_addr,
            self.dns_name.clone(),
            self.client_config.clone(),
            self.provider.clone(),
        );

        DnsMultiplexer::new(Box::pin(tls_client_stream), handle, signer)
    }
}
