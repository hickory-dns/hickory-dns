// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TLS based DNS client connection for Client impls
//! TODO: This modules was moved from hickory-dns-rustls, it really doesn't need to exist if tests are refactored...

use std::marker::PhantomData;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use futures::Future;
use rustls::ClientConfig;

use hickory_client::client::ClientConnection;
use hickory_client::client::Signer;
use hickory_proto::error::ProtoError;
use hickory_proto::rustls::{tls_client_connect_with_bind_addr, TlsClientStream};
use hickory_proto::tcp::Connect;
use hickory_proto::xfer::{DnsMultiplexer, DnsMultiplexerConnect};

/// Tls client connection
///
/// Use with `hickory_client::client::Client` impls
pub struct TlsClientConnection<T> {
    name_server: SocketAddr,
    bind_addr: Option<SocketAddr>,
    dns_name: String,
    client_config: Arc<ClientConfig>,
    marker: PhantomData<T>,
}

impl<T> TlsClientConnection<T> {
    pub fn new(
        name_server: SocketAddr,
        bind_addr: Option<SocketAddr>,
        dns_name: String,
        client_config: Arc<ClientConfig>,
    ) -> Self {
        TlsClientConnection {
            name_server,
            bind_addr,
            dns_name,
            client_config,
            marker: PhantomData,
        }
    }
}

#[allow(clippy::type_complexity)]
impl<T: Connect> ClientConnection for TlsClientConnection<T> {
    type Sender = DnsMultiplexer<TlsClientStream<T>, Signer>;
    type SenderFuture = DnsMultiplexerConnect<
        Pin<Box<dyn Future<Output = Result<TlsClientStream<T>, ProtoError>> + Send>>,
        TlsClientStream<T>,
        Signer,
    >;

    fn new_stream(&self, signer: Option<Arc<Signer>>) -> Self::SenderFuture {
        let (tls_client_stream, handle) = tls_client_connect_with_bind_addr(
            self.name_server,
            self.bind_addr,
            self.dns_name.clone(),
            self.client_config.clone(),
        );

        DnsMultiplexer::new(Box::pin(tls_client_stream), handle, signer)
    }
}
