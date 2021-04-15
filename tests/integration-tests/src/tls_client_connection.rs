// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TLS based DNS client connection for Client impls
//! TODO: This modules was moved from trust-dns-rustls, it really doesn't need to exist if tests are refactored...

use std::pin::Pin;
use std::sync::Arc;
use std::{marker::PhantomData, net::SocketAddr};

use futures::Future;
use rustls::ClientConfig;

use trust_dns_client::client::ClientConnection;
use trust_dns_client::client::Signer;
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::rustls::{tls_client_connect, TlsClientStream};
use trust_dns_proto::tcp::Connect;
use trust_dns_proto::xfer::{DnsMultiplexer, DnsMultiplexerConnect};

/// Tls client connection
///
/// Use with `trust_dns_client::client::Client` impls
pub struct TlsClientConnection<T> {
    name_server: SocketAddr,
    dns_name: String,
    client_config: Arc<ClientConfig>,
    marker: PhantomData<T>,
}

impl<T> TlsClientConnection<T> {
    pub fn new(
        name_server: SocketAddr,
        dns_name: String,
        client_config: Arc<ClientConfig>,
    ) -> Self {
        TlsClientConnection {
            name_server,
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
        let (tls_client_stream, handle) = tls_client_connect(
            self.name_server,
            self.dns_name.clone(),
            self.client_config.clone(),
        );

        DnsMultiplexer::new(Box::pin(tls_client_stream), handle, signer)
    }
}
