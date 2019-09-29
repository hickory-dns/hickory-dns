// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TLS based DNS client connection for Client impls
//! TODO: This modules was moved from trust-dns-rustls, it really doesn't need to exist if tests are refactored...

use std::net::SocketAddr;
use std::sync::Arc;

use futures::Future;

use trust_dns::client::ClientConnection;
use trust_dns::rr::dnssec::Signer;
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::xfer::{DnsMultiplexer, DnsMultiplexerConnect, DnsRequestSender};

use rustls::ClientConfig;
use trust_dns_rustls::{tls_client_connect, TlsClientStream};

/// Tls client connection
///
/// Use with `trust_dns::client::Client` impls
pub struct TlsClientConnection {
    name_server: SocketAddr,
    dns_name: String,
    client_config: Arc<ClientConfig>,
}

#[cfg(all(feature = "dns-over-openssl", not(feature = "dns-over-rustls")))]
impl TlsClientConnection {
    pub fn new(
        name_server: SocketAddr,
        dns_name: String,
        client_config: Arc<ClientConfig>,
    ) -> Self {
        TlsClientConnection {
            name_server,
            dns_name,
            client_config,
        }
    }
}

impl ClientConnection for TlsClientConnection {
    type Sender = DnsMultiplexer<TlsClientStream, Signer>;
    type Response = <Self::Sender as DnsRequestSender>::DnsResponseFuture;
    type SenderFuture = DnsMultiplexerConnect<
        Box<dyn Future<Output = Result<TlsClientStream, ProtoError>> + Send>,
        TlsClientStream,
        Signer,
    >;

    fn new_stream(&self, signer: Option<Arc<Signer>>) -> Self::SenderFuture {
        let (tls_client_stream, handle) = tls_client_connect(
            self.name_server,
            self.dns_name.clone(),
            self.client_config.clone(),
        );

        DnsMultiplexer::new(Box::new(tls_client_stream), Box::new(handle), signer)
    }
}
