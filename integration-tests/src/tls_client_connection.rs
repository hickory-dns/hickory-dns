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

use rustls::Certificate;

use trust_dns::client::ClientConnection;
use trust_dns::error::*;
use trust_dns::rr::dnssec::Signer;
use trust_dns_proto::xfer::{
    DnsExchange, DnsExchangeConnect, DnsMultiplexer, DnsMultiplexerConnect, DnsRequestSender,
    DnsRequestStreamHandle,
};

use trust_dns_rustls::TlsClientStream;
use trust_dns_rustls::TlsClientStreamBuilder;

/// Tls client connection
///
/// Use with `trust_dns::client::Client` impls
pub struct TlsClientConnection {
    builder: TlsClientStreamBuilder,
    name_server: SocketAddr,
    dns_name: String,
}

impl TlsClientConnection {
    pub fn builder() -> TlsClientConnectionBuilder {
        TlsClientConnectionBuilder(TlsClientStreamBuilder::new())
    }
}

impl ClientConnection for TlsClientConnection {
    type Sender = DnsMultiplexer<TlsClientStream, Signer>;
    type Response = <Self::Sender as DnsRequestSender>::DnsResponseFuture;
    type SenderFuture = DnsMultiplexerConnect<TlsClientStream, Signer>;

    fn new_stream(
        &self,
        signer: Option<Arc<Signer>>,
    ) -> (
        DnsExchangeConnect<Self::SenderFuture, Self::Sender, Self::Response>,
        DnsRequestStreamHandle<Self::Response>,
    ) {
        let (tls_client_stream, handle) = self
            .builder
            .clone()
            .build(self.name_server, self.dns_name.clone());

        let mp = DnsMultiplexer::new(Box::new(tls_client_stream), Box::new(handle), signer);
        DnsExchange::connect(mp)
    }
}

pub struct TlsClientConnectionBuilder(TlsClientStreamBuilder);

impl TlsClientConnectionBuilder {
    /// Add a custom trusted peer certificate or certificate auhtority.
    ///
    /// If this is the 'client' then the 'server' must have it associated as it's `identity`, or have had the `identity` signed by this certificate.
    pub fn add_ca(&mut self, ca: Certificate) {
        self.0.add_ca(ca);
    }

    /// Client side identity for client auth in TLS (aka mutual TLS auth)
    #[cfg(feature = "mtls")]
    pub fn identity(&mut self, pkcs12: Pkcs12) {
        self.0.identity(pkcs12);
    }

    /// Creates a new client connection.
    ///
    /// *Note* this has side affects of establishing the connection to the specified DNS server and
    ///        starting the event_loop. Expect this to change in the future.
    ///
    /// # Arguments
    ///
    /// * `name_server` - IP and Port for the remote DNS resolver
    /// * `dns_name` - The DNS name, Subject Public Key Info (SPKI) name, as associated to a certificate
    pub fn build(
        self,
        name_server: SocketAddr,
        dns_name: String,
    ) -> ClientResult<TlsClientConnection> {
        Ok(TlsClientConnection {
            builder: self.0,
            name_server,
            dns_name,
        })
    }
}
