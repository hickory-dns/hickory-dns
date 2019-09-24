// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TlsClientStream for DNS over TLS

use std::net::SocketAddr;
use std::pin::Pin;

use futures::{Future, TryFutureExt};
use native_tls::Certificate;
#[cfg(feature = "mtls")]
use native_tls::Pkcs12;
use tokio_tcp::TcpStream as TokioTcpStream;
use tokio_tls::TlsStream as TokioTlsStream;

use trust_dns_proto::error::ProtoError;
use trust_dns_proto::tcp::TcpClientStream;
use trust_dns_proto::xfer::BufDnsStreamHandle;

use crate::TlsStreamBuilder;

/// TlsClientStream secure DNS over TCP stream
///
/// See TlsClientStreamBuilder::new()
pub type TlsClientStream = TcpClientStream<TokioTlsStream<TokioTcpStream>>;

/// Builder for TlsClientStream
pub struct TlsClientStreamBuilder(TlsStreamBuilder);

impl TlsClientStreamBuilder {
    /// Creates a builder fo the construction of a TlsClientStream
    pub fn new() -> TlsClientStreamBuilder {
        TlsClientStreamBuilder(TlsStreamBuilder::new())
    }

    /// Add a custom trusted peer certificate or certificate authority.
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

    /// Creates a new TlsStream to the specified name_server
    ///
    /// # Arguments
    ///
    /// * `name_server` - IP and Port for the remote DNS resolver
    /// * `dns_name` - The DNS name, Subject Public Key Info (SPKI) name, as associated to a certificate
    pub fn build(
        self,
        name_server: SocketAddr,
        dns_name: String,
    ) -> (
        Pin<Box<dyn Future<Output = Result<TlsClientStream, ProtoError>> + Send>>,
        BufDnsStreamHandle,
    ) {
        let (stream_future, sender) = self.0.build(name_server, dns_name);

        let new_future = Box::pin(
            stream_future
                .map_ok(TcpClientStream::from_stream)
                .map_err(ProtoError::from),
        );

        let sender = BufDnsStreamHandle::new(name_server, sender);

        (new_future, sender)
    }
}

impl Default for TlsClientStreamBuilder {
    fn default() -> Self {
        Self::new()
    }
}
