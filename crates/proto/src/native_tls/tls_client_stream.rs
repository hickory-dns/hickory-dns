// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TlsClientStream for DNS over TLS

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use futures_util::TryFutureExt;
use native_tls::Certificate;
#[cfg(feature = "mtls")]
use native_tls::Pkcs12;
use tokio_native_tls::TlsStream as TokioTlsStream;

use crate::error::ProtoError;
use crate::iocompat::AsyncIoStdAsTokio;
use crate::iocompat::AsyncIoTokioAsStd;
use crate::native_tls::TlsStreamBuilder;
use crate::tcp::TcpClientStream;
use crate::xfer::BufDnsStreamHandle;
use crate::RuntimeProvider;

/// TlsClientStream secure DNS over TCP stream
///
/// See TlsClientStreamBuilder::new()
pub type TlsClientStream<R> =
    TcpClientStream<AsyncIoTokioAsStd<TokioTlsStream<AsyncIoStdAsTokio<R>>>>;

/// Builder for TlsClientStream
pub struct TlsClientStreamBuilder<R>(TlsStreamBuilder<R>);

impl<R: RuntimeProvider> TlsClientStreamBuilder<R> {
    /// Creates a builder fo the construction of a TlsClientStream
    pub fn new(connector: R) -> TlsClientStreamBuilder<R> {
        TlsClientStreamBuilder(TlsStreamBuilder::new(connector))
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
    #[allow(clippy::type_complexity)]
    pub fn build(
        self,
        name_server: SocketAddr,
        dns_name: String,
    ) -> (
        Pin<Box<dyn Future<Output = Result<TlsClientStream<R::TcpConnection>, ProtoError>> + Send>>,
        BufDnsStreamHandle,
    ) {
        let (stream_future, sender) = self.0.build(name_server, dns_name);

        let new_future = Box::pin(
            stream_future
                .map_ok(TcpClientStream::from_stream)
                .map_err(ProtoError::from),
        );

        (new_future, sender)
    }
}

impl<R: RuntimeProvider + Default> Default for TlsClientStreamBuilder<R> {
    fn default() -> Self {
        Self::new(Default::default())
    }
}
