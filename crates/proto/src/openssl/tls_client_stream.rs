// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;

use futures_util::TryFutureExt;
#[cfg(feature = "mtls")]
use openssl::pkcs12::Pkcs12;
use openssl::x509::X509;
use tokio_openssl::SslStream as TokioTlsStream;

use crate::error::ProtoError;
use crate::iocompat::AsyncIoStdAsTokio;
use crate::iocompat::AsyncIoTokioAsStd;
use crate::tcp::{Connect, TcpClientStream};
use crate::xfer::BufDnsStreamHandle;

use super::TlsStreamBuilder;

/// A Type definition for the TLS stream
pub type TlsClientStream<S> =
    TcpClientStream<AsyncIoTokioAsStd<TokioTlsStream<AsyncIoStdAsTokio<S>>>>;

/// A Builder for the TlsClientStream
pub struct TlsClientStreamBuilder<S>(TlsStreamBuilder<S>);

impl<S: Connect> TlsClientStreamBuilder<S> {
    /// Creates a builder for the construction of a TlsClientStream.
    pub fn new() -> Self {
        Self(TlsStreamBuilder::new())
    }

    /// Add a custom trusted peer certificate or certificate authority.
    ///
    /// If this is the 'client' then the 'server' must have it associated as it's `identity`, or have had the `identity` signed by this certificate.
    pub fn add_ca(&mut self, ca: X509) {
        self.0.add_ca(ca);
    }

    /// Add a custom trusted peer certificate or certificate authority encoded as a (binary) DER-encoded X.509 certificate.
    ///
    /// If this is the 'client' then the 'server' must have it associated as it's `identity`, or have had the `identity` signed by this certificate.
    pub fn add_ca_der(&mut self, ca_der: &[u8]) -> io::Result<()> {
        let ca = X509::from_der(ca_der)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        self.add_ca(ca);
        Ok(())
    }

    /// Client side identity for client auth in TLS (aka mutual TLS auth)
    #[cfg(feature = "mtls")]
    pub fn identity(&mut self, pkcs12: Pkcs12) {
        self.0.identity(pkcs12);
    }

    /// Sets the address to connect from.
    pub fn bind_addr(&mut self, bind_addr: SocketAddr) {
        self.0.bind_addr(bind_addr);
    }

    /// Creates a new TlsStream to the specified name_server
    ///
    /// # Arguments
    ///
    /// * `name_server` - IP and Port for the remote DNS resolver
    /// * `bind_addr` - IP and port to connect from
    /// * `dns_name` - The DNS name, Subject Public Key Info (SPKI) name, as associated to a certificate
    #[allow(clippy::type_complexity)]
    pub fn build(
        self,
        name_server: SocketAddr,
        dns_name: String,
    ) -> (
        Pin<Box<dyn Future<Output = Result<TlsClientStream<S>, ProtoError>> + Send>>,
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

impl<S: Connect> Default for TlsClientStreamBuilder<S> {
    fn default() -> Self {
        Self::new()
    }
}
