// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::error::Error;
use std::io;
use std::net::SocketAddr;

use futures::Future;
#[cfg(feature = "mtls")]
use openssl::pkcs12::Pkcs12;
use openssl::x509::X509;
use tokio_tcp::TcpStream as TokioTcpStream;
use tokio_openssl::SslStream as TokioTlsStream;

use trust_dns_proto::error::FromProtoError;
use trust_dns_proto::tcp::TcpClientStream;
use trust_dns_proto::xfer::{BufDnsStreamHandle, DnsStreamHandle};

use super::TlsStreamBuilder;

/// A Type definition for the TLS stream
pub type TlsClientStream = TcpClientStream<TokioTlsStream<TokioTcpStream>>;

/// A Builder for the TlsClientStream
pub struct TlsClientStreamBuilder(TlsStreamBuilder);

impl TlsClientStreamBuilder {
    /// Creates a builder for the construction of a TlsClientStream.
    pub fn new() -> Self {
        TlsClientStreamBuilder(TlsStreamBuilder::new())
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
        let ca = X509::from_der(&ca_der)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.description()))?;
        self.add_ca(ca);
        Ok(())
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
    pub fn build<E>(
        self,
        name_server: SocketAddr,
        dns_name: String,
    ) -> (
        Box<Future<Item = TlsClientStream, Error = io::Error> + Send>,
        Box<DnsStreamHandle<Error = E> + Send>,
    )
    where
        E: FromProtoError + Send + 'static,
    {
        let (stream_future, sender) = self.0.build(name_server, dns_name);

        let new_future =
            Box::new(stream_future.map(move |tls_stream| TcpClientStream::from_stream(tls_stream)));

        let sender = Box::new(BufDnsStreamHandle::new(name_server, sender));

        (new_future, sender)
    }
}
