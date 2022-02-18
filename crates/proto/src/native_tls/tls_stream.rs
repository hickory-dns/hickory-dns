// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Base TlsStream

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::{future::Future, marker::PhantomData};

use futures_util::TryFutureExt;
use native_tls::Protocol::Tlsv12;
use native_tls::{Certificate, Identity, TlsConnector};
use tokio_native_tls::{TlsConnector as TokioTlsConnector, TlsStream as TokioTlsStream};

use crate::iocompat::{AsyncIoStdAsTokio, AsyncIoTokioAsStd};
use crate::tcp::Connect;
use crate::tcp::TcpStream;
use crate::xfer::{BufDnsStreamHandle, StreamReceiver};

/// A TlsStream counterpart to the TcpStream which embeds a secure TlsStream
pub type TlsStream<S> = TcpStream<AsyncIoTokioAsStd<TokioTlsStream<AsyncIoStdAsTokio<S>>>>;

fn tls_new(certs: Vec<Certificate>, pkcs12: Option<Identity>) -> io::Result<TlsConnector> {
    let mut builder = TlsConnector::builder();
    builder.min_protocol_version(Some(Tlsv12));

    for cert in certs {
        builder.add_root_certificate(cert);
    }

    if let Some(pkcs12) = pkcs12 {
        builder.identity(pkcs12);
    }
    builder.build().map_err(|e| {
        io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("tls error: {}", e),
        )
    })
}

/// Initializes a TlsStream with an existing tokio_tls::TlsStream.
///
/// This is intended for use with a TlsListener and Incoming connections
pub fn tls_from_stream<S: Connect>(
    stream: TokioTlsStream<AsyncIoStdAsTokio<S>>,
    peer_addr: SocketAddr,
) -> (TlsStream<S>, BufDnsStreamHandle) {
    let (message_sender, outbound_messages) = BufDnsStreamHandle::new(peer_addr);

    let stream = TcpStream::from_stream_with_receiver(
        AsyncIoTokioAsStd(stream),
        peer_addr,
        outbound_messages,
    );

    (stream, message_sender)
}

/// A builder for the TlsStream
#[derive(Default)]
pub struct TlsStreamBuilder<S> {
    ca_chain: Vec<Certificate>,
    identity: Option<Identity>,
    bind_addr: Option<SocketAddr>,
    marker: PhantomData<S>,
}

impl<S: Connect> TlsStreamBuilder<S> {
    /// Constructs a new TlsStreamBuilder
    pub fn new() -> Self {
        Self {
            ca_chain: vec![],
            identity: None,
            bind_addr: None,
            marker: PhantomData,
        }
    }

    /// Add a custom trusted peer certificate or certificate authority.
    ///
    /// If this is the 'client' then the 'server' must have it associated as it's `identity`, or have had the `identity` signed by this certificate.
    pub fn add_ca(&mut self, ca: Certificate) {
        self.ca_chain.push(ca);
    }

    /// Client side identity for client auth in TLS (aka mutual TLS auth)
    #[cfg(feature = "mtls")]
    pub fn identity(&mut self, identity: Identity) {
        self.identity = Some(identity);
    }

    /// Sets the address to connect from.
    pub fn bind_addr(&mut self, bind_addr: SocketAddr) {
        self.bind_addr = Some(bind_addr);
    }

    /// Creates a new TlsStream to the specified name_server
    ///
    /// [RFC 7858](https://tools.ietf.org/html/rfc7858), DNS over TLS, May 2016
    ///
    /// ```text
    /// 3.2.  TLS Handshake and Authentication
    ///
    ///   Once the DNS client succeeds in connecting via TCP on the well-known
    ///   port for DNS over TLS, it proceeds with the TLS handshake [RFC5246],
    ///   following the best practices specified in [BCP195].
    ///
    ///   The client will then authenticate the server, if required.  This
    ///   document does not propose new ideas for authentication.  Depending on
    ///   the privacy profile in use (Section 4), the DNS client may choose not
    ///   to require authentication of the server, or it may make use of a
    ///   trusted Subject Public Key Info (SPKI) Fingerprint pin set.
    ///
    ///   After TLS negotiation completes, the connection will be encrypted and
    ///   is now protected from eavesdropping.
    /// ```
    ///
    /// # Arguments
    ///
    /// * `name_server` - IP and Port for the remote DNS resolver
    /// * `dns_name` - The DNS name, Public Key Info (SPKI) name, as associated to a certificate
    #[allow(clippy::type_complexity)]
    pub fn build(
        self,
        name_server: SocketAddr,
        dns_name: String,
    ) -> (
        // TODO: change to impl?
        Pin<Box<dyn Future<Output = Result<TlsStream<S>, io::Error>> + Send>>,
        BufDnsStreamHandle,
    ) {
        let (message_sender, outbound_messages) = BufDnsStreamHandle::new(name_server);

        let stream = self.inner_build(name_server, dns_name, outbound_messages);
        (Box::pin(stream), message_sender)
    }

    async fn inner_build(
        self,
        name_server: SocketAddr,
        dns_name: String,
        outbound_messages: StreamReceiver,
    ) -> Result<TlsStream<S>, io::Error> {
        use crate::native_tls::tls_stream;

        let ca_chain = self.ca_chain.clone();
        let identity = self.identity;

        let tcp_stream = S::connect_with_bind(name_server, self.bind_addr).await;

        // TODO: for some reason the above wouldn't accept a ?
        let tcp_stream = match tcp_stream {
            Ok(tcp_stream) => AsyncIoStdAsTokio(tcp_stream),
            Err(err) => return Err(err),
        };

        // This set of futures collapses the next tcp socket into a stream which can be used for
        //  sending and receiving tcp packets.
        let tls_connector = tls_stream::tls_new(ca_chain, identity)
            .map(TokioTlsConnector::from)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("tls error: {}", e),
                )
            })?;

        let tls_connected = tls_connector
            .connect(&dns_name, tcp_stream)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("tls error: {}", e),
                )
            })
            .await?;

        Ok(TcpStream::from_stream_with_receiver(
            AsyncIoTokioAsStd(tls_connected),
            name_server,
            outbound_messages,
        ))
    }
}
