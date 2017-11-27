// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Base TlsStream

use std::net::SocketAddr;
use std::io;

use futures::{future, Future, IntoFuture};
use futures::sync::mpsc::unbounded;
use native_tls::{Certificate, Pkcs12, TlsConnector};
use native_tls::Protocol::Tlsv12;
use tokio_core::net::TcpStream as TokioTcpStream;
use tokio_core::reactor::Handle;
use tokio_tls::{TlsConnectorExt, TlsStream as TokioTlsStream};

use trust_dns::BufStreamHandle;
use trust_dns::error::ClientError;
use trust_dns::tcp::TcpStream;

/// A TlsStream counterpart to the TcpStream which embeds a secure TlsStream
pub type TlsStream = TcpStream<TokioTlsStream<TokioTcpStream>>;

fn tls_new(certs: Vec<Certificate>, pkcs12: Option<Pkcs12>) -> io::Result<TlsConnector> {
    let mut builder = TlsConnector::builder().map_err(|e| {
        io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("tls error: {}", e),
        )
    })?;
    builder.supported_protocols(&[Tlsv12]).map_err(|e| {
        io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("tls error: {}", e),
        )
    })?;

    for cert in certs {
        builder.add_root_certificate(cert).map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("tls error: {}", e),
            )
        })?;
    }

    if let Some(pkcs12) = pkcs12 {
        builder.identity(pkcs12).map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("tls error: {}", e),
            )
        })?;
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
pub fn tls_from_stream(
    stream: TokioTlsStream<TokioTcpStream>,
    peer_addr: SocketAddr,
) -> (TlsStream, BufStreamHandle<ClientError>) {
    let (message_sender, outbound_messages) = unbounded();
    let message_sender = BufStreamHandle::new(message_sender);

    let stream = TcpStream::from_stream_with_receiver(stream, peer_addr, outbound_messages);

    (stream, message_sender)
}

/// A builder for the TlsStream
pub struct TlsStreamBuilder {
    ca_chain: Vec<Certificate>,
    identity: Option<Pkcs12>,
}

impl TlsStreamBuilder {
    /// Constructs a new TlsStreamBuilder
    pub fn new() -> TlsStreamBuilder {
        TlsStreamBuilder {
            ca_chain: vec![],
            identity: None,
        }
    }

    /// Add a custom trusted peer certificate or certificate auhtority.
    ///
    /// If this is the 'client' then the 'server' must have it associated as it's `identity`, or have had the `identity` signed by this certificate.
    pub fn add_ca(&mut self, ca: Certificate) {
        self.ca_chain.push(ca);
    }

    /// Client side identity for client auth in TLS (aka mutual TLS auth)
    #[cfg(feature = "mtls")]
    pub fn identity(&mut self, pkcs12: Pkcs12) {
        self.identity = Some(pkcs12);
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
    /// * `loop_handle` - The reactor Core handle
    pub fn build(
        self,
        name_server: SocketAddr,
        dns_name: String,
        loop_handle: &Handle,
    ) -> (
        Box<Future<Item = TlsStream, Error = io::Error>>,
        BufStreamHandle<ClientError>,
    ) {
        let (message_sender, outbound_messages) = unbounded();
        let message_sender = BufStreamHandle::new(message_sender);

        let tls_connector = match ::tls_stream::tls_new(self.ca_chain, self.identity) {
            Ok(c) => c,
            Err(e) => {
                return (
                    Box::new(future::err(e).into_future().map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            format!("tls error: {}", e),
                        )
                    })),
                    message_sender,
                )
            }
        };

        let tcp = TokioTcpStream::connect(&name_server, &loop_handle);

        // This set of futures collapses the next tcp socket into a stream which can be used for
        //  sending and receiving tcp packets.
        let stream: Box<Future<Item = TlsStream, Error = io::Error>> = Box::new(
            tcp.and_then(move |tcp_stream| {
                tls_connector
                    .connect_async(&dns_name, tcp_stream)
                    .map(move |s| {
                        TcpStream::from_stream_with_receiver(s, name_server, outbound_messages)
                    })
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            format!("tls error: {}", e),
                        )
                    })
            }).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("tls error: {}", e),
                    )
                }),
        );

        (stream, message_sender)
    }
}
