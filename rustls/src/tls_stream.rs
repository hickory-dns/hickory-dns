// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use futures::sync::mpsc::unbounded;
use futures::Future;
use rustls::{Certificate, ClientConfig, ClientSession};
use tokio_tcp::TcpStream as TokioTcpStream;
use tokio_rustls::{ClientConfigExt, TlsStream as TokioTlsStream};

use trust_dns_proto::error::FromProtoError;
use trust_dns_proto::tcp::TcpStream;
use trust_dns_proto::xfer::BufStreamHandle;

pub type TlsStream = TcpStream<TokioTlsStream<TokioTcpStream, ClientSession>>;

/// Initializes a TlsStream with an existing tokio_tls::TlsStream.
///
/// This is intended for use with a TlsListener and Incoming connections
pub fn tls_from_stream<E>(
    stream: TokioTlsStream<TokioTcpStream, ClientSession>,
    peer_addr: SocketAddr,
) -> (TlsStream, BufStreamHandle<E>)
where
    E: FromProtoError,
{
    let (message_sender, outbound_messages) = unbounded();
    let message_sender = BufStreamHandle::new(message_sender);

    let stream = TcpStream::from_stream_with_receiver(stream, peer_addr, outbound_messages);

    (stream, message_sender)
}

#[derive(Clone)]
pub struct TlsStreamBuilder {
    client_config: ClientConfig,
}

impl TlsStreamBuilder {
    /// Constructs a new TlsStreamBuilder
    pub fn new() -> Self {
        TlsStreamBuilder {
            client_config: ClientConfig::new(),
        }
    }

    /// Constructs a new TlsStreamBuilder with the associated ClientConfig
    pub fn with_client_config(client_config: ClientConfig) -> Self {
        TlsStreamBuilder { client_config }
    }

    /// Add a custom trusted peer certificate or certificate auhtority.
    ///
    /// If this is the 'client' then the 'server' must have it associated as it's `identity`, or have had the `identity` signed by this certificate.
    pub fn add_ca(&mut self, ca: Certificate) {
        self.client_config
            .root_store
            .add(&ca)
            .expect("bad certificate!");
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
    /// * `dns_name` - The DNS name,  Subject Public Key Info (SPKI) name, as associated to a certificate
    pub fn build<E>(
        self,
        name_server: SocketAddr,
        dns_name: String,
    ) -> (
        Box<Future<Item = TlsStream, Error = io::Error> + Send>,
        BufStreamHandle<E>,
    )
    where
        E: FromProtoError,
    {
        let (message_sender, outbound_messages) = unbounded();
        let message_sender = BufStreamHandle::new(message_sender);

        let tls_connector = Arc::new(self.client_config);
        let tcp = TokioTcpStream::connect(&name_server);

        // This set of futures collapses the next tcp socket into a stream which can be used for
        //  sending and receiving tcp packets.
        let stream =
            Box::new(tcp.and_then(move |tcp_stream| {
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
            }));

        (stream, message_sender)
    }
}
