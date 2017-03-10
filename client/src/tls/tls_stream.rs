// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::SocketAddr;
use std::io;

use futures::{future, Future, IntoFuture};
use futures::sync::mpsc::unbounded;
use native_tls::TlsConnector;
use native_tls::Pkcs12;
#[cfg(target_os = "macos")]
use native_tls::backend::security_framework::TlsConnectorBuilderExt;
#[cfg(target_os = "macos")]
use security_framework::certificate::SecCertificate;
#[cfg(target_os = "linux")]
use native_tls::backend::openssl::TlsConnectorBuilderExt;
#[cfg(target_os = "linux")]
use openssl::x509::X509;
#[cfg(target_os = "linux")]
use openssl::x509::store::X509StoreBuilder;
use native_tls::Protocol::Tlsv12;
use tokio_core::net::TcpStream as TokioTcpStream;
use tokio_core::reactor::Handle;
use tokio_tls::{TlsConnectorExt, TlsStream as TokioTlsStream};

use BufStreamHandle;
use tcp::TcpStream;

pub type TlsStream = TcpStream<TokioTlsStream<TokioTcpStream>>;

impl TlsStream {
    /// A builder for associating trust information to the `TlsStream`.
    pub fn builder() -> TlsStreamBuilder {
        TlsStreamBuilder {
            ca_chain: vec![],
            identity: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn new(certs: Vec<X509>, pkcs12: Option<Pkcs12>) -> io::Result<TlsConnector> {
        let mut tls = try!(TlsConnector::builder().map_err(|e| {
            io::Error::new(io::ErrorKind::ConnectionRefused,
                           format!("tls error: {}", e))
        }));
        try!(tls.supported_protocols(&[Tlsv12]).map_err(|e| {
            io::Error::new(io::ErrorKind::ConnectionRefused,
                           format!("tls error: {}", e))
        }));

        {
            // mutable reference block
            let mut openssl_builder = tls.builder_mut();
            let mut openssl_ctx_builder = openssl_builder.builder_mut();

            let mut store = try!(X509StoreBuilder::new().map_err(|e| {
                io::Error::new(io::ErrorKind::ConnectionRefused,
                               format!("tls error: {}", e))
            }));

            for cert in certs {
                try!(store.add_cert(cert).map_err(|e| {
                    io::Error::new(io::ErrorKind::ConnectionRefused,
                                   format!("tls error: {}", e))
                }));
            }

            try!(openssl_ctx_builder.set_verify_cert_store(store.build()).map_err(|e| {
                io::Error::new(io::ErrorKind::ConnectionRefused,
                               format!("tls error: {}", e))
            }));
        }

        // if there was a pkcs12 associated, we'll add it to the identity
        if let Some(pkcs12) = pkcs12 {
            try!(tls.identity(pkcs12).map_err(|e| {
                io::Error::new(io::ErrorKind::ConnectionRefused,
                               format!("tls error: {}", e))
            }));
        }
        tls.build().map_err(|e| {
            io::Error::new(io::ErrorKind::ConnectionRefused,
                           format!("tls error: {}", e))
        })
    }

    #[cfg(target_os = "macos")]
    fn new(certs: Vec<SecCertificate>, pkcs12: Option<Pkcs12>) -> io::Result<TlsConnector> {
        let mut builder = try!(TlsConnector::builder().map_err(|e| {
            io::Error::new(io::ErrorKind::ConnectionRefused,
                           format!("tls error: {}", e))
        }));
        try!(builder.supported_protocols(&[Tlsv12]).map_err(|e| {
            io::Error::new(io::ErrorKind::ConnectionRefused,
                           format!("tls error: {}", e))
        }));
        builder.anchor_certificates(&certs);

        if let Some(pkcs12) = pkcs12 {
            try!(builder.identity(pkcs12).map_err(|e| {
                io::Error::new(io::ErrorKind::ConnectionRefused,
                               format!("tls error: {}", e))
            }));
        }
        builder.build().map_err(|e| {
            io::Error::new(io::ErrorKind::ConnectionRefused,
                           format!("tls error: {}", e))
        })
    }

    /// Initializes a TcpStream with an existing tokio_core::net::TcpStream.
    ///
    /// This is intended for use with a TcpListener and Incoming.
    pub fn from_tls_stream(stream: TokioTlsStream<TokioTcpStream>,
                           peer_addr: SocketAddr)
                           -> (Self, BufStreamHandle) {
        let (message_sender, outbound_messages) = unbounded();

        let stream = TcpStream::from_stream_with_receiver(stream, peer_addr, outbound_messages);

        (stream, message_sender)
    }
}

pub struct TlsStreamBuilder {
    #[cfg(target_os = "macos")]
    ca_chain: Vec<SecCertificate>,

    #[cfg(target_os = "linux")]
    ca_chain: Vec<X509>,
    identity: Option<Pkcs12>,
}

impl TlsStreamBuilder {
    /// Add a custom trusted peer certificate or certificate auhtority.
    ///
    /// If this is the 'client' then the 'server' must have it associated as it's `identity`, or have had the `identity` signed by this certificate.
    #[cfg(target_os = "macos")]
    pub fn add_ca(&mut self, ca: SecCertificate) {
        self.ca_chain.push(ca);
    }

    /// Add a custom trusted peer certificate or certificate auhtority.
    ///
    /// If this is the 'client' then the 'server' must have it associated as it's `identity`, or have had the `identity` signed by this
    #[cfg(target_os = "linux")]
    pub fn add_ca(&mut self, ca: X509) {
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
    /// * `subject_name` - The Subject Public Key Info (SPKI) name as associated to a certificate
    /// * `loop_handle` - The reactor Core handle
    /// * `certs` - list of trusted certificate authorities
    /// * `pkcs12` - optional client identity for client auth (i.e. for mutual TLS authentication)
    /// TODO: make a builder for the certifiates...
    pub fn build(self,
                 name_server: SocketAddr,
                 subject_name: String,
                 loop_handle: Handle)
                 -> (Box<Future<Item = TlsStream, Error = io::Error>>, BufStreamHandle) {
        let (message_sender, outbound_messages) = unbounded();
        let tls_connector = match TlsStream::new(self.ca_chain, self.identity) {
            Ok(c) => c,
            Err(e) => {
                return (Box::new(future::err(e).into_future().map_err(|e| {
                            io::Error::new(io::ErrorKind::ConnectionRefused,
                                           format!("tls error: {}", e))
                        })),
                        message_sender)
            }
        };

        let tcp = TokioTcpStream::connect(&name_server, &loop_handle);

        // This set of futures collapses the next tcp socket into a stream which can be used for
        //  sending and receiving tcp packets.
        let stream: Box<Future<Item = TlsStream, Error = io::Error>> =
            Box::new(tcp.and_then(move |tcp_stream| {
                    tls_connector.connect_async(&subject_name, tcp_stream)
                        .map(move |s| {
                            TcpStream::from_stream_with_receiver(s, name_server, outbound_messages)
                        })
                        .map_err(|e| {
                            io::Error::new(io::ErrorKind::ConnectionRefused,
                                           format!("tls error: {}", e))
                        })
                })
                .map_err(|e| {
                    io::Error::new(io::ErrorKind::ConnectionRefused,
                                   format!("tls error: {}", e))
                }));

        (stream, message_sender)
    }
}
