// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::{future::Future, marker::PhantomData};

use futures_util::{future, TryFutureExt};
use openssl::pkcs12::ParsedPkcs12_2;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{ConnectConfiguration, SslConnector, SslContextBuilder, SslMethod, SslOptions};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::X509;
use tokio_openssl::{self, SslStream as TokioTlsStream};

use crate::iocompat::{AsyncIoStdAsTokio, AsyncIoTokioAsStd};
use crate::tcp::TcpStream;
use crate::tcp::{Connect, DnsTcpStream};
use crate::xfer::BufDnsStreamHandle;

pub(crate) trait TlsIdentityExt {
    fn identity(&mut self, pkcs12: &ParsedPkcs12_2) -> io::Result<()> {
        self.identity_parts(
            pkcs12.cert.as_ref(),
            pkcs12.pkey.as_ref(),
            pkcs12.ca.as_ref(),
        )
    }

    fn identity_parts(
        &mut self,
        cert: Option<&X509>,
        pkey: Option<&PKey<Private>>,
        chain: Option<&Stack<X509>>,
    ) -> io::Result<()>;
}

impl TlsIdentityExt for SslContextBuilder {
    fn identity_parts(
        &mut self,
        cert: Option<&X509>,
        pkey: Option<&PKey<Private>>,
        chain: Option<&Stack<X509>>,
    ) -> io::Result<()> {
        if let Some(cert) = cert {
            self.set_certificate(cert)?;
        }
        if let Some(pkey) = pkey {
            self.set_private_key(pkey)?;
        }
        self.check_private_key()?;
        if let Some(chain) = chain {
            for cert in chain {
                self.add_extra_chain_cert(cert.to_owned())?;
            }
        }
        Ok(())
    }
}

/// A TlsStream counterpart to the TcpStream which embeds a secure TlsStream
pub type TlsStream<S> = TcpStream<AsyncIoTokioAsStd<TokioTlsStream<S>>>;
pub(crate) type CompatTlsStream<S> = TlsStream<AsyncIoStdAsTokio<S>>;

fn new(certs: Vec<X509>, pkcs12: Option<ParsedPkcs12_2>) -> io::Result<SslConnector> {
    let mut tls = SslConnector::builder(SslMethod::tls())
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, format!("tls error: {e}")))?;

    // mutable reference block
    {
        let openssl_ctx_builder = &mut tls;

        // only want to support current TLS versions, 1.2 or future
        openssl_ctx_builder.set_options(
            SslOptions::NO_SSLV2
                | SslOptions::NO_SSLV3
                | SslOptions::NO_TLSV1
                | SslOptions::NO_TLSV1_1,
        );

        let mut store = X509StoreBuilder::new().map_err(|e| {
            io::Error::new(io::ErrorKind::ConnectionRefused, format!("tls error: {e}"))
        })?;

        for cert in certs {
            store.add_cert(cert).map_err(|e| {
                io::Error::new(io::ErrorKind::ConnectionRefused, format!("tls error: {e}"))
            })?;
        }

        openssl_ctx_builder
            .set_verify_cert_store(store.build())
            .map_err(|e| {
                io::Error::new(io::ErrorKind::ConnectionRefused, format!("tls error: {e}"))
            })?;

        // if there was a pkcs12 associated, we'll add it to the identity
        if let Some(pkcs12) = pkcs12 {
            openssl_ctx_builder.identity(&pkcs12)?;
        }
    }
    Ok(tls.build())
}

/// Initializes a TlsStream with an existing tokio_tls::TlsStream.
///
/// This is intended for use with a TlsListener and Incoming connections
pub fn tls_stream_from_existing_tls_stream<S: DnsTcpStream>(
    stream: AsyncIoTokioAsStd<TokioTlsStream<AsyncIoStdAsTokio<S>>>,
    peer_addr: SocketAddr,
) -> (CompatTlsStream<S>, BufDnsStreamHandle) {
    let (message_sender, outbound_messages) = BufDnsStreamHandle::new(peer_addr);
    let stream = TcpStream::from_stream_with_receiver(stream, peer_addr, outbound_messages);
    (stream, message_sender)
}

async fn connect_tls<S, F>(
    future: F,
    tls_config: ConnectConfiguration,
    dns_name: String,
) -> Result<TokioTlsStream<AsyncIoStdAsTokio<S>>, io::Error>
where
    S: DnsTcpStream,
    F: Future<Output = std::io::Result<S>> + Send + Unpin + 'static,
{
    let tcp = future
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, format!("tls error: {e}")))?;
    let mut stream = tls_config
        .into_ssl(&dns_name)
        .and_then(|ssl| TokioTlsStream::new(ssl, AsyncIoStdAsTokio(tcp)))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tls error: {e}")))?;
    Pin::new(&mut stream)
        .connect()
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, format!("tls error: {e}")))?;
    Ok(stream)
}

/// A builder for the TlsStream
#[derive(Default)]
pub struct TlsStreamBuilder<S> {
    ca_chain: Vec<X509>,
    identity: Option<ParsedPkcs12_2>,
    bind_addr: Option<SocketAddr>,
    marker: PhantomData<S>,
}

impl<S: DnsTcpStream> TlsStreamBuilder<S> {
    /// A builder for associating trust information to the `TlsStream`.
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
    /// If this is the 'client' then the 'server' must have it associated as it's `identity`, or have had the `identity` signed by this
    pub fn add_ca(&mut self, ca: X509) {
        self.ca_chain.push(ca);
    }

    /// Sets the address to connect from.
    pub fn bind_addr(&mut self, bind_addr: SocketAddr) {
        self.bind_addr = Some(bind_addr);
    }

    /// Similar to `build`, but with prebuilt tcp stream
    #[allow(clippy::type_complexity)]
    pub fn build_with_future<F>(
        self,
        future: F,
        name_server: SocketAddr,
        dns_name: String,
    ) -> (
        Pin<Box<dyn Future<Output = Result<CompatTlsStream<S>, io::Error>> + Send>>,
        BufDnsStreamHandle,
    )
    where
        F: Future<Output = std::io::Result<S>> + Send + Unpin + 'static,
    {
        let (message_sender, outbound_messages) = BufDnsStreamHandle::new(name_server);
        let tls_config = match new(self.ca_chain, self.identity) {
            Ok(c) => c,
            Err(e) => {
                return (
                    Box::pin(future::err(e).map_err(|e| {
                        io::Error::new(io::ErrorKind::ConnectionRefused, format!("tls error: {e}"))
                    })),
                    message_sender,
                )
            }
        };

        let tls_config = match tls_config.configure() {
            Ok(c) => c,
            Err(e) => {
                return (
                    Box::pin(future::err(e).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            format!("tls config error: {e}"),
                        )
                    })),
                    message_sender,
                )
            }
        };

        // This set of futures collapses the next tcp socket into a stream which can be used for
        //  sending and receiving tcp packets.
        let stream = Box::pin(connect_tls(future, tls_config, dns_name).map_ok(move |s| {
            TcpStream::from_stream_with_receiver(
                AsyncIoTokioAsStd(s),
                name_server,
                outbound_messages,
            )
        }));

        (stream, message_sender)
    }
}

impl<S: Connect> TlsStreamBuilder<S> {
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
    /// * `dns_name` - The DNS name, Subject Public Key Info (SPKI) name, as associated to a certificate
    #[allow(clippy::type_complexity)]
    pub fn build(
        self,
        name_server: SocketAddr,
        dns_name: String,
    ) -> (
        Pin<Box<dyn Future<Output = Result<CompatTlsStream<S>, io::Error>> + Send>>,
        BufDnsStreamHandle,
    ) {
        let future = S::connect_with_bind(name_server, self.bind_addr);
        self.build_with_future(future, name_server, dns_name)
    }
}
