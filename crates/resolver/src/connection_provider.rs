// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::future::Future;
use std::io;
use std::marker::Unpin;
use std::net::{IpAddr, SocketAddr};
#[cfg(feature = "__quic")]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
#[cfg(any(feature = "__tls", feature = "__https"))]
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::future::FutureExt;
use futures_util::ready;
#[cfg(feature = "__tls")]
use rustls::DigitallySignedStruct;
#[cfg(feature = "__tls")]
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
#[cfg(feature = "__tls")]
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
#[cfg(feature = "__tls")]
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
#[cfg(not(feature = "__tls"))]
use tracing::warn;

use crate::config::{ConnectionConfig, ProtocolConfig};
use crate::name_server_pool::PoolContext;
#[cfg(feature = "__https")]
use crate::proto::h2::HttpsClientConnect;
#[cfg(feature = "__h3")]
use crate::proto::h3::H3ClientStream;
#[cfg(feature = "__quic")]
use crate::proto::quic::QuicClientStream;
#[cfg(feature = "__tls")]
use crate::proto::rustls::tls_client_stream::tls_client_connect_with_future;
use crate::proto::{
    ProtoError,
    runtime::{RuntimeProvider, Spawn},
    tcp::TcpClientStream,
    udp::UdpClientStream,
    xfer::{Connecting, DnsExchange, DnsHandle, DnsMultiplexer},
};
#[cfg(feature = "__tls")]
use hickory_proto::rustls::{client_config, default_provider};

/// Create `DnsHandle` with the help of `RuntimeProvider`.
/// This trait is designed for customization.
pub trait ConnectionProvider: 'static + Clone + Send + Sync + Unpin {
    /// The handle to the connection for sending DNS requests.
    type Conn: DnsHandle + Clone + Send + Sync + 'static;
    /// Ths future is responsible for spawning any background tasks as necessary.
    type FutureConn: Future<Output = Result<Self::Conn, ProtoError>> + Send + 'static;
    /// Provider that handles the underlying I/O and timing.
    type RuntimeProvider: RuntimeProvider;

    /// Create a new connection.
    fn new_connection(
        &self,
        ip: IpAddr,
        config: &ConnectionConfig,
        cx: &PoolContext,
    ) -> Result<Self::FutureConn, io::Error>;

    /// Get a reference to a [`RuntimeProvider`].
    fn runtime_provider(&self) -> &Self::RuntimeProvider;
}

/// Resolves to a new Connection
#[must_use = "futures do nothing unless polled"]
pub struct ConnectionFuture<P: RuntimeProvider> {
    pub(crate) connect: Connecting<P>,
    pub(crate) spawner: P::Handle,
}

impl<P: RuntimeProvider> Future for ConnectionFuture<P> {
    type Output = Result<DnsExchange<P>, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Ok(match &mut self.connect {
            Connecting::Udp(conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                self.spawner.spawn_bg(bg);
                conn
            }
            Connecting::Tcp(conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                self.spawner.spawn_bg(bg);
                conn
            }
            #[cfg(feature = "__tls")]
            Connecting::Tls(conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                self.spawner.spawn_bg(bg);
                conn
            }
            #[cfg(feature = "__https")]
            Connecting::Https(conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                self.spawner.spawn_bg(bg);
                conn
            }
            #[cfg(feature = "__quic")]
            Connecting::Quic(conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                self.spawner.spawn_bg(bg);
                conn
            }
            #[cfg(feature = "__h3")]
            Connecting::H3(conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                self.spawner.spawn_bg(bg);
                conn
            }
            _ => unreachable!("unsupported connection type in Connecting"),
        }))
    }
}

impl<P: RuntimeProvider> ConnectionProvider for P {
    type Conn = DnsExchange<P>;
    type FutureConn = ConnectionFuture<P>;
    type RuntimeProvider = P;

    fn new_connection(
        &self,
        ip: IpAddr,
        config: &ConnectionConfig,
        cx: &PoolContext,
    ) -> Result<Self::FutureConn, io::Error> {
        let remote_addr = SocketAddr::new(ip, config.port);
        let dns_connect = match (&config.protocol, self.quic_binder()) {
            (ProtocolConfig::Udp, _) => {
                let provider_handle = self.clone();
                let stream = UdpClientStream::builder(remote_addr, provider_handle)
                    .with_timeout(Some(cx.options.timeout))
                    .with_os_port_selection(cx.options.os_port_selection)
                    .avoid_local_ports(cx.options.avoid_local_udp_ports.clone())
                    .with_bind_addr(config.bind_addr)
                    .build();
                let exchange = DnsExchange::connect(stream);
                Connecting::Udp(exchange)
            }
            (ProtocolConfig::Tcp, _) => {
                let (future, handle) = TcpClientStream::new(
                    remote_addr,
                    config.bind_addr,
                    Some(cx.options.timeout),
                    self.clone(),
                );

                // TODO: need config for Signer...
                let dns_conn =
                    DnsMultiplexer::with_timeout(future, handle, cx.options.timeout, None);
                let exchange = DnsExchange::connect(dns_conn);
                Connecting::Tcp(exchange)
            }
            #[cfg(feature = "__tls")]
            (ProtocolConfig::Tls { server_name }, _) => {
                let timeout = cx.options.timeout;
                let tcp_future = self.connect_tcp(remote_addr, None, None);

                let Ok(server_name) = ServerName::try_from(&**server_name) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid server name: {server_name}"),
                    ));
                };

                let mut tls_config = cx.tls.config.clone();
                // The port (853) of DOT is for dns dedicated, SNI is unnecessary. (ISP block by the SNI name)
                tls_config.enable_sni = false;

                let (stream, handle) = tls_client_connect_with_future(
                    tcp_future,
                    remote_addr,
                    server_name.to_owned(),
                    Arc::new(tls_config),
                    self.clone(),
                );

                Connecting::Tls(DnsExchange::connect(DnsMultiplexer::with_timeout(
                    stream, handle, timeout, None,
                )))
            }
            #[cfg(feature = "__https")]
            (ProtocolConfig::Https { server_name, path }, _) => {
                Connecting::Https(DnsExchange::connect(HttpsClientConnect::new(
                    self.connect_tcp(remote_addr, None, None),
                    Arc::new(cx.tls.config.clone()),
                    remote_addr,
                    server_name.clone(),
                    path.clone(),
                    self.clone(),
                )))
            }
            #[cfg(feature = "__quic")]
            (ProtocolConfig::Quic { server_name }, Some(binder)) => {
                let bind_addr = config.bind_addr.unwrap_or(match remote_addr {
                    SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
                });

                Connecting::Quic(DnsExchange::connect(
                    QuicClientStream::builder()
                        .crypto_config(cx.tls.config.clone())
                        .build_with_future(
                            binder.bind_quic(bind_addr, remote_addr)?,
                            remote_addr,
                            server_name.clone(),
                        ),
                ))
            }
            #[cfg(feature = "__h3")]
            (
                ProtocolConfig::H3 {
                    server_name,
                    path,
                    disable_grease,
                },
                Some(binder),
            ) => {
                let bind_addr = config.bind_addr.unwrap_or(match remote_addr {
                    SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
                });

                Connecting::H3(DnsExchange::connect(
                    H3ClientStream::builder()
                        .crypto_config(cx.tls.config.clone())
                        .disable_grease(*disable_grease)
                        .build_with_future(
                            binder.bind_quic(bind_addr, remote_addr)?,
                            remote_addr,
                            server_name.clone(),
                            path.clone(),
                        ),
                ))
            }
            #[cfg(feature = "__quic")]
            (ProtocolConfig::Quic { .. }, None) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "runtime provider does not support QUIC",
                ));
            }
            #[cfg(feature = "__h3")]
            (ProtocolConfig::H3 { .. }, None) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "runtime provider does not support QUIC",
                ));
            }
        };

        Ok(ConnectionFuture::<P> {
            connect: dns_connect,
            spawner: self.create_handle(),
        })
    }

    fn runtime_provider(&self) -> &Self::RuntimeProvider {
        self
    }
}

/// TLS configuration for the connection provider.
#[cfg_attr(not(feature = "__tls"), allow(missing_copy_implementations))]
pub struct TlsConfig {
    /// The TLS configuration to use for secure connections.
    #[cfg(feature = "__tls")]
    pub(crate) config: rustls::ClientConfig,
}

impl TlsConfig {
    /// Create a new `TlsConfig` with default settings.
    pub fn new() -> Result<Self, ProtoError> {
        Ok(Self {
            #[cfg(feature = "__tls")]
            config: client_config()?,
        })
    }

    /// Disable certificate verification.
    ///
    /// This is typically unsafe and insecure, except in the context of RFC 9539 opportunistic
    /// encryption which requires the peer certificate not be verified.
    #[cfg(feature = "__tls")]
    pub fn insecure_skip_verify(&mut self) {
        self.config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoCertificateVerification::default()))
    }

    /// Disable certificate verification.
    ///
    /// This is typically unsafe and insecure, except in the context of RFC 9539 opportunistic
    /// encryption which requires the peer certificate not be verified.
    #[cfg(not(feature = "__tls"))]
    pub fn insecure_skip_verify(&mut self) {
        warn!("asked to skip TLS verification without TLS support")
    }
}

/// A rustls ServerCertVerifier that performs **no** certificate verification.
///
/// This should only be used with great care, as skipping certificate verification is insecure
/// and could allow person-in-the-middle attacks.
#[cfg(feature = "__tls")]
#[derive(Debug)]
struct NoCertificateVerification(CryptoProvider);

#[cfg(feature = "__tls")]
impl Default for NoCertificateVerification {
    fn default() -> Self {
        Self(default_provider())
    }
}

#[cfg(feature = "__tls")]
impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(all(
    test,
    feature = "tokio",
    any(feature = "webpki-roots", feature = "rustls-platform-verifier"),
    any(
        feature = "__tls",
        feature = "__https",
        feature = "__quic",
        feature = "__h3"
    )
))]
mod tests {
    #[cfg(feature = "__quic")]
    use std::net::IpAddr;

    use test_support::subscribe;

    use crate::TokioResolver;
    #[cfg(any(feature = "__tls", feature = "__https"))]
    use crate::config::CLOUDFLARE;
    #[cfg(any(
        feature = "__tls",
        feature = "__https",
        feature = "__quic",
        feature = "__h3"
    ))]
    use crate::config::GOOGLE;
    use crate::config::ResolverConfig;
    #[cfg(feature = "__quic")]
    use crate::config::ServerGroup;
    #[cfg(feature = "__quic")]
    use crate::config::ServerOrderingStrategy;
    use crate::proto::runtime::TokioRuntimeProvider;
    #[cfg(feature = "__quic")]
    use crate::proto::rustls::client_config;

    #[cfg(feature = "__h3")]
    #[tokio::test]
    async fn test_google_h3() {
        subscribe();
        h3_test(ResolverConfig::h3(&GOOGLE)).await
    }

    #[cfg(feature = "__h3")]
    async fn h3_test(config: ResolverConfig) {
        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        // Prefer IPv4 addresses for this test.
        builder.options_mut().server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
        let resolver = builder.build().unwrap();

        let response = resolver
            .lookup_ip("www.example.com.")
            .await
            .expect("failed to run lookup");

        assert_ne!(response.iter().count(), 0);

        // check if there is another connection created
        let response = resolver
            .lookup_ip("www.example.com.")
            .await
            .expect("failed to run lookup");

        assert_ne!(response.iter().count(), 0);
    }

    #[cfg(feature = "__quic")]
    #[tokio::test]
    async fn test_adguard_quic() {
        subscribe();

        // AdGuard requires SNI.
        let config = client_config().unwrap();

        let group = ServerGroup {
            ips: &[
                IpAddr::from([94, 140, 14, 140]),
                IpAddr::from([94, 140, 14, 141]),
                IpAddr::from([0x2a10, 0x50c0, 0, 0, 0, 0, 0x1, 0xff]),
                IpAddr::from([0x2a10, 0x50c0, 0, 0, 0, 0, 0x2, 0xff]),
            ],
            server_name: "unfiltered.adguard-dns.com",
            path: "/dns-query",
        };

        quic_test(ResolverConfig::quic(&group), config).await
    }

    #[cfg(feature = "__quic")]
    async fn quic_test(config: ResolverConfig, tls_config: rustls::ClientConfig) {
        let mut resolver_builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        resolver_builder.options_mut().try_tcp_on_error = true;
        // Prefer IPv4 addresses for this test.
        resolver_builder.options_mut().server_ordering_strategy =
            ServerOrderingStrategy::UserProvidedOrder;
        resolver_builder = resolver_builder.with_tls_config(tls_config);
        let resolver = resolver_builder.build().unwrap();

        let response = resolver
            .lookup_ip("www.example.com.")
            .await
            .expect("failed to run lookup");

        assert_ne!(response.iter().count(), 0);

        // check if there is another connection created
        let response = resolver
            .lookup_ip("www.example.com.")
            .await
            .expect("failed to run lookup");

        assert_ne!(response.iter().count(), 0);
    }

    #[cfg(feature = "__https")]
    #[tokio::test]
    async fn test_google_https() {
        subscribe();
        https_test(ResolverConfig::https(&GOOGLE)).await
    }

    #[cfg(feature = "__https")]
    #[tokio::test]
    async fn test_cloudflare_https() {
        subscribe();
        https_test(ResolverConfig::https(&CLOUDFLARE)).await
    }

    #[cfg(feature = "__https")]
    async fn https_test(config: ResolverConfig) {
        let mut resolver_builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        resolver_builder.options_mut().try_tcp_on_error = true;
        let resolver = resolver_builder.build().unwrap();

        let response = resolver
            .lookup_ip("www.example.com.")
            .await
            .expect("failed to run lookup");

        assert_ne!(response.iter().count(), 0);

        // check if there is another connection created
        let response = resolver
            .lookup_ip("www.example.com.")
            .await
            .expect("failed to run lookup");

        assert_ne!(response.iter().count(), 0);
    }

    #[cfg(feature = "__tls")]
    #[tokio::test]
    async fn test_google_tls() {
        subscribe();
        tls_test(ResolverConfig::tls(&GOOGLE)).await
    }

    #[cfg(feature = "__tls")]
    #[tokio::test]
    async fn test_cloudflare_tls() {
        subscribe();
        tls_test(ResolverConfig::tls(&CLOUDFLARE)).await
    }

    #[cfg(feature = "__tls")]
    async fn tls_test(config: ResolverConfig) {
        let mut resolver_builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        resolver_builder.options_mut().try_tcp_on_error = true;
        let resolver = resolver_builder.build().unwrap();

        let response = resolver
            .lookup_ip("www.example.com.")
            .await
            .expect("failed to run lookup");

        assert_ne!(response.iter().count(), 0);
    }
}
