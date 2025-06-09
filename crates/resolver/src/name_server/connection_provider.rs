// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::future::Future;
use std::io;
use std::marker::Unpin;
#[cfg(feature = "__quic")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
#[cfg(any(feature = "__tls", feature = "__https"))]
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::future::FutureExt;
use futures_util::ready;
#[cfg(feature = "__tls")]
use rustls::pki_types::ServerName;

use crate::config::{NameServerConfig, ProtocolConfig, ResolverOpts};
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
        config: &NameServerConfig,
        options: &ResolverOpts,
    ) -> Result<Self::FutureConn, io::Error>;
}

/// Resolves to a new Connection
#[must_use = "futures do nothing unless polled"]
pub struct ConnectionFuture<R: RuntimeProvider> {
    pub(crate) connect: Connecting<R>,
    pub(crate) spawner: R::Handle,
}

impl<R: RuntimeProvider> Future for ConnectionFuture<R> {
    type Output = Result<DnsExchange, ProtoError>;

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
    type Conn = DnsExchange;
    type FutureConn = ConnectionFuture<P>;
    type RuntimeProvider = P;

    fn new_connection(
        &self,
        config: &NameServerConfig,
        options: &ResolverOpts,
    ) -> Result<Self::FutureConn, io::Error> {
        let dns_connect = match (&config.protocol, self.quic_binder()) {
            (ProtocolConfig::Udp, _) => {
                let provider_handle = self.clone();
                let stream = UdpClientStream::builder(config.socket_addr, provider_handle)
                    .with_timeout(Some(options.timeout))
                    .with_os_port_selection(options.os_port_selection)
                    .avoid_local_ports(options.avoid_local_udp_ports.clone())
                    .with_bind_addr(config.bind_addr)
                    .build();
                let exchange = DnsExchange::connect(stream);
                Connecting::Udp(exchange)
            }
            (ProtocolConfig::Tcp, _) => {
                let (future, handle) = TcpClientStream::new(
                    config.socket_addr,
                    config.bind_addr,
                    Some(options.timeout),
                    self.clone(),
                );

                // TODO: need config for Signer...
                let dns_conn = DnsMultiplexer::with_timeout(future, handle, options.timeout, None);
                let exchange = DnsExchange::connect(dns_conn);
                Connecting::Tcp(exchange)
            }
            #[cfg(feature = "__tls")]
            (ProtocolConfig::Tls { server_name }, _) => {
                let socket_addr = config.socket_addr;
                let timeout = options.timeout;
                let tcp_future = self.connect_tcp(socket_addr, None, None);

                let Ok(server_name) = ServerName::try_from(&**server_name) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid server name: {server_name}"),
                    ));
                };

                let mut tls_config = options.tls_config.clone();
                // The port (853) of DOT is for dns dedicated, SNI is unnecessary. (ISP block by the SNI name)
                tls_config.enable_sni = false;

                let (stream, handle) = tls_client_connect_with_future(
                    tcp_future,
                    socket_addr,
                    server_name.to_owned(),
                    Arc::new(tls_config),
                );

                Connecting::Tls(DnsExchange::connect(DnsMultiplexer::with_timeout(
                    stream, handle, timeout, None,
                )))
            }
            #[cfg(feature = "__https")]
            (ProtocolConfig::Https { server_name, path }, _) => {
                Connecting::Https(DnsExchange::connect(HttpsClientConnect::new(
                    self.connect_tcp(config.socket_addr, None, None),
                    Arc::new(options.tls_config.clone()),
                    config.socket_addr,
                    server_name.clone(),
                    path.clone(),
                )))
            }
            #[cfg(feature = "__quic")]
            (ProtocolConfig::Quic { server_name }, Some(binder)) => {
                let bind_addr = config.bind_addr.unwrap_or(match config.socket_addr {
                    SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
                });

                Connecting::Quic(DnsExchange::connect(
                    QuicClientStream::builder()
                        .crypto_config(options.tls_config.clone())
                        .build_with_future(
                            binder.bind_quic(bind_addr, config.socket_addr)?,
                            config.socket_addr,
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
                let bind_addr = config.bind_addr.unwrap_or(match config.socket_addr {
                    SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
                });

                Connecting::H3(DnsExchange::connect(
                    H3ClientStream::builder()
                        .crypto_config(options.tls_config.clone())
                        .disable_grease(*disable_grease)
                        .build_with_future(
                            binder.bind_quic(bind_addr, config.socket_addr)?,
                            config.socket_addr,
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
    #[cfg(feature = "__quic")]
    use std::sync::Arc;

    use test_support::subscribe;

    use crate::TokioResolver;
    use crate::config::ResolverConfig;
    #[cfg(feature = "__quic")]
    use crate::config::{NameServerConfigGroup, ServerOrderingStrategy};
    use crate::proto::runtime::TokioRuntimeProvider;
    #[cfg(feature = "__quic")]
    use crate::proto::rustls::client_config;

    #[cfg(feature = "__h3")]
    #[tokio::test]
    async fn test_google_h3() {
        subscribe();
        h3_test(ResolverConfig::google_h3()).await
    }

    #[cfg(feature = "__h3")]
    async fn h3_test(config: ResolverConfig) {
        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        // Prefer IPv4 addresses for this test.
        builder.options_mut().server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
        let resolver = builder.build();

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
        let config = client_config();

        let name_servers = NameServerConfigGroup::from_ips_quic(
            &[
                IpAddr::from([94, 140, 14, 140]),
                IpAddr::from([94, 140, 14, 141]),
                IpAddr::from([0x2a10, 0x50c0, 0, 0, 0, 0, 0x1, 0xff]),
                IpAddr::from([0x2a10, 0x50c0, 0, 0, 0, 0, 0x2, 0xff]),
            ],
            853,
            Arc::from("unfiltered.adguard-dns.com"),
            true,
        );
        quic_test(
            ResolverConfig::from_parts(None, Vec::new(), name_servers),
            config,
        )
        .await
    }

    #[cfg(feature = "__quic")]
    async fn quic_test(config: ResolverConfig, tls_config: rustls::ClientConfig) {
        let mut resolver_builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        resolver_builder.options_mut().try_tcp_on_error = true;
        resolver_builder.options_mut().tls_config = tls_config;
        // Prefer IPv4 addresses for this test.
        resolver_builder.options_mut().server_ordering_strategy =
            ServerOrderingStrategy::UserProvidedOrder;
        let resolver = resolver_builder.build();

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
        https_test(ResolverConfig::google_https()).await
    }

    #[cfg(feature = "__https")]
    #[tokio::test]
    async fn test_cloudflare_https() {
        subscribe();
        https_test(ResolverConfig::cloudflare_https()).await
    }

    #[cfg(feature = "__https")]
    async fn https_test(config: ResolverConfig) {
        let mut resolver_builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        resolver_builder.options_mut().try_tcp_on_error = true;
        let resolver = resolver_builder.build();

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
        tls_test(ResolverConfig::google_tls()).await
    }

    #[cfg(feature = "__tls")]
    #[tokio::test]
    async fn test_cloudflare_tls() {
        subscribe();
        tls_test(ResolverConfig::cloudflare_tls()).await
    }

    #[cfg(feature = "__tls")]
    async fn tls_test(config: ResolverConfig) {
        let mut resolver_builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        resolver_builder.options_mut().try_tcp_on_error = true;
        let resolver = resolver_builder.build();

        let response = resolver
            .lookup_ip("www.example.com.")
            .await
            .expect("failed to run lookup");

        assert_ne!(response.iter().count(), 0);
    }
}
