// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{
    fmt::{self, Display},
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::{future::FutureExt, stream::Stream};
use quinn::{ClientConfig, Connection, Endpoint, NewConnection, OpenBi, TransportConfig, VarInt};
use rustls::{version::TLS13, ClientConfig as TlsClientConfig};

use crate::{
    error::ProtoError,
    quic::quic_stream::{DoqErrorCode, QuicStream},
    udp::UdpSocket,
    xfer::{DnsRequest, DnsRequestSender, DnsResponse, DnsResponseStream},
};

use super::{quic_config, quic_stream};

/// A DNS client connection for DNS-over-QUIC
#[must_use = "futures do nothing unless polled"]
pub struct QuicClientStream {
    quic_connection: Connection,
    name_server_name: Arc<str>,
    name_server: SocketAddr,
    is_shutdown: bool,
}

impl Display for QuicClientStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            formatter,
            "QUIC({},{})",
            self.name_server, self.name_server_name
        )
    }
}

impl QuicClientStream {
    /// Builder for QuicClientStream
    pub fn builder() -> QuicClientStreamBuilder {
        QuicClientStreamBuilder::default()
    }

    async fn inner_send(stream: OpenBi, message: DnsRequest) -> Result<DnsResponse, ProtoError> {
        let (send_stream, recv_stream) = stream.await?;

        // RFC: The mapping specified here requires that the client selects a separate
        //  QUIC stream for each query. The server then uses the same stream to provide all the response messages for that query.
        let mut stream = QuicStream::new(send_stream, recv_stream);

        stream.send(message.into_parts().0).await?;

        // The client MUST send the DNS query over the selected stream,
        // and MUST indicate through the STREAM FIN mechanism that no further data will be sent on that stream.
        stream.finish().await?;

        let response = stream.receive().await?;
        Ok(response.into())
    }
}

impl DnsRequestSender for QuicClientStream {
    /// The send loop for QUIC in DNS stipulates that a new QUIC "stream" should be opened and use for sending data.
    ///
    /// It should be closed after receiving the response. TODO: AXFR/IXFR support...
    ///
    /// ```text
    /// 5.2. Stream Mapping and Usage
    ///
    /// The mapping of DNS traffic over QUIC streams takes advantage of the QUIC stream features detailed in Section 2 of [RFC9000],
    /// the QUIC transport specification.
    ///
    /// DNS traffic follows a simple pattern in which the client sends a query, and the server provides one or more responses
    /// (multiple responses can occur in zone transfers).The mapping specified here requires that the client selects a separate
    /// QUIC stream for each query. The server then uses the same stream to provide all the response messages for that query. In
    /// order that multiple responses can be parsed, a 2-octet length field is used in exactly the same way as the 2-octet length
    /// field defined for DNS over TCP [RFC1035]. The practical result of this is that the content of each QUIC stream is exactly
    /// the same as the content of a TCP connection that would manage exactly one query.All DNS messages (queries and responses)
    /// sent over DoQ connections MUST be encoded as a 2-octet length field followed by the message content as specified in [RFC1035].
    /// The client MUST select the next available client-initiated bidirectional stream for each subsequent query on a QUIC connection,
    /// in conformance with the QUIC transport specification [RFC9000].The client MUST send the DNS query over the selected stream,
    /// and MUST indicate through the STREAM FIN mechanism that no further data will be sent on that stream.The server MUST send the
    /// response(s) on the same stream and MUST indicate, after the last response, through the STREAM FIN mechanism that no further
    /// data will be sent on that stream.Therefore, a single DNS transaction consumes a single bidirectional client-initiated stream.
    /// This means that the client's first query occurs on QUIC stream 0, the second on 4, and so on (see Section 2.1 of [RFC9000].
    /// Servers MAY defer processing of a query until the STREAM FIN has been indicated on the stream selected by the client. Servers
    /// and clients MAY monitor the number of "dangling" streams for which the expected queries or responses have been received but
    /// not the STREAM FIN. Implementations MAY impose a limit on the number of such dangling streams. If limits are encountered,
    /// implementations MAY close the connection.
    ///
    /// 5.2.1. DNS Message IDs
    ///
    /// When sending queries over a QUIC connection, the DNS Message ID MUST be set to zero. The stream mapping for DoQ allows for
    /// unambiguous correlation of queries and responses and so the Message ID field is not required.
    ///
    /// This has implications for proxying DoQ message to and from other transports. For example, proxies may have to manage the
    /// fact that DoQ can support a larger number of outstanding queries on a single connection than e.g., DNS over TCP because DoQ
    /// is not limited by the Message ID space. This issue already exists for DoH, where a Message ID of 0 is recommended.When forwarding
    /// a DNS message from DoQ over another transport, a DNS Message ID MUST be generated according to the rules of the protocol that is
    /// in use. When forwarding a DNS message from another transport over DoQ, the Message ID MUST be set to zero.
    /// ```
    fn send_message(&mut self, message: DnsRequest) -> DnsResponseStream {
        if self.is_shutdown {
            panic!("can not send messages after stream is shutdown")
        }

        let connection = self.quic_connection.open_bi();

        Box::pin(Self::inner_send(connection, message)).into()
    }

    fn shutdown(&mut self) {
        self.is_shutdown = true;
        self.quic_connection
            .close(DoqErrorCode::NoError.into(), b"Shutdown");
    }

    fn is_shutdown(&self) -> bool {
        self.is_shutdown
    }
}

impl Stream for QuicClientStream {
    type Item = Result<(), ProtoError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.is_shutdown {
            Poll::Ready(None)
        } else {
            Poll::Ready(Some(Ok(())))
        }
    }
}

/// A QUIC connection builder for DNS-over-QUIC
#[derive(Clone)]
pub struct QuicClientStreamBuilder {
    crypto_config: TlsClientConfig,
    transport_config: Arc<TransportConfig>,
    bind_addr: Option<SocketAddr>,
}

impl QuicClientStreamBuilder {
    /// Constructs a new TlsStreamBuilder with the associated ClientConfig
    pub fn crypto_config(&mut self, crypto_config: TlsClientConfig) -> &mut Self {
        self.crypto_config = crypto_config;
        self
    }

    /// Sets the address to connect from.
    pub fn bind_addr(&mut self, bind_addr: SocketAddr) -> &mut Self {
        self.bind_addr = Some(bind_addr);
        self
    }

    /// Creates a new QuicStream to the specified name_server
    ///
    /// # Arguments
    ///
    /// * `name_server` - IP and Port for the remote DNS resolver
    /// * `dns_name` - The DNS name, Subject Public Key Info (SPKI) name, as associated to a certificate
    pub fn build(self, name_server: SocketAddr, dns_name: String) -> QuicClientConnect {
        QuicClientConnect(Box::pin(self.connect(name_server, dns_name)) as _)
    }

    async fn connect(
        self,
        name_server: SocketAddr,
        dns_name: String,
    ) -> Result<QuicClientStream, ProtoError> {
        let connect = if let Some(bind_addr) = self.bind_addr {
            <tokio::net::UdpSocket as UdpSocket>::connect_with_bind(name_server, bind_addr)
        } else {
            <tokio::net::UdpSocket as UdpSocket>::connect(name_server)
        };

        let socket = connect.await?;
        let socket = socket.into_std()?;

        let endpoint_config = quic_config::endpoint();
        let (mut endpoint, _incoming) = Endpoint::new(endpoint_config, None, socket)?;

        // ensure the ALPN protocol is set correctly
        let mut crypto_config = self.crypto_config;
        if crypto_config.alpn_protocols.is_empty() {
            crypto_config.alpn_protocols = vec![quic_stream::DOQ_ALPN.to_vec()];
        }
        let early_data_enabled = crypto_config.enable_early_data;

        let mut client_config = ClientConfig::new(Arc::new(crypto_config));
        client_config.transport = self.transport_config;

        endpoint.set_default_client_config(client_config);

        let connecting = endpoint.connect(name_server, &dns_name)?;
        // TODO: for Client/Dynamic update, don't use RTT, for queries, do use it.

        let connection = if early_data_enabled {
            match connecting.into_0rtt() {
                Ok((new_connection, _)) => new_connection,
                Err(connecting) => connecting.await?,
            }
        } else {
            connecting.await?
        };
        let NewConnection {
            connection: quic_connection,
            ..
        } = connection;

        Ok(QuicClientStream {
            quic_connection,
            name_server_name: Arc::from(dns_name),
            name_server,
            is_shutdown: false,
        })
    }
}

/// Default crypto options for quic
pub fn client_config_tls13_webpki_roots() -> TlsClientConfig {
    use rustls::{OwnedTrustAnchor, RootCertStore};
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    TlsClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&TLS13])
        .expect("TLS 1.3 not supported")
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

impl Default for QuicClientStreamBuilder {
    fn default() -> Self {
        let mut transport_config = quic_config::transport();
        // clients never accept new bidirectional streams
        transport_config.max_concurrent_bidi_streams(VarInt::from_u32(0));

        let client_config = client_config_tls13_webpki_roots();

        Self {
            crypto_config: client_config,
            transport_config: Arc::new(transport_config),
            bind_addr: None,
        }
    }
}

/// A future that resolves to an QuicClientStream
pub struct QuicClientConnect(
    Pin<Box<dyn Future<Output = Result<QuicClientStream, ProtoError>> + Send>>,
);

impl Future for QuicClientConnect {
    type Output = Result<QuicClientStream, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.poll_unpin(cx)
    }
}

/// A future that resolves to
pub struct QuicClientResponse(
    Pin<Box<dyn Future<Output = Result<DnsResponse, ProtoError>> + Send>>,
);

impl Future for QuicClientResponse {
    type Output = Result<DnsResponse, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx).map_err(ProtoError::from)
    }
}
