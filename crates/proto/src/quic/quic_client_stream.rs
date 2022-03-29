// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::convert::TryInto;
use std::fmt::{self, Display};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::ops::DerefMut;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use futures_util::future::{FutureExt, TryFutureExt};
use futures_util::ready;
use futures_util::stream::Stream;
use log::{debug, warn};
use quinn::{
    ClientConfig, Connection, Endpoint, EndpointConfig, NewConnection, OpenBi, TransportConfig,
    VarInt,
};
use rustls::ClientConfig as TlsClientConfig;

use crate::{
    error::ProtoError,
    iocompat::AsyncIoStdAsTokio,
    quic::quic_stream::{DoqErrorCode, QuicStream},
    tcp::Connect,
    udp::UdpSocket,
    xfer::{DnsRequest, DnsRequestSender, DnsResponse, DnsResponseStream, SerialMessage},
};

use super::quic_stream;

/// A DNS client connection for DNS-over-Quic
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
            "Quic({},{})",
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
    /// The send loop for Quic in DNS stipulates that a new Quic "steam" should be opened and use for sending data.
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

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        todo!()
    }
}

/// A Quic connection builder for DNS-over-Quic
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

    /// Sets a good set of defaults for the DoQ transport config
    pub fn default_transport_config(&mut self) -> &mut Self {
        self.set_transport_config(TransportConfig::default())
    }

    /// This will override the max_concurrent_bidi_streams and max_concurrent_uni_streams to 0, as DoQ doesn't support server push
    pub fn set_transport_config(&mut self, mut transport_config: TransportConfig) -> &mut Self {
        sanitize_transport_config(&mut transport_config);
        self.transport_config = Arc::new(transport_config);

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

        let (mut endpoint, _incoming) = Endpoint::new(EndpointConfig::default(), None, socket)?;

        // ensure the ALPN protocol is set correctly
        let mut crypto_config = self.crypto_config;
        crypto_config.alpn_protocols = vec![quic_stream::DOQ_ALPN.to_vec()];

        let client_config = ClientConfig::new(Arc::new(crypto_config));
        endpoint.set_default_client_config(client_config);

        let connecting = endpoint.connect(name_server, &dns_name)?;
        // TODO: for Client/Dynamic update, don't use RTT, for queries, do use it.

        let connection = connecting.await?;
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

fn sanitize_transport_config(transport_config: &mut TransportConfig) {
    transport_config.max_concurrent_bidi_streams(VarInt::from_u32(0));
    transport_config.max_concurrent_uni_streams(VarInt::from_u32(0));
}

fn client_config_tls12_webpki_roots() -> TlsClientConfig {
    use rustls::{OwnedTrustAnchor, RootCertStore};
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let client_config = TlsClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    client_config
}

impl Default for QuicClientStreamBuilder {
    fn default() -> Self {
        let mut transport_config = TransportConfig::default();
        sanitize_transport_config(&mut transport_config);

        let client_config = client_config_tls12_webpki_roots();

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

struct TlsConfig {
    client_config: Arc<TlsClientConfig>,
    dns_name: Arc<str>,
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::str::FromStr;

    use rustls::KeyLogFile;
    use tokio::net::UdpSocket as TokioUdpSocket;
    use tokio::runtime::Runtime;

    use crate::iocompat::AsyncIoTokioAsStd;
    use crate::op::{Message, Query, ResponseCode};
    use crate::rr::{Name, RData, RecordType};
    use crate::xfer::{DnsRequestOptions, FirstAnswer};

    use super::*;

    #[test]
    #[cfg(off)]
    fn test_quic_google() {
        env_logger::builder().is_test(true).build();

        let google = SocketAddr::from(([8, 8, 8, 8], 853));
        let mut request = Message::new();
        let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        request.add_query(query);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let mut client_config = client_config_tls12_webpki_roots();
        client_config.key_log = Arc::new(KeyLogFile::new());

        let mut builder = QuicClientStreamBuilder::default();
        builder.crypto_config(Arc::new(client_config));

        let connect = builder.build(google, "dns.google".to_string());
        println!("starting quic connect");

        // tokio runtime stuff...
        let runtime = Runtime::new().expect("could not start runtime");
        let mut quic = runtime.block_on(connect).expect("quic connect failed");
        println!("completed quic connect");

        let response = runtime
            .block_on(quic.send_message(request).first_answer())
            .expect("send_message failed");

        let record = &response.answers()[0];
        let addr = record
            .data()
            .and_then(RData::as_a)
            .expect("Expected A record");

        assert_eq!(addr, &Ipv4Addr::new(93, 184, 216, 34));

        //
        // assert that the connection works for a second query
        let mut request = Message::new();
        let query = Query::query(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::AAAA,
        );
        request.add_query(query);
        let request = DnsRequest::new(request, DnsRequestOptions::default());

        for _ in 0..3 {
            let response = runtime
                .block_on(quic.send_message(request.clone()).first_answer())
                .expect("send_message failed");
            if response.response_code() == ResponseCode::ServFail {
                continue;
            }

            let record = &response.answers()[0];
            let addr = record
                .data()
                .and_then(RData::as_aaaa)
                .expect("invalid response, expected A record");

            assert_eq!(
                addr,
                &Ipv6Addr::new(0x2606, 0x2800, 0x0220, 0x0001, 0x0248, 0x1893, 0x25c8, 0x1946)
            );
        }
    }
}
