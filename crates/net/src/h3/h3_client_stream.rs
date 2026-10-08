// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::fmt::{self, Display};
use core::future::{Future, poll_fn};
use core::net::SocketAddr;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures_util::stream::Stream;
use h3::client::SendRequest;
use h3_quinn::OpenStreams;
use http::Request;
use http::response::Parts;
use quinn::{Endpoint, TransportConfig};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, warn};

use super::{BodyStream, h3_config};
use crate::error::NetError;
use crate::http::{HttpSender, RequestContext, SetHeaders, Version, content_length, fetch_body};
use crate::proto::ProtoError;
use crate::proto::op::DnsRequest;
use crate::quic::connect_quic;
use crate::runtime::{RuntimeProvider, Spawn};
use crate::tls::{alpn, tls_config};
use crate::udp::UdpSocket;
use crate::xfer::{CONNECT_TIMEOUT, DnsExchange, DnsRequestSender, DnsResponseStream};

/// A DNS client connection for DNS-over-HTTP/3
#[derive(Clone)]
#[must_use = "futures do nothing unless polled"]
pub struct H3ClientStream {
    // Corresponds to the dns-name of the HTTP/3 server
    name_server: SocketAddr,
    send_request: SendRequest<OpenStreams, Bytes>,
    context: Arc<RequestContext>,
    shutdown_tx: mpsc::Sender<()>,
    is_shutdown: bool,
}

impl H3ClientStream {
    /// Builder for H3ClientStream
    pub fn builder() -> H3ClientStreamBuilder {
        H3ClientStreamBuilder {
            crypto_config: None,
            transport_config: Arc::new(h3_config::transport()),
            bind_addr: None,
            set_headers: None,
            disable_grease: false,
            connect_timeout: CONNECT_TIMEOUT,
        }
    }
}

impl HttpSender for H3ClientStream {
    async fn send_http_request(
        &mut self,
        request: Request<()>,
        message: Bytes,
    ) -> Result<(Parts, BytesMut), NetError> {
        // Send the request
        let mut stream = self.send_request.send_request(request).await?;
        stream.send_data(message).await?;
        stream.finish().await?;

        let (parts, ()) = stream.recv_response().await?.into_parts();

        // get the length of packet
        let content_length = content_length(&parts.headers)?;

        // read the response body
        let response_bytes = fetch_body(
            BodyStream::from(|cx: &mut Context<'_>| stream.poll_recv_data(cx)),
            content_length,
        )
        .await?;

        Ok((parts, response_bytes))
    }

    fn context(&self) -> &RequestContext {
        &self.context
    }
}

impl DnsRequestSender for H3ClientStream {
    /// See `crate::http::send_message`
    fn send_message(&mut self, request: DnsRequest) -> DnsResponseStream {
        crate::http::send_message(self, self.is_shutdown, request)
    }

    fn shutdown(&mut self) {
        self.is_shutdown = true;
    }

    fn is_shutdown(&self) -> bool {
        self.is_shutdown
    }
}

impl Stream for H3ClientStream {
    type Item = Result<(), NetError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.is_shutdown {
            return Poll::Ready(None);
        }

        // just checking if the connection is ok
        if self.shutdown_tx.is_closed() {
            return Poll::Ready(Some(Err(NetError::from(
                "h3 connection is already shutdown",
            ))));
        }

        Poll::Ready(Some(Ok(())))
    }
}

impl Display for H3ClientStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            formatter,
            "H3({},{})",
            self.name_server, self.context.server_name
        )
    }
}

/// A H3 connection builder for DNS-over-HTTP/3
#[derive(Clone)]
pub struct H3ClientStreamBuilder {
    crypto_config: Option<rustls::ClientConfig>,
    transport_config: Arc<TransportConfig>,
    bind_addr: Option<SocketAddr>,
    set_headers: Option<Arc<dyn SetHeaders>>,
    disable_grease: bool,
    connect_timeout: Duration,
}

impl H3ClientStreamBuilder {
    /// Constructs a new H3ClientStreamBuilder with the associated ClientConfig
    pub fn crypto_config(mut self, crypto_config: rustls::ClientConfig) -> Self {
        self.crypto_config = Some(crypto_config);
        self
    }

    /// Sets the address to connect from.
    pub fn bind_addr(mut self, bind_addr: SocketAddr) -> Self {
        self.bind_addr = Some(bind_addr);
        self
    }

    /// Set the [`SetHeaders`] trait object used to inject dynamic headers into the DoH request
    pub fn set_headers(&mut self, headers: Arc<dyn SetHeaders>) {
        self.set_headers.replace(headers);
    }

    /// Sets whether to disable GREASE
    pub fn disable_grease(mut self, disable_grease: bool) -> Self {
        self.disable_grease = disable_grease;
        self
    }

    /// Override the connect timeout (default: 2 seconds).
    ///
    /// This controls the QUIC connect and the HTTP/3 handshake timeouts.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Creates a new H3Stream to the specified name_server
    ///
    /// # Arguments
    ///
    /// * `name_server` - IP and Port for the remote DNS resolver
    /// * `server_name` - The DNS name associated with a certificate
    pub fn build(
        self,
        name_server: SocketAddr,
        server_name: Arc<str>,
        path: Arc<str>,
    ) -> impl Future<Output = Result<H3ClientStream, NetError>> + Send + 'static {
        self.connect(name_server, server_name, path)
    }

    /// Creates a new [`DnsExchange`] wrapping the [`H3ClientStream`] from this builder
    pub async fn exchange<P: RuntimeProvider>(
        self,
        socket: Arc<dyn quinn::AsyncUdpSocket>,
        name_server: SocketAddr,
        server_name: Arc<str>,
        path: Arc<str>,
        provider: P,
    ) -> Result<DnsExchange<P>, NetError> {
        let stream = self
            .connect_with_future(socket, name_server, server_name, path)
            .await?;
        let (exchange, bg) = DnsExchange::from_stream(stream);
        provider.create_handle().spawn_bg(bg);
        Ok(exchange)
    }

    /// Creates a new H3Stream with existing connection
    pub fn build_with_future(
        self,
        socket: Arc<dyn quinn::AsyncUdpSocket>,
        name_server: SocketAddr,
        server_name: Arc<str>,
        path: Arc<str>,
    ) -> impl Future<Output = Result<H3ClientStream, NetError>> + Send + 'static {
        self.connect_with_future(socket, name_server, server_name, path)
    }

    async fn connect_with_future(
        self,
        socket: Arc<dyn quinn::AsyncUdpSocket>,
        name_server: SocketAddr,
        server_name: Arc<str>,
        path: Arc<str>,
    ) -> Result<H3ClientStream, NetError> {
        let endpoint = Endpoint::new_with_abstract_socket(
            h3_config::endpoint(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        self.connect_inner(endpoint, name_server, server_name, path)
            .await
    }

    async fn connect(
        self,
        name_server: SocketAddr,
        server_name: Arc<str>,
        path: Arc<str>,
    ) -> Result<H3ClientStream, NetError> {
        let connect = if let Some(bind_addr) = self.bind_addr {
            <tokio::net::UdpSocket as UdpSocket>::connect_with_bind(name_server, bind_addr)
        } else {
            <tokio::net::UdpSocket as UdpSocket>::connect(name_server)
        };

        let socket = connect.await?;
        let socket = socket.into_std()?;
        let endpoint = Endpoint::new(
            h3_config::endpoint(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        self.connect_inner(endpoint, name_server, server_name, path)
            .await
    }

    async fn connect_inner(
        self,
        endpoint: Endpoint,
        name_server: SocketAddr,
        server_name: Arc<str>,
        path: Arc<str>,
    ) -> Result<H3ClientStream, NetError> {
        let quic_connection = timeout(
            self.connect_timeout,
            connect_quic(
                name_server,
                server_name.clone(),
                alpn::H3,
                match self.crypto_config {
                    Some(crypto_config) => crypto_config,
                    None => tls_config::client_config()?,
                },
                self.transport_config,
                endpoint,
            ),
        )
        .await
        .map_err(|_| NetError::Timeout)??;

        let h3_connection = h3_quinn::Connection::new(quic_connection);
        let mut builder = h3::client::builder();
        builder.send_grease(!self.disable_grease);
        let future = builder.build(h3_connection);
        let (mut driver, send_request) = match timeout(self.connect_timeout, future).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                return Err(ProtoError::from(format!("h3 connection failed: {e}")).into());
            }
            Err(_) => return Err(NetError::Timeout),
        };

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        // TODO: hand this back for others to run rather than spawning here?
        debug!("h3 connection is ready: {}", name_server);
        tokio::spawn(async move {
            tokio::select! {
                error = poll_fn(|cx| driver.poll_close(cx)) => {
                    // `poll_close()` strangely unconditionally returns a `ConnectionError`
                    if !error.is_h3_no_error() {
                        warn!(%error, "h3 connection failed to close")
                    }
                }
                _ = shutdown_rx.recv() => {
                    debug!("h3 connection is shutting down: {}", name_server);
                }
            }
        });

        Ok(H3ClientStream {
            name_server,
            send_request,
            context: Arc::new(RequestContext {
                version: Version::Http3,
                server_name,
                query_path: path,
                set_headers: self.set_headers,
            }),
            shutdown_tx,
            is_shutdown: false,
        })
    }
}

#[cfg(all(
    test,
    any(feature = "rustls-platform-verifier", feature = "webpki-roots")
))]
mod tests {
    use core::net::SocketAddr;
    use core::str::FromStr;
    use std::println;

    use rustls::KeyLogFile;
    use test_support::subscribe;
    use tokio::task::JoinSet;

    use super::*;
    use crate::proto::op::{DnsRequestOptions, Edns, Message, Query};
    use crate::proto::rr::{Name, RData, RecordType};
    use crate::xfer::FirstAnswer;

    #[tokio::test]
    async fn test_h3_google() {
        subscribe();

        let google = SocketAddr::from(([8, 8, 8, 8], 443));
        let mut request = Message::query();
        let query = Query::new(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        request.add_query(query);
        request.metadata.recursion_desired = true;
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        request.edns = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let mut client_config = tls_config::client_config().unwrap();
        client_config.key_log = Arc::new(KeyLogFile::new());

        let mut h3 = H3ClientStream::builder()
            .crypto_config(client_config)
            .build(google, Arc::from("dns.google"), Arc::from("/dns-query"))
            .await
            .expect("h3 connect failed");

        let response = h3
            .send_message(request)
            .first_answer()
            .await
            .expect("send_message failed");

        assert!(
            response
                .answers
                .iter()
                .any(|record| matches!(record.data, RData::A(_)))
        );

        //
        // assert that the connection works for a second query
        let mut request = Message::query();
        let query = Query::new(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::AAAA,
        );
        request.add_query(query);
        request.metadata.recursion_desired = true;
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        request.edns = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let response = h3
            .send_message(request.clone())
            .first_answer()
            .await
            .expect("send_message failed");

        assert!(
            response
                .answers
                .iter()
                .any(|record| matches!(record.data, RData::AAAA(_)))
        );
    }

    #[tokio::test]
    async fn test_h3_google_with_pure_ip_address_server() {
        subscribe();

        let google = SocketAddr::from(([8, 8, 8, 8], 443));
        let mut request = Message::query();
        let query = Query::new(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        request.add_query(query);
        request.metadata.recursion_desired = true;
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        request.edns = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let mut client_config = tls_config::client_config().unwrap();
        client_config.key_log = Arc::new(KeyLogFile::new());

        let mut h3 = H3ClientStream::builder()
            .crypto_config(client_config)
            .build(
                google,
                Arc::from(google.ip().to_string()),
                Arc::from("/dns-query"),
            )
            .await
            .expect("h3 connect failed");

        let response = h3
            .send_message(request)
            .first_answer()
            .await
            .expect("send_message failed");

        assert!(
            response
                .answers
                .iter()
                .any(|record| matches!(record.data, RData::A(_)))
        );

        //
        // assert that the connection works for a second query
        let mut request = Message::query();
        let query = Query::new(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::AAAA,
        );
        request.add_query(query);
        request.metadata.recursion_desired = true;
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        request.edns = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let response = h3
            .send_message(request.clone())
            .first_answer()
            .await
            .expect("send_message failed");

        assert!(
            response
                .answers
                .iter()
                .any(|record| matches!(record.data, RData::AAAA(_)))
        );
    }

    #[tokio::test]
    async fn test_h3_cloudflare() {
        subscribe();

        let cloudflare = SocketAddr::from(([1, 1, 1, 1], 443));
        let mut request = Message::query();
        let query = Query::new(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        request.add_query(query);
        request.metadata.recursion_desired = true;
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        request.edns = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let mut client_config = tls_config::client_config().unwrap();
        client_config.key_log = Arc::new(KeyLogFile::new());

        let mut h3 = H3ClientStream::builder()
            .crypto_config(client_config)
            // Currently CF is using a broken GREASE implementation, see <https://github.com/hyperium/h3/issues/206>.
            .disable_grease(true)
            .build(
                cloudflare,
                Arc::from("cloudflare-dns.com"),
                Arc::from("/dns-query"),
            )
            .await
            .expect("h3 connect failed");

        let response = h3
            .send_message(request)
            .first_answer()
            .await
            .expect("send_message failed");

        assert!(
            response
                .answers
                .iter()
                .any(|record| matches!(record.data, RData::A(_)))
        );

        //
        // assert that the connection works for a second query
        let mut request = Message::query();
        let query = Query::new(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::AAAA,
        );
        request.add_query(query);
        request.metadata.recursion_desired = true;
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        request.edns = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let response = h3
            .send_message(request)
            .first_answer()
            .await
            .expect("send_message failed");

        assert!(
            response
                .answers
                .iter()
                .any(|record| matches!(record.data, RData::AAAA(_)))
        );
    }

    #[tokio::test]
    #[allow(clippy::print_stdout)]
    async fn test_h3_client_stream_clonable() {
        subscribe();

        // use google
        let google = SocketAddr::from(([8, 8, 8, 8], 443));

        let mut client_config = tls_config::client_config().unwrap();
        client_config.key_log = Arc::new(KeyLogFile::new());

        let h3 = H3ClientStream::builder()
            .crypto_config(client_config)
            .build(google, Arc::from("dns.google"), Arc::from("/dns-query"))
            .await
            .expect("h3 connect failed");

        // prepare request
        let mut request = Message::query();
        let query = Query::new(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::AAAA,
        );
        request.add_query(query);
        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let mut join_set = JoinSet::new();

        for i in 0..50 {
            let mut h3 = h3.clone();
            let request = request.clone();

            join_set.spawn(async move {
                let start = std::time::Instant::now();
                h3.send_message(request)
                    .first_answer()
                    .await
                    .expect("send_message failed");
                println!("request[{i}] completed: {:?}", start.elapsed());
            });
        }

        let total = join_set.len();
        let mut idx = 0usize;
        while join_set.join_next().await.is_some() {
            println!("join_set completed {idx}/{total}");
            idx += 1;
        }
    }
}
