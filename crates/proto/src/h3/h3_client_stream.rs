// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt::{self, Display};
use std::future::{self, Future};
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_util::future::FutureExt;
use futures_util::stream::Stream;
use h3::client::SendRequest;
use h3_quinn::OpenStreams;
use http::header::{self, CONTENT_LENGTH};
use quinn::{ClientConfig, Endpoint, EndpointConfig, TransportConfig};
use rustls::ClientConfig as TlsClientConfig;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::error::ProtoError;
use crate::http::Version;
use crate::op::Message;
use crate::quic::quic_socket::QuinnAsyncUdpSocketAdapter;
use crate::quic::QuicLocalAddr;
use crate::udp::{DnsUdpSocket, UdpSocket};
use crate::xfer::{DnsRequest, DnsRequestSender, DnsResponse, DnsResponseStream};

use super::ALPN_H3;

/// A DNS client connection for DNS-over-HTTP/3
#[derive(Clone)]
#[must_use = "futures do nothing unless polled"]
pub struct H3ClientStream {
    // Corresponds to the dns-name of the HTTP/3 server
    name_server_name: Arc<str>,
    name_server: SocketAddr,
    send_request: SendRequest<OpenStreams, Bytes>,
    shutdown_tx: mpsc::Sender<()>,
    is_shutdown: bool,
}

impl Display for H3ClientStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            formatter,
            "H3({},{})",
            self.name_server, self.name_server_name
        )
    }
}

impl H3ClientStream {
    /// Builder for H3ClientStream
    pub fn builder() -> H3ClientStreamBuilder {
        H3ClientStreamBuilder::default()
    }

    async fn inner_send(
        mut h3: SendRequest<OpenStreams, Bytes>,
        message: Bytes,
        name_server_name: Arc<str>,
    ) -> Result<DnsResponse, ProtoError> {
        // build up the http request
        let request =
            crate::http::request::new(Version::Http3, &name_server_name, message.remaining());

        let request =
            request.map_err(|err| ProtoError::from(format!("bad http request: {err}")))?;

        debug!("request: {:#?}", request);

        // Send the request
        let mut stream = h3
            .send_request(request)
            .await
            .map_err(|err| ProtoError::from(format!("h3 send_request error: {err}")))?;

        stream
            .send_data(message)
            .await
            .map_err(|e| ProtoError::from(format!("h3 send_data error: {e}")))?;

        stream
            .finish()
            .await
            .map_err(|err| ProtoError::from(format!("received a stream error: {err}")))?;

        let response = stream
            .recv_response()
            .await
            .map_err(|err| ProtoError::from(format!("h3 recv_response error: {err}")))?;

        debug!("got response: {:#?}", response);

        // get the length of packet
        let content_length = response
            .headers()
            .get(CONTENT_LENGTH)
            .map(|v| v.to_str())
            .transpose()
            .map_err(|e| ProtoError::from(format!("bad headers received: {e}")))?
            .map(usize::from_str)
            .transpose()
            .map_err(|e| ProtoError::from(format!("bad headers received: {e}")))?;

        // TODO: what is a good max here?
        // clamp(512, 4096) says make sure it is at least 512 bytes, and min 4096 says it is at most 4k
        // just a little protection from malicious actors.
        let mut response_bytes =
            BytesMut::with_capacity(content_length.unwrap_or(512).clamp(512, 4096));

        while let Some(partial_bytes) = stream
            .recv_data()
            .await
            .map_err(|e| ProtoError::from(format!("h3 recv_data error: {e}")))?
        {
            debug!("got bytes: {}", partial_bytes.remaining());
            response_bytes.put(partial_bytes);

            // assert the length
            if let Some(content_length) = content_length {
                if response_bytes.len() >= content_length {
                    break;
                }
            }
        }

        // assert the length
        if let Some(content_length) = content_length {
            if response_bytes.len() != content_length {
                // TODO: make explicit error type
                return Err(ProtoError::from(format!(
                    "expected byte length: {}, got: {}",
                    content_length,
                    response_bytes.len()
                )));
            }
        }

        // Was it a successful request?
        if !response.status().is_success() {
            let error_string = String::from_utf8_lossy(response_bytes.as_ref());

            // TODO: make explicit error type
            return Err(ProtoError::from(format!(
                "http unsuccessful code: {}, message: {}",
                response.status(),
                error_string
            )));
        } else {
            // verify content type
            {
                // in the case that the ContentType is not specified, we assume it's the standard DNS format
                let content_type = response
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .map(|h| {
                        h.to_str().map_err(|err| {
                            // TODO: make explicit error type
                            ProtoError::from(format!("ContentType header not a string: {err}"))
                        })
                    })
                    .unwrap_or(Ok(crate::http::MIME_APPLICATION_DNS))?;

                if content_type != crate::http::MIME_APPLICATION_DNS {
                    return Err(ProtoError::from(format!(
                        "ContentType unsupported (must be '{}'): '{}'",
                        crate::http::MIME_APPLICATION_DNS,
                        content_type
                    )));
                }
            }
        };

        // and finally convert the bytes into a DNS message
        let message = Message::from_vec(&response_bytes)?;
        Ok(DnsResponse::new(message, response_bytes.to_vec()))
    }
}

impl DnsRequestSender for H3ClientStream {
    /// This indicates that the HTTP message was successfully sent, and we now have the response.RecvStream
    ///
    /// If the request fails, this will return the error, and it should be assumed that the Stream portion of
    ///   this will have no date.
    ///
    /// ```text
    /// 5.2.  The HTTP Response
    ///
    ///    An HTTP response with a 2xx status code ([RFC7231] Section 6.3)
    ///    indicates a valid DNS response to the query made in the HTTP request.
    ///    A valid DNS response includes both success and failure responses.
    ///    For example, a DNS failure response such as SERVFAIL or NXDOMAIN will
    ///    be the message in a successful 2xx HTTP response even though there
    ///    was a failure at the DNS layer.  Responses with non-successful HTTP
    ///    status codes do not contain DNS answers to the question in the
    ///    corresponding request.  Some of these non-successful HTTP responses
    ///    (e.g., redirects or authentication failures) could mean that clients
    ///    need to make new requests to satisfy the original question.
    ///
    ///    Different response media types will provide more or less information
    ///    from a DNS response.  For example, one response type might include
    ///    the information from the DNS header bytes while another might omit
    ///    it.  The amount and type of information that a media type gives is
    ///    solely up to the format, and not defined in this protocol.
    ///
    ///    The only response type defined in this document is "application/dns-
    ///    message", but it is possible that other response formats will be
    ///    defined in the future.
    ///
    ///    The DNS response for "application/dns-message" in Section 7 MAY have
    ///    one or more EDNS options [RFC6891], depending on the extension
    ///    definition of the extensions given in the DNS request.
    ///
    ///    Each DNS request-response pair is matched to one HTTP exchange.  The
    ///    responses may be processed and transported in any order using HTTP's
    ///    multi-streaming functionality ([RFC7540] Section 5).
    ///
    ///    Section 6.1 discusses the relationship between DNS and HTTP response
    ///    caching.
    ///
    ///    A DNS API server MUST be able to process application/dns-message
    ///    request messages.
    ///
    ///    A DNS API server SHOULD respond with HTTP status code 415
    ///    (Unsupported Media Type) upon receiving a media type it is unable to
    ///    process.
    /// ```
    fn send_message(&mut self, mut message: DnsRequest) -> DnsResponseStream {
        if self.is_shutdown {
            panic!("can not send messages after stream is shutdown")
        }

        // per the RFC, a zero id allows for the HTTP packet to be cached better
        message.set_id(0);

        let bytes = match message.to_vec() {
            Ok(bytes) => bytes,
            Err(err) => return err.into(),
        };

        Box::pin(Self::inner_send(
            self.send_request.clone(),
            Bytes::from(bytes),
            Arc::clone(&self.name_server_name),
        ))
        .into()
    }

    fn shutdown(&mut self) {
        self.is_shutdown = true;
    }

    fn is_shutdown(&self) -> bool {
        self.is_shutdown
    }
}

impl Stream for H3ClientStream {
    type Item = Result<(), ProtoError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.is_shutdown {
            return Poll::Ready(None);
        }

        // just checking if the connection is ok
        if self.shutdown_tx.is_closed() {
            return Poll::Ready(Some(Err(ProtoError::from(
                "h3 connection is already shutdown",
            ))));
        }

        Poll::Ready(Some(Ok(())))
    }
}

/// A H3 connection builder for DNS-over-HTTP/3
#[derive(Clone)]
pub struct H3ClientStreamBuilder {
    crypto_config: TlsClientConfig,
    transport_config: Arc<TransportConfig>,
    bind_addr: Option<SocketAddr>,
}

impl H3ClientStreamBuilder {
    /// Constructs a new H3ClientStreamBuilder with the associated ClientConfig
    pub fn crypto_config(&mut self, crypto_config: TlsClientConfig) -> &mut Self {
        self.crypto_config = crypto_config;
        self
    }

    /// Sets the address to connect from.
    pub fn bind_addr(&mut self, bind_addr: SocketAddr) {
        self.bind_addr = Some(bind_addr);
    }

    /// Creates a new H3Stream to the specified name_server
    ///
    /// # Arguments
    ///
    /// * `name_server` - IP and Port for the remote DNS resolver
    /// * `dns_name` - The DNS name, Subject Public Key Info (SPKI) name, as associated to a certificate
    pub fn build(self, name_server: SocketAddr, dns_name: String) -> H3ClientConnect {
        H3ClientConnect(Box::pin(self.connect(name_server, dns_name)) as _)
    }

    /// Creates a new H3Stream with existing connection
    pub fn build_with_future<S, F>(
        self,
        future: F,
        name_server: SocketAddr,
        dns_name: String,
    ) -> H3ClientConnect
    where
        S: DnsUdpSocket + QuicLocalAddr + 'static,
        F: Future<Output = std::io::Result<S>> + Send + Unpin + 'static,
    {
        H3ClientConnect(Box::pin(self.connect_with_future(future, name_server, dns_name)) as _)
    }

    async fn connect_with_future<S, F>(
        self,
        future: F,
        name_server: SocketAddr,
        dns_name: String,
    ) -> Result<H3ClientStream, ProtoError>
    where
        S: DnsUdpSocket + QuicLocalAddr + 'static,
        F: Future<Output = std::io::Result<S>> + Send,
    {
        let socket = future.await?;
        let wrapper = QuinnAsyncUdpSocketAdapter { io: socket };
        let endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            wrapper,
            Arc::new(quinn::TokioRuntime),
        )?;
        self.connect_inner(endpoint, name_server, dns_name).await
    }

    async fn connect(
        self,
        name_server: SocketAddr,
        dns_name: String,
    ) -> Result<H3ClientStream, ProtoError> {
        let connect = if let Some(bind_addr) = self.bind_addr {
            <tokio::net::UdpSocket as UdpSocket>::connect_with_bind(name_server, bind_addr)
        } else {
            <tokio::net::UdpSocket as UdpSocket>::connect(name_server)
        };

        let socket = connect.await?;
        let socket = socket.into_std()?;
        let endpoint = Endpoint::new(
            EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        self.connect_inner(endpoint, name_server, dns_name).await
    }

    async fn connect_inner(
        self,
        mut endpoint: Endpoint,
        name_server: SocketAddr,
        dns_name: String,
    ) -> Result<H3ClientStream, ProtoError> {
        let mut crypto_config = self.crypto_config;
        // ensure the ALPN protocol is set correctly
        if crypto_config.alpn_protocols.is_empty() {
            crypto_config.alpn_protocols = vec![ALPN_H3.to_vec()];
        }
        let early_data_enabled = crypto_config.enable_early_data;

        let mut client_config = ClientConfig::new(Arc::new(crypto_config));
        client_config.transport_config(self.transport_config.clone());

        endpoint.set_default_client_config(client_config);

        let connecting = endpoint.connect(name_server, &dns_name)?;
        // TODO: for Client/Dynamic update, don't use RTT, for queries, do use it.

        let quic_connection = if early_data_enabled {
            match connecting.into_0rtt() {
                Ok((new_connection, _)) => new_connection,
                Err(connecting) => connecting.await?,
            }
        } else {
            connecting.await?
        };

        let h3_connection = h3_quinn::Connection::new(quic_connection);
        let (mut driver, send_request) = h3::client::new(h3_connection)
            .await
            .map_err(|e| ProtoError::from(format!("h3 connection failed: {e}")))?;

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        // TODO: hand this back for others to run rather than spawning here?
        debug!("h3 connection is ready: {}", name_server);
        tokio::spawn(async move {
            tokio::select! {
                res = future::poll_fn(|cx| driver.poll_close(cx)) => {
                    res.map_err(|e| warn!("h3 connection failed: {e}"))
                }
                _ = shutdown_rx.recv() => {
                    debug!("h3 connection is shutting down: {}", name_server);
                    Ok(())
                }
            }
        });

        Ok(H3ClientStream {
            name_server_name: Arc::from(dns_name),
            name_server,
            send_request,
            shutdown_tx,
            is_shutdown: false,
        })
    }
}

impl Default for H3ClientStreamBuilder {
    fn default() -> Self {
        Self {
            crypto_config: super::client_config_tls13().unwrap(),
            transport_config: Arc::new(super::transport()),
            bind_addr: None,
        }
    }
}

/// A future that resolves to an H3ClientStream
pub struct H3ClientConnect(
    Pin<Box<dyn Future<Output = Result<H3ClientStream, ProtoError>> + Send>>,
);

impl Future for H3ClientConnect {
    type Output = Result<H3ClientStream, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.poll_unpin(cx)
    }
}

/// A future that resolves to
pub struct H3ClientResponse(Pin<Box<dyn Future<Output = Result<DnsResponse, ProtoError>> + Send>>);

impl Future for H3ClientResponse {
    type Output = Result<DnsResponse, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx).map_err(ProtoError::from)
    }
}

#[cfg(all(test, any(feature = "native-certs", feature = "webpki-roots")))]
mod tests {
    use std::net::SocketAddr;
    use std::str::FromStr;

    use rustls::KeyLogFile;
    use tokio::runtime::Runtime;
    use tokio::task::JoinSet;

    use crate::op::{Message, Query, ResponseCode};
    use crate::rr::rdata::{A, AAAA};
    use crate::rr::{Name, RecordType};
    use crate::xfer::{DnsRequestOptions, FirstAnswer};

    use super::*;

    #[test]
    fn test_h3_google() {
        //env_logger::try_init().ok();

        let google = SocketAddr::from(([8, 8, 8, 8], 443));
        let mut request = Message::new();
        let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        request.add_query(query);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let mut client_config = super::super::client_config_tls13().unwrap();
        client_config.key_log = Arc::new(KeyLogFile::new());

        let mut h3_builder = H3ClientStream::builder();
        h3_builder.crypto_config(client_config);
        let connect = h3_builder.build(google, "dns.google".to_string());

        // tokio runtime stuff...
        let runtime = Runtime::new().expect("could not start runtime");
        let mut h3 = runtime.block_on(connect).expect("h3 connect failed");

        let response = runtime
            .block_on(h3.send_message(request).first_answer())
            .expect("send_message failed");

        let record = &response.answers()[0];
        let addr = record.data().as_a().expect("Expected A record");

        assert_eq!(addr, &A::new(93, 184, 215, 14));

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
                .block_on(h3.send_message(request.clone()).first_answer())
                .expect("send_message failed");
            if response.response_code() == ResponseCode::ServFail {
                continue;
            }

            let record = &response.answers()[0];
            let addr = record
                .data()
                .as_aaaa()
                .expect("invalid response, expected A record");

            assert_eq!(
                addr,
                &AAAA::new(0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c)
            );
        }
    }

    #[test]
    fn test_h3_google_with_pure_ip_address_server() {
        //env_logger::try_init().ok();

        let google = SocketAddr::from(([8, 8, 8, 8], 443));
        let mut request = Message::new();
        let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        request.add_query(query);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let mut client_config = super::super::client_config_tls13().unwrap();
        client_config.key_log = Arc::new(KeyLogFile::new());

        let mut h3_builder = H3ClientStream::builder();
        h3_builder.crypto_config(client_config);
        let connect = h3_builder.build(google, google.ip().to_string());

        // tokio runtime stuff...
        let runtime = Runtime::new().expect("could not start runtime");
        let mut h3 = runtime.block_on(connect).expect("h3 connect failed");

        let response = runtime
            .block_on(h3.send_message(request).first_answer())
            .expect("send_message failed");

        let record = &response.answers()[0];
        let addr = record.data().as_a().expect("Expected A record");

        assert_eq!(addr, &A::new(93, 184, 215, 14));

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
                .block_on(h3.send_message(request.clone()).first_answer())
                .expect("send_message failed");
            if response.response_code() == ResponseCode::ServFail {
                continue;
            }

            let record = &response.answers()[0];
            let addr = record
                .data()
                .as_aaaa()
                .expect("invalid response, expected A record");

            assert_eq!(
                addr,
                &AAAA::new(0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c)
            );
        }
    }

    /// Currently fails, see <https://github.com/hyperium/h3/issues/206>.
    #[test]
    #[ignore] // cloudflare has been unreliable as a public test service.
    fn test_h3_cloudflare() {
        // self::env_logger::try_init().ok();

        let cloudflare = SocketAddr::from(([1, 1, 1, 1], 443));
        let mut request = Message::new();
        let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        request.add_query(query);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let mut client_config = super::super::client_config_tls13().unwrap();
        client_config.key_log = Arc::new(KeyLogFile::new());

        let mut h3_builder = H3ClientStream::builder();
        h3_builder.crypto_config(client_config);
        let connect = h3_builder.build(cloudflare, "cloudflare-dns.com".to_string());

        // tokio runtime stuff...
        let runtime = Runtime::new().expect("could not start runtime");
        let mut h3 = runtime.block_on(connect).expect("h3 connect failed");

        let response = runtime
            .block_on(h3.send_message(request).first_answer())
            .expect("send_message failed");

        let record = &response.answers()[0];
        let addr = record
            .data()
            .as_a()
            .expect("invalid response, expected A record");

        assert_eq!(addr, &A::new(93, 184, 215, 14));

        //
        // assert that the connection works for a second query
        let mut request = Message::new();
        let query = Query::query(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::AAAA,
        );
        request.add_query(query);
        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let response = runtime
            .block_on(h3.send_message(request).first_answer())
            .expect("send_message failed");

        let record = &response.answers()[0];
        let addr = record
            .data()
            .as_aaaa()
            .expect("invalid response, expected A record");

        assert_eq!(
            addr,
            &AAAA::new(0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c)
        );
    }

    #[test]
    #[allow(clippy::print_stdout)]
    fn test_h3_client_stream_clonable() {
        // use google
        let google = SocketAddr::from(([8, 8, 8, 8], 443));

        let mut client_config = super::super::client_config_tls13().unwrap();
        client_config.key_log = Arc::new(KeyLogFile::new());

        let mut h3_builder = H3ClientStream::builder();
        h3_builder.crypto_config(client_config);
        let connect = h3_builder.build(google, "dns.google".to_string());

        // tokio runtime stuff...
        let runtime = Runtime::new().expect("could not start runtime");
        let h3 = runtime.block_on(connect).expect("h3 connect failed");

        // prepare request
        let mut request = Message::new();
        let query = Query::query(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::AAAA,
        );
        request.add_query(query);
        let request = DnsRequest::new(request, DnsRequestOptions::default());

        runtime.block_on(async move {
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
        });
    }
}
