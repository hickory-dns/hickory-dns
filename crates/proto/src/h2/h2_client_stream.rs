// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::fmt::{self, Display};
use core::future::Future;
use core::ops::DerefMut;
use core::pin::Pin;
use core::str::FromStr;
use core::task::{Context, Poll};
use std::io;
use std::net::SocketAddr;

use bytes::{Buf, Bytes, BytesMut};
use futures_util::future::{FutureExt, TryFutureExt};
use futures_util::ready;
use futures_util::stream::Stream;
use h2::client::{Connection, SendRequest};
use http::header::{self, CONTENT_LENGTH};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::time::{error, timeout};
use tokio_rustls::{TlsConnector, client::TlsStream as TokioTlsClientStream};
use tracing::{debug, warn};

use crate::error::ProtoError;
use crate::http::Version;
use crate::runtime::RuntimeProvider;
use crate::runtime::iocompat::AsyncIoStdAsTokio;
use crate::tcp::DnsTcpStream;
use crate::xfer::{CONNECT_TIMEOUT, DnsRequest, DnsRequestSender, DnsResponse, DnsResponseStream};

const ALPN_H2: &[u8] = b"h2";

/// A DNS client connection for DNS-over-HTTPS
#[derive(Clone)]
#[must_use = "futures do nothing unless polled"]
pub struct HttpsClientStream {
    // Corresponds to the dns-name of the HTTPS server
    name_server_name: Arc<str>,
    query_path: Arc<str>,
    name_server: SocketAddr,
    h2: SendRequest<Bytes>,
    is_shutdown: bool,
}

impl Display for HttpsClientStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            formatter,
            "HTTPS({},{})",
            self.name_server, self.name_server_name
        )
    }
}

impl HttpsClientStream {
    async fn inner_send(
        h2: SendRequest<Bytes>,
        message: Bytes,
        name_server_name: Arc<str>,
        query_path: Arc<str>,
    ) -> Result<DnsResponse, ProtoError> {
        let mut h2 = match h2.ready().await {
            Ok(h2) => h2,
            Err(err) => {
                // TODO: make specific error
                return Err(ProtoError::from(format!("h2 send_request error: {err}")));
            }
        };

        // build up the http request
        let request = crate::http::request::new(
            Version::Http2,
            &name_server_name,
            &query_path,
            message.remaining(),
        );

        let request =
            request.map_err(|err| ProtoError::from(format!("bad http request: {err}")))?;

        debug!("request: {:#?}", request);

        // Send the request
        let (response_future, mut send_stream) = h2
            .send_request(request, false)
            .map_err(|err| ProtoError::from(format!("h2 send_request error: {err}")))?;

        send_stream
            .send_data(message, true)
            .map_err(|e| ProtoError::from(format!("h2 send_data error: {e}")))?;

        let mut response_stream = response_future
            .await
            .map_err(|err| ProtoError::from(format!("received a stream error: {err}")))?;

        debug!("got response: {:#?}", response_stream);

        // get the length of packet
        let content_length = response_stream
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
            BytesMut::with_capacity(content_length.unwrap_or(512).clamp(512, 4_096));

        while let Some(partial_bytes) = response_stream.body_mut().data().await {
            let partial_bytes =
                partial_bytes.map_err(|e| ProtoError::from(format!("bad http request: {e}")))?;

            debug!("got bytes: {}", partial_bytes.len());
            response_bytes.extend(partial_bytes);

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
        if !response_stream.status().is_success() {
            let error_string = String::from_utf8_lossy(response_bytes.as_ref());

            // TODO: make explicit error type
            return Err(ProtoError::from(format!(
                "http unsuccessful code: {}, message: {}",
                response_stream.status(),
                error_string
            )));
        } else {
            // verify content type
            {
                // in the case that the ContentType is not specified, we assume it's the standard DNS format
                let content_type = response_stream
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
        DnsResponse::from_buffer(response_bytes.to_vec())
    }
}

impl DnsRequestSender for HttpsClientStream {
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
    fn send_message(&mut self, mut request: DnsRequest) -> DnsResponseStream {
        if self.is_shutdown {
            panic!("can not send messages after stream is shutdown")
        }

        // per the RFC, a zero id allows for the HTTP packet to be cached better
        request.set_id(0);

        let bytes = match request.to_vec() {
            Ok(bytes) => bytes,
            Err(err) => return err.into(),
        };

        Box::pin(Self::inner_send(
            self.h2.clone(),
            Bytes::from(bytes),
            Arc::clone(&self.name_server_name),
            Arc::clone(&self.query_path),
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

impl Stream for HttpsClientStream {
    type Item = Result<(), ProtoError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.is_shutdown {
            return Poll::Ready(None);
        }

        // just checking if the connection is ok
        match self.h2.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Some(Ok(()))),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(ProtoError::from(format!(
                "h2 stream errored: {e}",
            ))))),
        }
    }
}

/// A HTTPS connection builder for DNS-over-HTTPS
#[derive(Clone)]
pub struct HttpsClientStreamBuilder<P> {
    provider: P,
    client_config: Arc<ClientConfig>,
    bind_addr: Option<SocketAddr>,
}

impl<P: RuntimeProvider> HttpsClientStreamBuilder<P> {
    /// Constructs a new TlsStreamBuilder with the associated ClientConfig
    pub fn with_client_config(client_config: Arc<ClientConfig>, provider: P) -> Self {
        Self {
            provider,
            client_config,
            bind_addr: None,
        }
    }

    /// Sets the address to connect from.
    pub fn bind_addr(&mut self, bind_addr: SocketAddr) {
        self.bind_addr = Some(bind_addr);
    }

    /// Creates a new HttpsStream to the specified name_server
    ///
    /// # Arguments
    ///
    /// * `name_server` - IP and Port for the remote DNS resolver
    /// * `dns_name` - The DNS name associated with a certificate
    /// * `http_endpoint` - The HTTP endpoint where the remote DNS resolver provides service, typically `/dns-query`
    pub fn build(
        mut self,
        name_server: SocketAddr,
        dns_name: String,
        http_endpoint: String,
    ) -> HttpsClientConnect<P::Tcp> {
        // ensure the ALPN protocol is set correctly
        if self.client_config.alpn_protocols.is_empty() {
            let mut client_config = (*self.client_config).clone();
            client_config.alpn_protocols = vec![ALPN_H2.to_vec()];

            self.client_config = Arc::new(client_config);
        }

        let tls = TlsConfig {
            client_config: self.client_config,
            dns_name: Arc::from(dns_name),
            http_endpoint: Arc::from(http_endpoint),
        };

        let connect = self.provider.connect_tcp(name_server, self.bind_addr, None);
        HttpsClientConnect(HttpsClientConnectState::TcpConnecting {
            connect,
            name_server,
            tls: Some(tls),
        })
    }
}

/// A future that resolves to an HttpsClientStream
pub struct HttpsClientConnect<S>(HttpsClientConnectState<S>)
where
    S: DnsTcpStream;

impl<S: DnsTcpStream> HttpsClientConnect<S> {
    /// Creates a new HttpsStream with existing connection
    pub fn new<F>(
        future: F,
        mut client_config: Arc<ClientConfig>,
        name_server: SocketAddr,
        dns_name: String,
        http_endpoint: String,
    ) -> Self
    where
        S: DnsTcpStream,
        F: Future<Output = std::io::Result<S>> + Send + Unpin + 'static,
    {
        // ensure the ALPN protocol is set correctly
        if client_config.alpn_protocols.is_empty() {
            let mut client_cfg = (*client_config).clone();
            client_cfg.alpn_protocols = vec![ALPN_H2.to_vec()];

            client_config = Arc::new(client_cfg);
        }

        let tls = TlsConfig {
            client_config,
            dns_name: Arc::from(dns_name),
            http_endpoint: Arc::from(http_endpoint),
        };

        Self(HttpsClientConnectState::TcpConnecting {
            connect: Box::pin(future),
            name_server,
            tls: Some(tls),
        })
    }
}

impl<S> Future for HttpsClientConnect<S>
where
    S: DnsTcpStream,
{
    type Output = Result<HttpsClientStream, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.poll_unpin(cx)
    }
}

struct TlsConfig {
    client_config: Arc<ClientConfig>,
    dns_name: Arc<str>,
    http_endpoint: Arc<str>,
}

#[allow(clippy::large_enum_variant)]
#[allow(clippy::type_complexity)]
enum HttpsClientConnectState<S>
where
    S: DnsTcpStream,
{
    TcpConnecting {
        connect: Pin<Box<dyn Future<Output = io::Result<S>> + Send>>,
        name_server: SocketAddr,
        tls: Option<TlsConfig>,
    },
    TlsConnecting {
        // TODO: also abstract away Tokio TLS in RuntimeProvider.
        tls: Pin<
            Box<
                dyn Future<
                        Output = Result<
                            Result<TokioTlsClientStream<AsyncIoStdAsTokio<S>>, io::Error>,
                            error::Elapsed,
                        >,
                    > + Send,
            >,
        >,
        name_server_name: Arc<str>,
        name_server: SocketAddr,
        query_path: Arc<str>,
    },
    H2Handshake {
        handshake: Pin<
            Box<
                dyn Future<
                        Output = Result<
                            (
                                SendRequest<Bytes>,
                                Connection<TokioTlsClientStream<AsyncIoStdAsTokio<S>>, Bytes>,
                            ),
                            h2::Error,
                        >,
                    > + Send,
            >,
        >,
        name_server_name: Arc<str>,
        name_server: SocketAddr,
        query_path: Arc<str>,
    },
    Connected(Option<HttpsClientStream>),
    Errored(Option<ProtoError>),
}

impl<S> Future for HttpsClientConnectState<S>
where
    S: DnsTcpStream,
{
    type Output = Result<HttpsClientStream, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let next = match &mut *self.as_mut() {
                Self::TcpConnecting {
                    connect,
                    name_server,
                    tls,
                } => {
                    let tcp = ready!(connect.poll_unpin(cx))?;

                    debug!("tcp connection established to: {}", name_server);
                    let tls = tls
                        .take()
                        .expect("programming error, tls should not be None here");
                    let name_server_name = Arc::clone(&tls.dns_name);
                    let query_path = Arc::clone(&tls.http_endpoint);

                    match ServerName::try_from(&*tls.dns_name) {
                        Ok(dns_name) => Self::TlsConnecting {
                            name_server_name,
                            name_server: *name_server,
                            tls: Box::pin(timeout(
                                CONNECT_TIMEOUT,
                                TlsConnector::from(tls.client_config)
                                    .connect(dns_name.to_owned(), AsyncIoStdAsTokio(tcp)),
                            )),
                            query_path,
                        },
                        Err(_) => Self::Errored(Some(ProtoError::from(format!(
                            "bad dns_name: {}",
                            &tls.dns_name
                        )))),
                    }
                }
                Self::TlsConnecting {
                    name_server_name,
                    name_server,
                    query_path,
                    tls,
                } => {
                    let Ok(res) = ready!(tls.poll_unpin(cx)) else {
                        return Poll::Ready(Err(format!(
                            "TLS handshake timed out after {CONNECT_TIMEOUT:?}"
                        )
                        .into()));
                    };
                    let tls = res?;
                    debug!("tls connection established to: {}", name_server);
                    let mut handshake = h2::client::Builder::new();
                    handshake.enable_push(false);

                    let handshake = handshake.handshake(tls);
                    Self::H2Handshake {
                        name_server_name: Arc::clone(name_server_name),
                        name_server: *name_server,
                        query_path: Arc::clone(query_path),
                        handshake: Box::pin(handshake),
                    }
                }
                Self::H2Handshake {
                    name_server_name,
                    name_server,
                    query_path,
                    handshake,
                } => {
                    let (send_request, connection) = ready!(
                        handshake
                            .poll_unpin(cx)
                            .map_err(|e| ProtoError::from(format!("h2 handshake error: {e}")))
                    )?;

                    // TODO: hand this back for others to run rather than spawning here?
                    debug!("h2 connection established to: {}", name_server);
                    tokio::spawn(
                        connection
                            .map_err(|e| warn!("h2 connection failed: {e}"))
                            .map(|_: Result<(), ()>| ()),
                    );

                    Self::Connected(Some(HttpsClientStream {
                        name_server_name: Arc::clone(name_server_name),
                        name_server: *name_server,
                        query_path: Arc::clone(query_path),
                        h2: send_request,
                        is_shutdown: false,
                    }))
                }
                Self::Connected(conn) => {
                    return Poll::Ready(Ok(conn.take().expect("cannot poll after complete")));
                }
                Self::Errored(err) => {
                    return Poll::Ready(Err(err.take().expect("cannot poll after complete")));
                }
            };

            *self.as_mut().deref_mut() = next;
        }
    }
}

/// A future that resolves to
pub struct HttpsClientResponse(
    Pin<Box<dyn Future<Output = Result<DnsResponse, ProtoError>> + Send>>,
);

impl Future for HttpsClientResponse {
    type Output = Result<DnsResponse, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx).map_err(ProtoError::from)
    }
}

#[cfg(any(feature = "webpki-roots", feature = "rustls-platform-verifier"))]
#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use std::net::SocketAddr;

    use rustls::KeyLogFile;
    use test_support::subscribe;

    use crate::op::{Edns, Message, Query};
    use crate::rr::{Name, RecordType};
    use crate::runtime::TokioRuntimeProvider;
    use crate::rustls::client_config;
    use crate::xfer::{DnsRequestOptions, FirstAnswer};

    use super::*;

    #[tokio::test]
    async fn test_https_google() {
        subscribe();

        let google = SocketAddr::from(([8, 8, 8, 8], 443));
        let mut request = Message::new();
        let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        request.add_query(query);
        request.set_recursion_desired(true);
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        *request.extensions_mut() = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let mut client_config = client_config_h2();
        client_config.key_log = Arc::new(KeyLogFile::new());

        let provider = TokioRuntimeProvider::new();
        let https_builder =
            HttpsClientStreamBuilder::with_client_config(Arc::new(client_config), provider);
        let connect =
            https_builder.build(google, "dns.google".to_string(), "/dns-query".to_string());

        let mut https = connect.await.expect("https connect failed");

        let response = https
            .send_message(request)
            .first_answer()
            .await
            .expect("send_message failed");

        assert!(
            response
                .answers()
                .iter()
                .any(|record| record.data().as_a().is_some())
        );

        //
        // assert that the connection works for a second query
        let mut request = Message::new();
        let query = Query::query(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::AAAA,
        );
        request.add_query(query);
        request.set_recursion_desired(true);
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        *request.extensions_mut() = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let response = https
            .send_message(request.clone())
            .first_answer()
            .await
            .expect("send_message failed");

        assert!(
            response
                .answers()
                .iter()
                .any(|record| record.data().as_aaaa().is_some())
        );
    }

    #[tokio::test]
    async fn test_https_google_with_pure_ip_address_server() {
        subscribe();

        let google = SocketAddr::from(([8, 8, 8, 8], 443));
        let mut request = Message::new();
        let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        request.add_query(query);
        request.set_recursion_desired(true);
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        *request.extensions_mut() = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let mut client_config = client_config_h2();
        client_config.key_log = Arc::new(KeyLogFile::new());

        let provider = TokioRuntimeProvider::new();
        let https_builder =
            HttpsClientStreamBuilder::with_client_config(Arc::new(client_config), provider);
        let connect =
            https_builder.build(google, google.ip().to_string(), "/dns-query".to_string());

        let mut https = connect.await.expect("https connect failed");

        let response = https
            .send_message(request)
            .first_answer()
            .await
            .expect("send_message failed");

        assert!(
            response
                .answers()
                .iter()
                .any(|record| record.data().as_a().is_some())
        );

        //
        // assert that the connection works for a second query
        let mut request = Message::new();
        let query = Query::query(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::AAAA,
        );
        request.add_query(query);
        request.set_recursion_desired(true);
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        *request.extensions_mut() = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let response = https
            .send_message(request.clone())
            .first_answer()
            .await
            .expect("send_message failed");

        assert!(
            response
                .answers()
                .iter()
                .any(|record| record.data().as_aaaa().is_some())
        );
    }

    #[tokio::test]
    #[ignore = "cloudflare has been unreliable as a public test service"]
    async fn test_https_cloudflare() {
        subscribe();

        let cloudflare = SocketAddr::from(([1, 1, 1, 1], 443));
        let mut request = Message::new();
        let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        request.add_query(query);
        request.set_recursion_desired(true);
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        *request.extensions_mut() = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let client_config = client_config_h2();
        let provider = TokioRuntimeProvider::new();
        let https_builder =
            HttpsClientStreamBuilder::with_client_config(Arc::new(client_config), provider);
        let connect = https_builder.build(
            cloudflare,
            "cloudflare-dns.com".to_string(),
            "/dns-query".to_string(),
        );

        let mut https = connect.await.expect("https connect failed");

        let response = https
            .send_message(request)
            .first_answer()
            .await
            .expect("send_message failed");

        assert!(
            response
                .answers()
                .iter()
                .any(|record| record.data().as_a().is_some())
        );

        //
        // assert that the connection works for a second query
        let mut request = Message::new();
        let query = Query::query(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::AAAA,
        );
        request.add_query(query);
        request.set_recursion_desired(true);
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        *request.extensions_mut() = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let response = https
            .send_message(request)
            .first_answer()
            .await
            .expect("send_message failed");

        assert!(
            response
                .answers()
                .iter()
                .any(|record| record.data().as_aaaa().is_some())
        );
    }

    fn client_config_h2() -> ClientConfig {
        let mut config = client_config();
        config.alpn_protocols = vec![ALPN_H2.to_vec()];
        config
    }
}
