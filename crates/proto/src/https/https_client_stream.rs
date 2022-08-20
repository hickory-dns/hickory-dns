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
use h2::client::{Connection, SendRequest};
use http::header::{self, CONTENT_LENGTH};
use rustls::ClientConfig;
use tokio_rustls::{
    client::TlsStream as TokioTlsClientStream, Connect as TokioTlsConnect, TlsConnector,
};
use tracing::{debug, warn};

use crate::error::ProtoError;
use crate::iocompat::AsyncIoStdAsTokio;
use crate::tcp::Connect;
use crate::xfer::{DnsRequest, DnsRequestSender, DnsResponse, DnsResponseStream, SerialMessage};

const ALPN_H2: &[u8] = b"h2";

/// A DNS client connection for DNS-over-HTTPS
#[derive(Clone)]
#[must_use = "futures do nothing unless polled"]
pub struct HttpsClientStream {
    // Corresponds to the dns-name of the HTTPS server
    name_server_name: Arc<str>,
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
        name_server: SocketAddr,
    ) -> Result<DnsResponse, ProtoError> {
        let mut h2 = match h2.ready().await {
            Ok(h2) => h2,
            Err(err) => {
                // TODO: make specific error
                return Err(ProtoError::from(format!("h2 send_request error: {}", err)));
            }
        };

        // build up the http request
        let request = crate::https::request::new(&name_server_name, message.remaining());

        let request =
            request.map_err(|err| ProtoError::from(format!("bad http request: {}", err)))?;

        debug!("request: {:#?}", request);

        // Send the request
        let (response_future, mut send_stream) = h2
            .send_request(request, false)
            .map_err(|err| ProtoError::from(format!("h2 send_request error: {}", err)))?;

        send_stream
            .send_data(message, true)
            .map_err(|e| ProtoError::from(format!("h2 send_data error: {}", e)))?;

        let mut response_stream = response_future
            .await
            .map_err(|err| ProtoError::from(format!("received a stream error: {}", err)))?;

        debug!("got response: {:#?}", response_stream);

        // get the length of packet
        let content_length = response_stream
            .headers()
            .get(CONTENT_LENGTH)
            .map(|v| v.to_str())
            .transpose()
            .map_err(|e| ProtoError::from(format!("bad headers received: {}", e)))?
            .map(usize::from_str)
            .transpose()
            .map_err(|e| ProtoError::from(format!("bad headers received: {}", e)))?;

        // TODO: what is a good max here?
        // clamp(512, 4096) says make sure it is at least 512 bytes, and min 4096 says it is at most 4k
        // just a little protection from malicious actors.
        let mut response_bytes =
            BytesMut::with_capacity(content_length.unwrap_or(512).clamp(512, 4096));

        while let Some(partial_bytes) = response_stream.body_mut().data().await {
            let partial_bytes =
                partial_bytes.map_err(|e| ProtoError::from(format!("bad http request: {}", e)))?;

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
                            ProtoError::from(format!("ContentType header not a string: {}", err))
                        })
                    })
                    .unwrap_or(Ok(crate::https::MIME_APPLICATION_DNS))?;

                if content_type != crate::https::MIME_APPLICATION_DNS {
                    return Err(ProtoError::from(format!(
                        "ContentType unsupported (must be '{}'): '{}'",
                        crate::https::MIME_APPLICATION_DNS,
                        content_type
                    )));
                }
            }
        };

        // and finally convert the bytes into a DNS message
        let message = SerialMessage::new(response_bytes.to_vec(), name_server).to_message()?;
        Ok(message.into())
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
            self.h2.clone(),
            Bytes::from(bytes),
            Arc::clone(&self.name_server_name),
            self.name_server,
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
                "h2 stream errored: {}",
                e
            ))))),
        }
    }
}

/// A HTTPS connection builder for DNS-over-HTTPS
#[derive(Clone)]
pub struct HttpsClientStreamBuilder {
    client_config: Arc<ClientConfig>,
    bind_addr: Option<SocketAddr>,
}

impl HttpsClientStreamBuilder {
    /// Constructs a new TlsStreamBuilder with the associated ClientConfig
    pub fn with_client_config(client_config: Arc<ClientConfig>) -> Self {
        Self {
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
    /// * `dns_name` - The DNS name, Subject Public Key Info (SPKI) name, as associated to a certificate
    pub fn build<S: Connect>(
        mut self,
        name_server: SocketAddr,
        dns_name: String,
    ) -> HttpsClientConnect<S> {
        // ensure the ALPN protocol is set correctly
        if self.client_config.alpn_protocols.is_empty() {
            let mut client_config = (*self.client_config).clone();
            client_config.alpn_protocols = vec![ALPN_H2.to_vec()];

            self.client_config = Arc::new(client_config);
        }

        let tls = TlsConfig {
            client_config: self.client_config,
            dns_name: Arc::from(dns_name),
        };

        HttpsClientConnect::<S>(HttpsClientConnectState::ConnectTcp {
            name_server,
            bind_addr: self.bind_addr,
            tls: Some(tls),
        })
    }
}

/// A future that resolves to an HttpsClientStream
pub struct HttpsClientConnect<S>(HttpsClientConnectState<S>)
where
    S: Connect;

impl<S> Future for HttpsClientConnect<S>
where
    S: Connect,
{
    type Output = Result<HttpsClientStream, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.poll_unpin(cx)
    }
}

struct TlsConfig {
    client_config: Arc<ClientConfig>,
    dns_name: Arc<str>,
}

#[allow(clippy::large_enum_variant)]
#[allow(clippy::type_complexity)]
enum HttpsClientConnectState<S>
where
    S: Connect,
{
    ConnectTcp {
        name_server: SocketAddr,
        bind_addr: Option<SocketAddr>,
        tls: Option<TlsConfig>,
    },
    TcpConnecting {
        connect: Pin<Box<dyn Future<Output = io::Result<S>> + Send>>,
        name_server: SocketAddr,
        tls: Option<TlsConfig>,
    },
    TlsConnecting {
        // TODO: also abstract away Tokio TLS in RuntimeProvider.
        tls: TokioTlsConnect<AsyncIoStdAsTokio<S>>,
        name_server_name: Arc<str>,
        name_server: SocketAddr,
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
    },
    Connected(Option<HttpsClientStream>),
    Errored(Option<ProtoError>),
}

impl<S> Future for HttpsClientConnectState<S>
where
    S: Connect,
{
    type Output = Result<HttpsClientStream, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let next = match *self {
                Self::ConnectTcp {
                    name_server,
                    bind_addr,
                    ref mut tls,
                } => {
                    debug!("tcp connecting to: {}", name_server);
                    let connect = S::connect_with_bind(name_server, bind_addr);
                    Self::TcpConnecting {
                        connect,
                        name_server,
                        tls: tls.take(),
                    }
                }
                Self::TcpConnecting {
                    ref mut connect,
                    name_server,
                    ref mut tls,
                } => {
                    let tcp = ready!(connect.poll_unpin(cx))?;

                    debug!("tcp connection established to: {}", name_server);
                    let tls = tls
                        .take()
                        .expect("programming error, tls should not be None here");
                    let name_server_name = Arc::clone(&tls.dns_name);

                    match tls.dns_name.as_ref().try_into() {
                        Ok(dns_name) => {
                            let tls = TlsConnector::from(tls.client_config);
                            let tls = tls.connect(dns_name, AsyncIoStdAsTokio(tcp));
                            Self::TlsConnecting {
                                name_server_name,
                                name_server,
                                tls,
                            }
                        }
                        Err(_) => Self::Errored(Some(ProtoError::from(format!(
                            "bad dns_name: {}",
                            &tls.dns_name
                        )))),
                    }
                }
                Self::TlsConnecting {
                    ref name_server_name,
                    name_server,
                    ref mut tls,
                } => {
                    let tls = ready!(tls.poll_unpin(cx))?;
                    debug!("tls connection established to: {}", name_server);
                    let mut handshake = h2::client::Builder::new();
                    handshake.enable_push(false);

                    let handshake = handshake.handshake(tls);
                    Self::H2Handshake {
                        name_server_name: Arc::clone(name_server_name),
                        name_server,
                        handshake: Box::pin(handshake),
                    }
                }
                Self::H2Handshake {
                    ref name_server_name,
                    name_server,
                    ref mut handshake,
                } => {
                    let (send_request, connection) = ready!(handshake
                        .poll_unpin(cx)
                        .map_err(|e| ProtoError::from(format!("h2 handshake error: {}", e))))?;

                    // TODO: hand this back for others to run rather than spawning here?
                    debug!("h2 connection established to: {}", name_server);
                    tokio::spawn(
                        connection
                            .map_err(|e| warn!("h2 connection failed: {}", e))
                            .map(|_: Result<(), ()>| ()),
                    );

                    Self::Connected(Some(HttpsClientStream {
                        name_server_name: Arc::clone(name_server_name),
                        name_server,
                        h2: send_request,
                        is_shutdown: false,
                    }))
                }
                Self::Connected(ref mut conn) => {
                    return Poll::Ready(Ok(conn.take().expect("cannot poll after complete")))
                }
                Self::Errored(ref mut err) => {
                    return Poll::Ready(Err(err.take().expect("cannot poll after complete")))
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::str::FromStr;

    use rustls::KeyLogFile;
    use tokio::net::TcpStream as TokioTcpStream;
    use tokio::runtime::Runtime;

    use crate::iocompat::AsyncIoTokioAsStd;
    use crate::op::{Message, Query, ResponseCode};
    use crate::rr::{Name, RData, RecordType};
    use crate::xfer::{DnsRequestOptions, FirstAnswer};

    use super::*;

    #[test]
    fn test_https_google() {
        //env_logger::try_init().ok();

        let google = SocketAddr::from(([8, 8, 8, 8], 443));
        let mut request = Message::new();
        let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        request.add_query(query);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let mut client_config = client_config_tls12_webpki_roots();
        client_config.key_log = Arc::new(KeyLogFile::new());

        let https_builder = HttpsClientStreamBuilder::with_client_config(Arc::new(client_config));
        let connect = https_builder
            .build::<AsyncIoTokioAsStd<TokioTcpStream>>(google, "dns.google".to_string());

        // tokio runtime stuff...
        let runtime = Runtime::new().expect("could not start runtime");
        let mut https = runtime.block_on(connect).expect("https connect failed");

        let response = runtime
            .block_on(https.send_message(request).first_answer())
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
                .block_on(https.send_message(request.clone()).first_answer())
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

    #[test]
    #[ignore] // cloudflare has been unreliable as a public test service.
    fn test_https_cloudflare() {
        // self::env_logger::try_init().ok();

        let cloudflare = SocketAddr::from(([1, 1, 1, 1], 443));
        let mut request = Message::new();
        let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        request.add_query(query);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let client_config = client_config_tls12_webpki_roots();
        let https_builder = HttpsClientStreamBuilder::with_client_config(Arc::new(client_config));
        let connect = https_builder.build::<AsyncIoTokioAsStd<TokioTcpStream>>(
            cloudflare,
            "cloudflare-dns.com".to_string(),
        );

        // tokio runtime stuff...
        let runtime = Runtime::new().expect("could not start runtime");
        let mut https = runtime.block_on(connect).expect("https connect failed");

        let response = runtime
            .block_on(https.send_message(request).first_answer())
            .expect("send_message failed");

        let record = &response.answers()[0];
        let addr = record
            .data()
            .and_then(RData::as_a)
            .expect("invalid response, expected A record");

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

        let response = runtime
            .block_on(https.send_message(request).first_answer())
            .expect("send_message failed");

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

    fn client_config_tls12_webpki_roots() -> ClientConfig {
        use rustls::{OwnedTrustAnchor, RootCertStore};
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let mut client_config = ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        client_config.alpn_protocols = vec![ALPN_H2.to_vec()];
        client_config
    }
}
