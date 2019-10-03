// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::ops::DerefMut;
use std::fmt::{self, Display};
use std::mem;
use std::net::SocketAddr;
use std::sync::Arc;
use std::pin::Pin;
use std::task::Context;
use std::io;

use bytes::Bytes;
use futures::{future, Future, FutureExt, Poll, Stream, TryFutureExt};
use h2::client::{Connection, SendRequest};
use h2;
use http::{self, header};
use rustls::{Certificate, ClientConfig};
use tokio_executor;
use tokio_rustls::{client::TlsStream as TokioTlsClientStream, Connect, TlsConnector};
use tokio_net::tcp::{TcpStream as TokioTcpStream};
use typed_headers::{ContentLength, HeaderMapExt};
use webpki::DNSNameRef;

use trust_dns_proto::error::ProtoError;
use trust_dns_proto::xfer::{DnsRequest, DnsRequestSender, DnsResponse, SerialMessage};

const ALPN_H2: &[u8] = b"h2";

/// A DNS client connection for DNS-over-HTTPS
#[derive(Clone)]
#[must_use = "futures do nothing unless polled"]
pub struct HttpsClientStream {
    // Corresponds to the dns-name of the HTTPS server
    name_server_name: Arc<String>,
    name_server: SocketAddr,
    h2: SendRequest<Bytes>,
    is_shutdown: bool,
}

impl Display for HttpsClientStream {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            formatter,
            "HTTPS({},{})",
            self.name_server, self.name_server_name
        )
    }
}

impl HttpsClientStream {
    async fn inner_send(h2: SendRequest<Bytes>,
        message: SerialMessage,
        name_server_name: Arc<String>,
        name_server: SocketAddr) -> Result<DnsResponse, ProtoError> {
        
        let mut h2 = match h2.ready().await {
            Ok(h2) => h2,
            Err(err) => {
                // TODO: make specific error
                return Err(ProtoError::from(format!("h2 send_request error: {}", err)));
            }
        };

        // build up the http request

        let bytes = Bytes::from(message.bytes());
        let request = crate::request::new(&name_server_name, bytes.len());

        let request = request.map_err(|err| ProtoError::from(format!("bad http request: {}", err)))?;

        debug!("request: {:#?}", request);

        // Send the request
        let (response_future, mut send_stream) =
            h2.send_request(request, false).map_err(|err| {
                ProtoError::from(format!("h2 send_request error: {}", err))
            })?;

        send_stream
            .send_data(bytes, true)
            .map_err(|e| ProtoError::from(format!("h2 send_data error: {}", e)))?;

        let mut response_stream = response_future.await.map_err(|err| ProtoError::from(
            format!("received a stream error: {}", err)
        ))?;

        debug!("got response: {:#?}", response_stream);

        // get the length of packet
        let content_length: Option<usize> = response_stream
            .headers()
            .typed_get()
            .map_err(|e| ProtoError::from(format!("bad headers received: {}", e)))?
            .map(|c: ContentLength| *c as usize);

        // TODO: what is a good max here?
        // max(512) says make sure it is at least 512 bytes, and min 4096 says it is at most 4k
        //  just a little protection from malicious actors.
        let mut response_bytes = Bytes::with_capacity(content_length.unwrap_or(512).max(512).min(4096));

        while let Some(partial_bytes) = response_stream.body_mut().data().await {
            let partial_bytes = partial_bytes.map_err(|e| ProtoError::from(format!("bad http request: {}", e)))?;

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
                response_stream.status(), error_string
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
                            ProtoError::from(format!(
                                "ContentType header not a string: {}",
                                err
                            ))
                        })
                    }).unwrap_or(Ok(crate::MIME_APPLICATION_DNS))?;

                if content_type != crate::MIME_APPLICATION_DNS {
                    return Err(ProtoError::from(format!(
                        "ContentType unsupported (must be '{}'): '{}'",
                        crate::MIME_APPLICATION_DNS,
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
    type DnsResponseFuture = Pin<Box<dyn Future<Output = Result<DnsResponse, ProtoError>> + Send>>;

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
    fn send_message(&mut self, mut message: DnsRequest) -> Self::DnsResponseFuture {
        if self.is_shutdown {
            panic!("can not send messages after stream is shutdown")
        }

        // per the RFC, a zero id allows for the HTTP packet to be cached better
        message.set_id(0);

        let bytes = match message.to_vec() {
            Ok(bytes) => bytes,
            Err(err) => {
                return Box::pin(future::err(err.into()))
            }
        };
        let message = SerialMessage::new(bytes, self.name_server);

        Box::pin(Self::inner_send(self.h2.clone(), message, Arc::clone(&self.name_server_name), self.name_server))

        // HttpsSerialResponse(HttpsSerialResponseInner::StartSend {
        //     h2: self.h2.clone(),
        //     message,
        //     name_server_name: Arc::clone(&self.name_server_name),
        //     name_server: self.name_server,
        // })
    }

    fn error_response(error: ProtoError) -> Self::DnsResponseFuture {
        Box::pin(future::err(error.into()))
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

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        if self.is_shutdown {
            return Poll::Ready(None);
        }

        // just checking if the connection is ok
        match self.h2.poll_ready(cx) {
            Poll::Ready(Ok(r)) => Poll::Ready(Some(Ok(r))),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(ProtoError::from(format!("h2 stream errored: {}", e))))),
        }
    }
}

/// A HTTPS connection builder for DNS-over-HTTPS
#[derive(Clone)]
pub struct HttpsClientStreamBuilder {
    client_config: ClientConfig,
}

impl HttpsClientStreamBuilder {
    /// Return a new builder for DNS-over-HTTPS
    pub fn new() -> HttpsClientStreamBuilder {
        HttpsClientStreamBuilder {
            client_config: ClientConfig::new(),
        }
    }

    /// Constructs a new TlsStreamBuilder with the associated ClientConfig
    pub fn with_client_config(client_config: ClientConfig) -> Self {
        HttpsClientStreamBuilder { client_config }
    }

    /// Add a custom trusted peer certificate or certificate authority.
    ///
    /// If this is the 'client' then the 'server' must have it associated as it's `identity`, or have had the `identity` signed by this certificate.
    pub fn add_ca(&mut self, ca: Certificate) {
        self.client_config
            .root_store
            .add(&ca)
            .expect("bad certificate!");
    }

    /// Creates a new HttpsStream to the specified name_server
    ///
    /// # Arguments
    ///
    /// * `name_server` - IP and Port for the remote DNS resolver
    /// * `dns_name` - The DNS name, Subject Public Key Info (SPKI) name, as associated to a certificate
    /// * `loop_handle` - The reactor Core handle
    pub fn build(self, name_server: SocketAddr, dns_name: String) -> HttpsClientConnect {
        let mut client_config = self.client_config;
        client_config.alpn_protocols.push(ALPN_H2.to_vec());

        let tls = TlsConfig {
            client_config: Arc::new(client_config),
            dns_name: Arc::new(dns_name),
        };

        HttpsClientConnect(HttpsClientConnectState::ConnectTcp {
            name_server,
            tls: Some(tls),
        })
    }
}

impl Default for HttpsClientStreamBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A future that resolves to an HttpsClientStream
pub struct HttpsClientConnect(HttpsClientConnectState);

impl Future for HttpsClientConnect {
    type Output = Result<HttpsClientStream, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.0.poll_unpin(cx)
    }
}

struct TlsConfig {
    client_config: Arc<ClientConfig>,
    dns_name: Arc<String>,
}

#[allow(clippy::large_enum_variant)]
enum HttpsClientConnectState {
    ConnectTcp {
        name_server: SocketAddr,
        tls: Option<TlsConfig>,
    },
    TcpConnecting {
        connect: Pin<Box<dyn Future<Output = io::Result<TokioTcpStream>>>>,
        name_server: SocketAddr,
        tls: Option<TlsConfig>,
    },
    TlsConnecting {
        // TODO: abstract TLS implementation
        tls: Connect<TokioTcpStream>,
        name_server_name: Arc<String>,
        name_server: SocketAddr,
    },
    H2Handshake {
        handshake: Pin<Box<dyn Future<Output = Result<(SendRequest<Bytes>, Connection<TokioTlsClientStream<TokioTcpStream>, Bytes>), h2::Error>>>>,
        name_server_name: Arc<String>,
        name_server: SocketAddr,
    },
    Connected(Option<HttpsClientStream>),
    Errored(Option<ProtoError>),
}

impl Future for HttpsClientConnectState {
    type Output = Result<HttpsClientStream, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            let next = match *self {
                HttpsClientConnectState::ConnectTcp { name_server, ref mut tls } => {
                    debug!("tcp connecting to: {}", name_server);
                    let connect = Box::pin(TokioTcpStream::connect(name_server));
                    HttpsClientConnectState::TcpConnecting {
                        connect,
                        name_server: name_server,
                        tls: tls.take(),
                    }
                }
                HttpsClientConnectState::TcpConnecting {
                    ref mut connect,
                    name_server,
                    ref mut tls,
                } => {
                    let tcp = ready!(connect.poll_unpin(cx))?;

                    debug!("tcp connection established to: {}", name_server);
                    let tls = tls
                        .take()
                        .expect("programming error, tls should not be None here");
                    let dns_name = tls.dns_name;
                    let name_server_name = Arc::clone(&dns_name);

                    match DNSNameRef::try_from_ascii_str(&dns_name) {
                        Ok(dns_name) => {
                            let tls = TlsConnector::from(tls.client_config);
                            let tls = tls.connect(dns_name, tcp);
                            HttpsClientConnectState::TlsConnecting {
                                name_server_name,
                                name_server: name_server,
                                tls,
                            }
                        }
                        Err(_) => HttpsClientConnectState::Errored(Some(ProtoError::from(
                            format!("bad dns_name: {}", dns_name),
                        ))),
                    }
                }
                HttpsClientConnectState::TlsConnecting {
                    ref name_server_name,
                    name_server,
                    ref mut tls,
                } => {
                    let tls = ready!(tls.poll_unpin(cx))?;
                    debug!("tls connection established to: {}", name_server);
                    let mut handshake = h2::client::Builder::new();
                    handshake.enable_push(false);

                    let handshake = handshake.handshake(tls);
                    HttpsClientConnectState::H2Handshake {
                        name_server_name: Arc::clone(&name_server_name),
                        name_server: name_server,
                        handshake: Box::pin(handshake),
                    }
                }
                HttpsClientConnectState::H2Handshake {
                    ref name_server_name,
                    name_server,
                    ref mut handshake,
                } => {
                    let (send_request, connection) = ready!(
                        handshake
                            .poll_unpin(cx)
                            .map_err(|e| ProtoError::from(format!("h2 handshake error: {}", e)))
                    )?;

                    // TODO: hand this back for others to run rather than spawning here?
                    debug!("h2 connection established to: {}", name_server);
                    tokio_executor::spawn(
                        connection.map_err(|e| warn!("h2 connection failed: {}", e)).map(|_: Result<(),()>| ()),
                    );

                    HttpsClientConnectState::Connected(Some(HttpsClientStream {
                        name_server_name: Arc::clone(&name_server_name),
                        name_server: name_server,
                        h2: send_request,
                        is_shutdown: false,
                    }))
                }
                HttpsClientConnectState::Connected(ref mut conn) => {
                    return Poll::Ready(Ok(conn.take().expect("cannot poll after complete")))
                }
                HttpsClientConnectState::Errored(ref mut err) => {
                    return Poll::Ready(Err(err.take().expect("cannot poll after complete")))
                }
            };

            mem::replace(self.as_mut().deref_mut(), next);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate env_logger;
    extern crate tokio;

    use std::net::{Ipv4Addr, SocketAddr};
    use std::str::FromStr;

    use self::tokio::runtime::current_thread;
    use rustls::{ClientConfig, ProtocolVersion, RootCertStore};
    use webpki_roots;

    use trust_dns_proto::op::{Message, Query};
    use trust_dns_proto::rr::{Name, RData, RecordType};

    use super::*;

    #[test]
    fn test_https_cloudflare() {
        self::env_logger::try_init().ok();

        let cloudflare = SocketAddr::from(([1, 1, 1, 1], 443));
        let mut request = Message::new();
        let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        request.add_query(query);

        let request = DnsRequest::new(request, Default::default());

        // using the mozilla default root store
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        let versions = vec![ProtocolVersion::TLSv1_2];

        let mut client_config = ClientConfig::new();
        client_config.root_store = root_store;
        client_config.versions = versions;

        let https_builder = HttpsClientStreamBuilder::with_client_config(client_config);
        let connect = https_builder.build(cloudflare, "cloudflare-dns.com".to_string());

        // tokio runtime stuff...
        let mut runtime = current_thread::Runtime::new().expect("could not start runtime");
        let mut https = runtime.block_on(connect).expect("https connect failed");

        let sending = https.send_message(request);
        let response: DnsResponse = runtime.block_on(sending).expect("send_message failed");

        //assert_eq!(response.addr(), SocketAddr::from(([1, 1, 1, 1], 443)));

        // let message = Message::read(&mut BinDecoder::new(response.bytes()))
        //     .expect("failed to decode response");
        let message = response;

        let record = &message.answers()[0];
        let addr = if let RData::A(addr) = record.rdata() {
            addr
        } else {
            panic!("invalid response, expected A record");
        };

        assert_eq!(addr, &Ipv4Addr::new(93, 184, 216, 34))
    }
}
