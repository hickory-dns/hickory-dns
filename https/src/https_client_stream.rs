// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt::{self, Display};
use std::mem;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use futures::{Async, Future, Poll, Stream};
use h2::client::{Handshake, SendRequest};
use h2::{self, RecvStream};
use http::header;
use http::uri;
use http::{Request, Response, StatusCode, Uri, Version};
use rustls::{Certificate, ClientConfig, ClientSession};
use tokio_executor;
use tokio_rustls::ClientConfigExt;
use tokio_rustls::{ConnectAsync, TlsStream as TokioTlsStream};
use tokio_tcp::{ConnectFuture, TcpStream as TokioTcpStream};

use trust_dns_proto::error::ProtoError;
use trust_dns_proto::xfer::{DnsRequest, DnsResponse, SerialMessage, DnsRequestSender};

const ALPN_H2: &str = "h2";
const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

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

impl DnsRequestSender for HttpsClientStream {
    type SerialResponse = HttpsSerialResponse;

    fn send_message(&mut self, message: DnsRequest) -> Self::SerialResponse {
        if self.is_shutdown {
            panic!("can not send messages after stream is shutdown")
        }

        let bytes = match message.to_vec() {
            Ok(bytes) => bytes,
            Err(err) => {
                return HttpsSerialResponse(HttpsSerialResponseInner::Errored(Some(err.into())))
            }
        };
        let message = SerialMessage::new(bytes, self.name_server);

        HttpsSerialResponse(HttpsSerialResponseInner::StartSend {
            h2: self.h2.clone(),
            message,
            name_server_name: Arc::clone(&self.name_server_name),
            name_server: self.name_server,
        })
    }

    fn error_response(error: ProtoError) -> Self::SerialResponse {
        HttpsSerialResponse(HttpsSerialResponseInner::Errored(Some(error)))
    }

    fn shutdown(&mut self) {
        self.is_shutdown = true;
    }

    fn is_shutdown(&self) -> bool {
        self.is_shutdown
    }
}

impl Stream for HttpsClientStream {
    type Item = ();
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if self.is_shutdown {
            return Ok(Async::Ready(None));
        }

        // just checking if the connection is ok
        self.h2
            .poll_ready()
            .map(|readiness| match readiness {
                Async::Ready(()) => Async::Ready(Some(())),
                Async::NotReady => Async::NotReady,
            })
            .map_err(|e| ProtoError::from(format!("h2 stream errored: {}", e)))
    }
}

/// A future that will resolve to a DnsResponse upon completion
#[must_use = "futures do nothing unless polled"]
pub struct HttpsSerialResponse(HttpsSerialResponseInner);

impl Future for HttpsSerialResponse {
    type Item = DnsResponse;
    type Error = ProtoError;

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
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let serial_message = try_ready!(self.0.poll());
        let message = serial_message.to_message()?;
        Ok(Async::Ready(message.into()))
    }
}

enum HttpsSerialResponseInner {
    StartSend {
        h2: SendRequest<Bytes>,
        message: SerialMessage,
        name_server_name: Arc<String>,
        name_server: SocketAddr,
    },
    Incoming {
        response_future: h2::client::ResponseFuture,
        _response_send_stream: h2::SendStream<Bytes>,
        name_server: SocketAddr,
    },
    Receiving {
        response_stream: Response<RecvStream>,
        response_bytes: Bytes,
        content_length: Option<usize>,
        name_server: SocketAddr,
    },
    Failure {
        response_bytes: Bytes,
        status_code: StatusCode,
    },
    Complete(Option<SerialMessage>),
    Errored(Option<ProtoError>),
}

impl Future for HttpsSerialResponseInner {
    type Item = SerialMessage;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            use self::HttpsSerialResponseInner::*;

            let next = match self {
                StartSend {
                    ref mut h2,
                    message,
                    name_server_name,
                    name_server,
                } => {
                    match h2.poll_ready() {
                        Ok(Async::Ready(())) => (),
                        Ok(Async::NotReady) => return Ok(Async::NotReady),
                        Err(err) => {
                            return Err(ProtoError::from(format!("h2 send_request error: {}", err)))
                        }
                    }

                    // build up the http request

                    // https://tools.ietf.org/html/draft-ietf-doh-dns-over-https-10#section-5.1
                    // The URI Template defined in this document is processed without any
                    // variables when the HTTP method is POST.  When the HTTP method is GET
                    // the single variable "dns" is defined as the content of the DNS
                    // request (as described in Section 7), encoded with base64url
                    // [RFC4648].
                    // let (message, _) = message.unwrap();

                    // TODO: this is basically the GET version, but it is more expesive than POST
                    //   perhaps add an option if people want better HTTP caching options.

                    // let query = BASE64URL_NOPAD.encode(&message);
                    // let url = format!("/dns-query?dns={}", query);
                    // let request = Request::get(&url)
                    //     .header(header::CONTENT_TYPE, ::ACCEPTS_DNS_BINARY)
                    //     .header(header::HOST, &self.name_server_name as &str)
                    //     .header("authority", &self.name_server_name as &str)
                    //     .header(header::USER_AGENT, USER_AGENT)
                    //     .body(());

                    let mut parts = uri::Parts::default();
                    parts.scheme = Some(uri::Scheme::HTTPS);
                    parts.authority = Some(
                        uri::Authority::from_str(&name_server_name)
                            .map_err(|e| ProtoError::from(format!("invalid authority: {}", e)))?,
                    );
                    parts.path_and_query = Some(uri::PathAndQuery::from_static("/dns-query"));

                    let url = Uri::from_parts(parts)
                        .map_err(|e| ProtoError::from(format!("uri parse error: {}", e)))?;
                    let request = Request::post(url)
                        .header(header::CONTENT_TYPE, ::ACCEPTS_DNS_BINARY)
                        .header(header::ACCEPT, ::ACCEPTS_DNS_BINARY)
                        .header(header::USER_AGENT, USER_AGENT)
                        .version(Version::HTTP_2)
                        .body(());

                    let request = request
                        .map_err(|err| ProtoError::from(format!("bad http request: {}", err)))?;

                    debug!("request: {:#?}", request);

                    // Send the request
                    let (response_future, mut send_stream) =
                        h2.send_request(request, false).map_err(|err| {
                            ProtoError::from(format!("h2 send_request error: {}", err))
                        })?;

                    send_stream
                        .send_data(Bytes::from(message.bytes()), true)
                        .map_err(|e| ProtoError::from(format!("h2 send_data error: {}", e)))?;

                    HttpsSerialResponseInner::Incoming {
                        response_future,
                        _response_send_stream: send_stream,
                        name_server: *name_server,
                    }
                }
                Incoming {
                    ref mut response_future,
                    name_server,
                    ..
                } => {
                    let response_stream = try_ready!(response_future.poll().map_err(|err| {
                        ProtoError::from(format!("recieved a stream error: {}", err))
                    }));

                    // get the length of packet
                    let content_length: usize = response_stream
                        .headers()
                        .get(header::CONTENT_LENGTH)
                        .map_or(Ok(512), |h| {
                            h.to_str()
                                .map_err(|err| {
                                    ProtoError::from(format!(
                                        "ContentLength header not a string: {}",
                                        err
                                    ))
                                })
                                .and_then(|s| {
                                    usize::from_str(s).map_err(|err| {
                                        ProtoError::from(format!(
                                            "ContentLength header not a number: {}",
                                            err
                                        ))
                                    })
                                })
                        })?;

                    Receiving {
                        response_stream,
                        response_bytes: Bytes::with_capacity(content_length),
                        content_length: Some(content_length),
                        name_server: *name_server,
                    }
                }
                Receiving {
                    ref mut response_stream,
                    ref mut response_bytes,
                    content_length,
                    name_server,
                } => {
                    while let Some(partial_bytes) = try_ready!(
                        response_stream
                            .body_mut()
                            .poll()
                            .map_err(|e| ProtoError::from(format!("bad http request: {}", e)))
                    ) {
                        response_bytes.extend(partial_bytes);
                    }
                    // assert the length
                    if let Some(content_length) = content_length {
                        if *content_length != response_bytes.len() {
                            return Err(ProtoError::from(format!(
                                "expected byte length: {}, got: {}",
                                content_length,
                                response_bytes.len()
                            )));
                        }
                    }

                    // Was it a successful request?
                    if !response_stream.status().is_success() {
                        Failure {
                            response_bytes: response_bytes.slice_from(0),
                            status_code: response_stream.status(),
                        }
                    } else {
                        // verify content type
                        {
                            let content_type = response_stream
                                .headers()
                                .get(header::CONTENT_TYPE)
                                .ok_or_else(|| ProtoError::from("ContentLength header missing"))
                                .and_then(|h| {
                                    h.to_str().map_err(|err| {
                                        ProtoError::from(format!(
                                            "ContentType header not a string: {}",
                                            err
                                        ))
                                    })
                                })?;

                            if content_type != ::ACCEPTS_DNS_BINARY {
                                return Err(ProtoError::from(format!(
                                        "ContentType unsupported (must be 'application/dns-message'): {}",
                                        content_type
                                    ),
                                ));
                            }
                        };

                        Complete(Some(SerialMessage::new(
                            response_bytes.to_vec(),
                            *name_server,
                        )))
                    }
                }
                Failure {
                    response_bytes,
                    status_code,
                } => {
                    let error_string = String::from_utf8_lossy(response_bytes.as_ref());

                    return Err(ProtoError::from(format!(
                        "http unsuccessful code: {}, message: {}",
                        status_code, error_string
                    )));
                }
                Complete(ref mut message) => {
                    return Ok(Async::Ready(
                        message.take().expect("cannot poll after complete"),
                    ))
                }
                Errored(ref mut error) => {
                    return Err(error.take().expect("cannot poll after complete"))
                }
            };

            *self = next;
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

    /// Add a custom trusted peer certificate or certificate auhtority.
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
        client_config.alpn_protocols.push(ALPN_H2.to_owned());

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

pub struct HttpsClientConnect(HttpsClientConnectState);

impl Future for HttpsClientConnect {
    type Item = HttpsClientStream;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

struct TlsConfig {
    client_config: Arc<ClientConfig>,
    dns_name: Arc<String>,
}

enum HttpsClientConnectState {
    ConnectTcp {
        name_server: SocketAddr,
        tls: Option<TlsConfig>,
    },
    TcpConnecting {
        connect: ConnectFuture,
        name_server: SocketAddr,
        tls: Option<TlsConfig>,
    },
    TlsConnecting {
        // TODO: abstract TLS implementation
        tls: ConnectAsync<TokioTcpStream>,
        name_server_name: Arc<String>,
        name_server: SocketAddr,
    },
    H2Handshake {
        handshake: Handshake<TokioTlsStream<TokioTcpStream, ClientSession>>,
        name_server_name: Arc<String>,
        name_server: SocketAddr,
    },
    Connected(Option<HttpsClientStream>),
}

impl Future for HttpsClientConnectState {
    type Item = HttpsClientStream;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            let next = match self {
                HttpsClientConnectState::ConnectTcp { name_server, tls } => {
                    let connect = TokioTcpStream::connect(&name_server);
                    HttpsClientConnectState::TcpConnecting {
                        connect,
                        name_server: *name_server,
                        tls: tls.take(),
                    }
                }
                HttpsClientConnectState::TcpConnecting {
                    connect,
                    name_server,
                    tls,
                } => {
                    let tcp = try_ready!(connect.poll());
                    let tls = tls
                        .take()
                        .expect("programming error, tls should not be None here");
                    let dns_name = tls.dns_name;
                    let name_server_name = Arc::clone(&dns_name);
                    let tls = tls.client_config.connect_async(&dns_name, tcp);
                    HttpsClientConnectState::TlsConnecting {
                        name_server_name,
                        name_server: *name_server,
                        tls,
                    }
                }
                HttpsClientConnectState::TlsConnecting {
                    name_server_name,
                    name_server,
                    tls,
                } => {
                    let tls = try_ready!(tls.poll());
                    let mut handshake = h2::client::Builder::new();
                    handshake.enable_push(false);

                    let handshake = handshake.handshake(tls);
                    HttpsClientConnectState::H2Handshake {
                        name_server_name: Arc::clone(&name_server_name),
                        name_server: *name_server,
                        handshake,
                    }
                }
                HttpsClientConnectState::H2Handshake {
                    name_server_name,
                    name_server,
                    handshake,
                } => {
                    let (send_request, connection) = try_ready!(
                        handshake
                            .poll()
                            .map_err(|e| ProtoError::from(format!("h2 handshake error: {}", e)))
                    );

                    tokio_executor::spawn(
                        connection.map_err(|e| warn!("h2 connection failed: {}", e)),
                    );

                    HttpsClientConnectState::Connected(Some(HttpsClientStream {
                        name_server_name: Arc::clone(&name_server_name),
                        name_server: *name_server,
                        h2: send_request,
                        is_shutdown: false,
                    }))
                }
                HttpsClientConnectState::Connected(conn) => {
                    return Ok(Async::Ready(
                        conn.take().expect("cannot poll after complete"),
                    ))
                }
            };

            mem::replace(self, next);
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
