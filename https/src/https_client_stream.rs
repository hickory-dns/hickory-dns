// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io;
use std::mem;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use data_encoding::BASE64;
use futures::{Async, Future, Poll, Stream};
use h2::client::{Handshake, SendRequest};
use h2::{self, RecvStream};
use http::header;
use http::{Request, Response};
use rustls::{Certificate, ClientConfig, ClientSession};
use tokio_executor;
use tokio_rustls::ClientConfigExt;
use tokio_rustls::{ConnectAsync, TlsStream as TokioTlsStream};
use tokio_tcp::{ConnectFuture, TcpStream as TokioTcpStream};

use trust_dns_proto::xfer::{SendMessage, SendMessageAsync, SerialMessage, SerialMessageSender};

pub struct HttpsClientStream {
    name_server: SocketAddr,
    h2: SendRequest<Bytes>,
}

impl SerialMessageSender for HttpsClientStream {
    type SerialResponse = HttpsSerialResponse;

    fn send_message(
        &mut self,
        message: SerialMessage,
    ) -> SendMessage<Self::SerialResponse, io::Error> {
        match self.h2.poll_ready() {
            Ok(Async::Ready(())) => (),
            Ok(Async::NotReady) => return Ok(SendMessageAsync::NotReady(message)),
            Err(err) => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    format!("h2 send_request error: {}", err),
                ))
            }
        }

        // build up the http request

        // https://tools.ietf.org/html/draft-ietf-doh-dns-over-https-10#section-5.1
        // The URI Template defined in this document is processed without any
        // variables when the HTTP method is POST.  When the HTTP method is GET
        // the single variable "dns" is defined as the content of the DNS
        // request (as described in Section 7), encoded with base64url
        // [RFC4648].
        let (message, _) = message.unwrap();
        let query = BASE64.encode(&message);
        let mut request = Request::get(format!("/dns-query?{}", query));
        request.header(header::CONTENT_TYPE, ::ACCEPTS);

        let request = request.body(()).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad http request: {}", err),
            )
        })?;

        // Send the request
        let (response_future, send_stream) = self.h2.send_request(request, true).map_err(|err| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("h2 send_request error: {}", err),
            )
        })?;

        Ok(SendMessageAsync::Ready(HttpsSerialResponse::new(
            response_future,
            send_stream,
            self.name_server,
        )))
    }
}

pub struct HttpsSerialResponse {
    response_future: h2::client::ResponseFuture,
    _response_send_stream: h2::SendStream<Bytes>,
    name_server: SocketAddr,
    response_stream: Option<Response<RecvStream>>,
    response_bytes: Option<Vec<u8>>,
    response_remaining: Option<usize>,
}

impl HttpsSerialResponse {
    fn new(
        response_future: h2::client::ResponseFuture,
        response_send_stream: h2::SendStream<Bytes>,
        name_server: SocketAddr,
    ) -> Self {
        HttpsSerialResponse {
            response_future,
            _response_send_stream: response_send_stream,
            name_server,
            response_stream: None,
            response_bytes: None,
            response_remaining: None,
        }
    }
}

impl Future for HttpsSerialResponse {
    type Item = SerialMessage;
    type Error = io::Error;

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
        loop {
            while self.response_remaining.unwrap_or(0) > 0 {
                // TODO: need to review https://tools.ietf.org/html/draft-ietf-doh-dns-over-https-10 for error codes...
                let response = self
                    .response_stream
                    .as_mut()
                    .expect("a request must be sent before a response can be used");

                // poll for the next set of bytes...
                let bytes = try_ready!(response.body_mut().poll().map_err(|err| io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("bad http request: {}", err),
                )));

                // TODO: it might be interesting to try and return the header, and then a Stream of records... maybe.
                // collect the bytes...
                if let Some(bytes) = bytes {
                    *self.response_remaining.as_mut().unwrap() -= bytes.len();
                    self.response_bytes
                        .as_mut()
                        .expect("response_bytes was not initialized")
                        .append(&mut bytes.to_vec());
                }
            }

            // Getting here means the loop above completed
            //   If there was a buffer, then we got a result
            if let Some(response_bytes) = self.response_bytes.take() {
                // getting here means that the stream was empty and will return no more,
                //   drop the stream
                self.response_stream.take();
                self.response_bytes.take();
                self.response_remaining.take();

                let serial_message = SerialMessage::new(response_bytes, self.name_server);
                return Ok(Async::Ready(serial_message));
            }

            // Otherwise, getting to this point we need to poll the stream, either the first time
            //    or if it's after the fact, than most likely this RecvStream will fail...
            let response: Response<RecvStream> =
                try_ready!(self.response_future.poll().map_err(|err| io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    format!("recieved a stream error: {}", err)
                )));

            // Was it a successful request?
            if !response.status().is_success() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("request was not successful: {}", response.status()),
                ));
            }

            // get the length of packet
            let content_length: usize = response
                .headers()
                .get(header::CONTENT_LENGTH)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "ContentLength header missing")
                })
                .and_then(|h| {
                    h.to_str().map_err(|err| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("ContentLength header not a string: {}", err),
                        )
                    })
                })
                .and_then(|s| {
                    usize::from_str(s).map_err(|err| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("ContentLength header not a number: {}", err),
                        )
                    })
                })?;

            // verify content type
            {
                let content_type = response
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "ContentLength header missing")
                    })
                    .and_then(|h| {
                        h.to_str().map_err(|err| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("ContentType header not a string: {}", err),
                            )
                        })
                    })?;

                if content_type != ::ACCEPTS {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "ContentType unsupported (must be 'application/dns-message'): {}",
                            content_type
                        ),
                    ));
                }
            };

            // setup the while loop above, and we'll loop back to it
            self.response_remaining = Some(content_length);
            self.response_bytes = Some(Vec::with_capacity(content_length));
            self.response_stream = Some(response);
        }
    }
}

#[derive(Clone)]
pub struct HttpsClientStreamBuilder {
    client_config: ClientConfig,
}

impl HttpsClientStreamBuilder {
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
    pub fn build<E>(self, name_server: SocketAddr, dns_name: String) -> HttpsClientConnect {
        let tls = TlsConfig {
            client_config: Arc::new(self.client_config),
            dns_name: dns_name,
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
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

struct TlsConfig {
    client_config: Arc<ClientConfig>,
    dns_name: String,
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
        tls: ConnectAsync<TokioTcpStream>,
        name_server: SocketAddr,
    },
    H2Handshake {
        handshake: Handshake<TokioTlsStream<TokioTcpStream, ClientSession>>,
        name_server: SocketAddr,
    },
    Connected(HttpsClientStream),
}

impl Future for HttpsClientConnectState {
    type Item = HttpsClientStream;
    type Error = io::Error;

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
                    let tls = tls.client_config.connect_async(&dns_name, tcp);
                    HttpsClientConnectState::TlsConnecting {
                        name_server: *name_server,
                        tls,
                    }
                }
                HttpsClientConnectState::TlsConnecting { name_server, tls } => {
                    let tls = try_ready!(tls.poll());
                    let handshake = h2::client::handshake(tls);
                    HttpsClientConnectState::H2Handshake {
                        name_server: *name_server,
                        handshake,
                    }
                }
                HttpsClientConnectState::H2Handshake {
                    name_server,
                    handshake,
                } => {
                    let (send_request, connection) =
                        try_ready!(handshake.poll().map_err(|e| io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            format!("h2 handshake error: {}", e)
                        )));

                    tokio_executor::spawn(
                        connection.map_err(|e| warn!("h2 connection failed: {}", e)),
                    );

                    HttpsClientConnectState::Connected(HttpsClientStream {
                        name_server: *name_server,
                        h2: send_request,
                    })
                }
                HttpsClientConnectState::Connected(..) => panic!("invalid state"),
            };

            // if we've got the connection, we're done
            if let HttpsClientConnectState::Connected(conn) = next {
                return Ok(Async::Ready(conn));
            }

            mem::replace(self, next);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_https_cloudflare() {}
}
