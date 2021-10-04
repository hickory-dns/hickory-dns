// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use futures_util::{future, lock::Mutex, StreamExt};
use log::{debug, info, warn};
#[cfg(feature = "dns-over-rustls")]
use rustls::{Certificate, PrivateKey};
use tokio::{net, task::JoinHandle};

#[cfg(all(feature = "dns-over-openssl", not(feature = "dns-over-rustls")))]
use crate::proto::openssl::tls_server::*;
use crate::{
    authority::{MessageRequest, MessageResponseBuilder},
    client::op::LowerQuery,
    proto::{
        error::ProtoError,
        iocompat::AsyncIoTokioAsStd,
        op::{Edns, Header, Query, ResponseCode},
        serialize::binary::{BinDecodable, BinDecoder},
        tcp::TcpStream,
        udp::UdpStream,
        xfer::SerialMessage,
        BufDnsStreamHandle,
    },
    server::{Protocol, Request, RequestHandler, ResponseHandle, ResponseHandler, TimeoutStream},
};

// TODO, would be nice to have a Slab for buffers here...

/// A Futures based implementation of a DNS server
pub struct ServerFuture<T: RequestHandler> {
    handler: Arc<Mutex<T>>,
    joins: Vec<JoinHandle<Result<(), ProtoError>>>,
}

impl<T: RequestHandler> ServerFuture<T> {
    /// Creates a new ServerFuture with the specified Handler.
    pub fn new(handler: T) -> ServerFuture<T> {
        ServerFuture {
            handler: Arc::new(Mutex::new(handler)),
            joins: vec![],
        }
    }

    /// Register a UDP socket. Should be bound before calling this function.
    pub fn register_socket(&mut self, socket: net::UdpSocket) {
        debug!("registering udp: {:?}", socket);

        // create the new UdpStream, the IP address isn't relevant, and ideally goes essentially no where.
        //   the address used is acquired from the inbound queries
        let (mut buf_stream, stream_handle) =
            UdpStream::with_bound(socket, ([127, 255, 255, 254], 0).into());
        //let request_stream = RequestStream::new(buf_stream, stream_handle);
        let handler = self.handler.clone();

        // this spawns a ForEach future which handles all the requests into a Handler.
        let join_handle = tokio::spawn({
            async move {
                while let Some(message) = buf_stream.next().await {
                    let message = match message {
                        Err(e) => {
                            warn!("error receiving message on udp_socket: {}", e);
                            continue;
                        }
                        Ok(message) => message,
                    };

                    let src_addr = message.addr();
                    debug!("received udp request from: {}", src_addr);
                    let handler = handler.clone();
                    let stream_handle = stream_handle.with_remote_addr(src_addr);

                    tokio::spawn(async move {
                        self::handle_raw_request(message, Protocol::Udp, handler, stream_handle)
                            .await;
                    });
                }

                // TODO: let's consider capturing all the initial configuration details so that the socket could be recreated...
                Err(ProtoError::from("unexpected close of UDP socket"))
            }
        });

        self.joins.push(join_handle);
    }

    /// Register a UDP socket. Should be bound before calling this function.
    pub fn register_socket_std(&mut self, socket: std::net::UdpSocket) -> io::Result<()> {
        self.register_socket(net::UdpSocket::from_std(socket)?);
        Ok(())
    }

    /// Register a TcpListener to the Server. This should already be bound to either an IPv6 or an
    ///  IPv4 address.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `listener` - a bound TCP socket
    /// * `timeout` - timeout duration of incoming requests, any connection that does not send
    ///               requests within this time period will be closed. In the future it should be
    ///               possible to create long-lived queries, but these should be from trusted sources
    ///               only, this would require some type of whitelisting.
    pub fn register_listener(&mut self, listener: net::TcpListener, timeout: Duration) {
        debug!("register tcp: {:?}", listener);

        let handler = self.handler.clone();

        // for each incoming request...
        let join = tokio::spawn({
            async move {
                loop {
                    let tcp_stream = listener.accept().await;
                    let tcp_stream = match tcp_stream {
                        Ok((t, _)) => t,
                        Err(e) => {
                            debug!("error receiving TCP tcp_stream error: {}", e);
                            continue;
                        }
                    };

                    let handler = handler.clone();

                    // and spawn to the io_loop
                    tokio::spawn(async move {
                        let src_addr = tcp_stream.peer_addr().unwrap();
                        debug!("accepted request from: {}", src_addr);
                        // take the created stream...
                        let (buf_stream, stream_handle) =
                            TcpStream::from_stream(AsyncIoTokioAsStd(tcp_stream), src_addr);
                        let mut timeout_stream = TimeoutStream::new(buf_stream, timeout);
                        //let request_stream = RequestStream::new(timeout_stream, stream_handle);

                        while let Some(message) = timeout_stream.next().await {
                            let message = match message {
                                Ok(message) => message,
                                Err(e) => {
                                    debug!(
                                        "error in TCP request_stream src: {} error: {}",
                                        src_addr, e
                                    );
                                    // we're going to bail on this connection...
                                    return;
                                }
                            };

                            // we don't spawn here to limit clients from getting too many resources
                            self::handle_raw_request(
                                message,
                                Protocol::Tcp,
                                handler.clone(),
                                stream_handle.clone(),
                            )
                            .await;
                        }
                    });
                }
            }
        });

        self.joins.push(join);
    }

    /// Register a TcpListener to the Server. This should already be bound to either an IPv6 or an
    ///  IPv4 address.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `listener` - a bound TCP socket
    /// * `timeout` - timeout duration of incoming requests, any connection that does not send
    ///               requests within this time period will be closed. In the future it should be
    ///               possible to create long-lived queries, but these should be from trusted sources
    ///               only, this would require some type of whitelisting.
    pub fn register_listener_std(
        &mut self,
        listener: std::net::TcpListener,
        timeout: Duration,
    ) -> io::Result<()> {
        self.register_listener(net::TcpListener::from_std(listener)?, timeout);
        Ok(())
    }

    /// Register a TlsListener to the Server. The TlsListener should already be bound to either an
    /// IPv6 or an IPv4 address.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `listener` - a bound TCP (needs to be on a different port from standard TCP connections) socket
    /// * `timeout` - timeout duration of incoming requests, any connection that does not send
    ///               requests within this time period will be closed. In the future it should be
    ///               possible to create long-lived queries, but these should be from trusted sources
    ///               only, this would require some type of whitelisting.
    /// * `pkcs12` - certificate used to announce to clients
    #[cfg(all(feature = "dns-over-openssl", not(feature = "dns-over-rustls")))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(feature = "dns-over-openssl", not(feature = "dns-over-rustls"))))
    )]
    pub fn register_tls_listener(
        &mut self,
        listener: net::TcpListener,
        timeout: Duration,
        certificate_and_key: ((X509, Option<Stack<X509>>), PKey<Private>),
    ) -> io::Result<()> {
        use crate::proto::openssl::{tls_server, TlsStream};
        use openssl::ssl::Ssl;
        use std::pin::Pin;
        use tokio_openssl::SslStream as TokioSslStream;

        let ((cert, chain), key) = certificate_and_key;

        let handler = self.handler.clone();
        debug!("registered tcp: {:?}", listener);

        let tls_acceptor = Box::pin(tls_server::new_acceptor(cert, chain, key)?);

        // for each incoming request...
        let join = tokio::spawn({
            async move {
                loop {
                    let tcp_stream = listener.accept().await;
                    let tcp_stream = match tcp_stream {
                        Ok((t, _)) => t,
                        Err(e) => {
                            debug!("error receiving TLS tcp_stream error: {}", e);
                            continue;
                        }
                    };

                    let handler = handler.clone();
                    let tls_acceptor = tls_acceptor.clone();

                    // kick out to a different task immediately, let them do the TLS handshake
                    tokio::spawn(async move {
                        let src_addr = tcp_stream.peer_addr().unwrap();
                        debug!("starting TLS request from: {}", src_addr);

                        // perform the TLS
                        let mut tls_stream = match Ssl::new(tls_acceptor.context())
                            .and_then(|ssl| TokioSslStream::new(ssl, tcp_stream))
                        {
                            Ok(tls_stream) => tls_stream,
                            Err(e) => {
                                debug!("tls handshake src: {} error: {}", src_addr, e);
                                return ();
                            }
                        };
                        match Pin::new(&mut tls_stream).accept().await {
                            Ok(()) => {}
                            Err(e) => {
                                debug!("tls handshake src: {} error: {}", src_addr, e);
                                return ();
                            }
                        };
                        debug!("accepted TLS request from: {}", src_addr);
                        let (buf_stream, stream_handle) =
                            TlsStream::from_stream(AsyncIoTokioAsStd(tls_stream), src_addr);
                        let mut timeout_stream = TimeoutStream::new(buf_stream, timeout);
                        while let Some(message) = timeout_stream.next().await {
                            let message = match message {
                                Ok(message) => message,
                                Err(e) => {
                                    debug!(
                                        "error in TLS request_stream src: {:?} error: {}",
                                        src_addr, e
                                    );

                                    // kill this connection
                                    return ();
                                }
                            };

                            self::handle_raw_request(
                                message,
                                handler.clone(),
                                stream_handle.clone(),
                            )
                            .await;
                        }
                    });
                }
            }
        });

        self.joins.push(join);

        Ok(())
    }

    /// Register a TlsListener to the Server. The TlsListener should already be bound to either an
    /// IPv6 or an IPv4 address.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `listener` - a bound TCP (needs to be on a different port from standard TCP connections) socket
    /// * `timeout` - timeout duration of incoming requests, any connection that does not send
    ///               requests within this time period will be closed. In the future it should be
    ///               possible to create long-lived queries, but these should be from trusted sources
    ///               only, this would require some type of whitelisting.
    /// * `pkcs12` - certificate used to announce to clients
    #[cfg(all(feature = "dns-over-openssl", not(feature = "dns-over-rustls")))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(feature = "dns-over-openssl", not(feature = "dns-over-rustls"))))
    )]
    pub fn register_tls_listener_std(
        &mut self,
        listener: std::net::TcpListener,
        timeout: Duration,
        certificate_and_key: ((X509, Option<Stack<X509>>), PKey<Private>),
    ) -> io::Result<()> {
        self.register_tls_listener(
            net::TcpListener::from_std(listener)?,
            timeout,
            certificate_and_key,
        )
    }

    /// Register a TlsListener to the Server. The TlsListener should already be bound to either an
    /// IPv6 or an IPv4 address.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `listener` - a bound TCP (needs to be on a different port from standard TCP connections) socket
    /// * `timeout` - timeout duration of incoming requests, any connection that does not send
    ///               requests within this time period will be closed. In the future it should be
    ///               possible to create long-lived queries, but these should be from trusted sources
    ///               only, this would require some type of whitelisting.
    /// * `pkcs12` - certificate used to announce to clients
    #[cfg(feature = "dns-over-rustls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dns-over-rustls")))]
    pub fn register_tls_listener(
        &mut self,
        listener: net::TcpListener,
        timeout: Duration,
        certificate_and_key: (Vec<Certificate>, PrivateKey),
    ) -> io::Result<()> {
        use crate::proto::rustls::{tls_from_stream, tls_server};
        use tokio_rustls::TlsAcceptor;

        let handler = self.handler.clone();

        debug!("registered tcp: {:?}", listener);

        let tls_acceptor = tls_server::new_acceptor(certificate_and_key.0, certificate_and_key.1)
            .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("error creating TLS acceptor: {}", e),
            )
        })?;
        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_acceptor));

        // for each incoming request...
        let join = tokio::spawn({
            async move {
                loop {
                    let tcp_stream = listener.accept().await;
                    let tcp_stream = match tcp_stream {
                        Ok((t, _)) => t,
                        Err(e) => {
                            debug!("error receiving TLS tcp_stream error: {}", e);
                            continue;
                        }
                    };

                    let handler = handler.clone();
                    let tls_acceptor = tls_acceptor.clone();

                    // kick out to a different task immediately, let them do the TLS handshake
                    tokio::spawn(async move {
                        let src_addr = tcp_stream.peer_addr().unwrap();
                        debug!("starting TLS request from: {}", src_addr);

                        // perform the TLS
                        let tls_stream = tls_acceptor.accept(tcp_stream).await;

                        let tls_stream = match tls_stream {
                            Ok(tls_stream) => AsyncIoTokioAsStd(tls_stream),
                            Err(e) => {
                                debug!("tls handshake src: {} error: {}", src_addr, e);
                                return;
                            }
                        };
                        debug!("accepted TLS request from: {}", src_addr);
                        let (buf_stream, stream_handle) = tls_from_stream(tls_stream, src_addr);
                        let mut timeout_stream = TimeoutStream::new(buf_stream, timeout);
                        while let Some(message) = timeout_stream.next().await {
                            let message = match message {
                                Ok(message) => message,
                                Err(e) => {
                                    debug!(
                                        "error in TLS request_stream src: {:?} error: {}",
                                        src_addr, e
                                    );

                                    // kill this connection
                                    return;
                                }
                            };

                            self::handle_raw_request(
                                message,
                                Protocol::Tls,
                                handler.clone(),
                                stream_handle.clone(),
                            )
                            .await;
                        }
                    });
                }
            }
        });

        self.joins.push(join);

        Ok(())
    }

    /// Register a TlsListener to the Server. The TlsListener should already be bound to either an
    /// IPv6 or an IPv4 address.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `listener` - a bound TCP (needs to be on a different port from standard TCP connections) socket
    /// * `timeout` - timeout duration of incoming requests, any connection that does not send
    ///               requests within this time period will be closed. In the future it should be
    ///               possible to create long-lived queries, but these should be from trusted sources
    ///               only, this would require some type of whitelisting.
    /// * `pkcs12` - certificate used to announce to clients
    #[cfg(all(
        feature = "dns-over-https-openssl",
        not(feature = "dns-over-https-rustls")
    ))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(
            feature = "dns-over-https-openssl",
            not(feature = "dns-over-https-rustls")
        )))
    )]
    pub fn register_https_listener(
        &self,
        listener: tcp::TcpListener,
        timeout: Duration,
        pkcs12: ParsedPkcs12,
    ) -> io::Result<()> {
        unimplemented!("openssl based `dns-over-https` not yet supported. see the `dns-over-https-rustls` feature")
    }

    /// Register a TlsListener to the Server. The TlsListener should already be bound to either an
    /// IPv6 or an IPv4 address.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `listener` - a bound TCP (needs to be on a different port from standard TCP connections) socket
    /// * `timeout` - timeout duration of incoming requests, any connection that does not send
    ///               requests within this time period will be closed. In the future it should be
    ///               possible to create long-lived queries, but these should be from trusted sources
    ///               only, this would require some type of whitelisting.
    /// * `pkcs12` - certificate used to announce to clients
    #[cfg(feature = "dns-over-https-rustls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dns-over-https-rustls")))]
    pub fn register_https_listener(
        &mut self,
        listener: net::TcpListener,
        // TODO: need to set a timeout between requests.
        _timeout: Duration,
        certificate_and_key: (Vec<Certificate>, PrivateKey),
        dns_hostname: String,
    ) -> io::Result<()> {
        use tokio_rustls::TlsAcceptor;

        use crate::proto::rustls::tls_server;
        use crate::server::https_handler::h2_handler;

        let dns_hostname: Arc<str> = Arc::from(dns_hostname);
        let handler = self.handler.clone();
        debug!("registered tcp: {:?}", listener);

        let tls_acceptor = tls_server::new_acceptor(certificate_and_key.0, certificate_and_key.1)
            .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("error creating TLS acceptor: {}", e),
            )
        })?;
        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_acceptor));

        // for each incoming request...
        let dns_hostname = dns_hostname;
        let join = tokio::spawn({
            async move {
                let dns_hostname = dns_hostname;
                loop {
                    let tcp_stream = listener.accept().await;
                    let tcp_stream = match tcp_stream {
                        Ok((t, _)) => t,
                        Err(e) => {
                            debug!("error receiving HTTPS tcp_stream error: {}", e);
                            continue;
                        }
                    };

                    let handler = handler.clone();
                    let tls_acceptor = tls_acceptor.clone();
                    let dns_hostname = dns_hostname.clone();

                    tokio::spawn(async move {
                        let src_addr = tcp_stream.peer_addr().unwrap();
                        debug!("starting HTTPS request from: {}", src_addr);

                        // TODO: need to consider timeout of total connect...
                        // take the created stream...
                        let tls_stream = tls_acceptor.accept(tcp_stream).await;

                        let tls_stream = match tls_stream {
                            Ok(tls_stream) => tls_stream,
                            Err(e) => {
                                debug!("https handshake src: {} error: {}", src_addr, e);
                                return;
                            }
                        };
                        debug!("accepted HTTPS request from: {}", src_addr);

                        h2_handler(handler, tls_stream, src_addr, dns_hostname).await;
                    });
                }
            }
        });

        self.joins.push(join);
        Ok(())
    }

    /// This will run until all background tasks of the trust_dns_server end.
    pub async fn block_until_done(self) -> Result<(), ProtoError> {
        let (result, _, _) = future::select_all(self.joins).await;

        result.map_err(|e| ProtoError::from(format!("Internal error in spawn: {}", e)))?
    }
}

pub(crate) async fn handle_raw_request<T: RequestHandler>(
    message: SerialMessage,
    protocol: Protocol,
    request_handler: Arc<Mutex<T>>,
    response_handler: BufDnsStreamHandle,
) {
    let src_addr = message.addr();
    let response_handler = ResponseHandle::new(message.addr(), response_handler);

    self::handle_request(
        message.bytes(),
        src_addr,
        protocol,
        request_handler,
        response_handler,
    )
    .await;
}

#[derive(Clone)]
struct ReportingResponseHandler<R: ResponseHandler> {
    request_header: Header,
    query: LowerQuery,
    protocol: Protocol,
    src_addr: SocketAddr,
    handler: R,
}

#[async_trait::async_trait]
impl<R: ResponseHandler> ResponseHandler for ReportingResponseHandler<R> {
    async fn send_response(
        &mut self,
        response: crate::authority::MessageResponse<'_, '_>,
    ) -> io::Result<super::ResponseInfo> {
        let response_info = self.handler.send_response(response).await?;

        let id = self.request_header.id();
        let rid = response_info.id();
        if id != rid {
            warn!("request id:{} does not match response id:{}", id, rid);
            debug_assert_eq!(id, rid, "request id and response id should match");
        }

        let rflags = response_info.flags();
        let answer_count = response_info.answer_count();
        let authority_count = response_info.name_server_count();
        let additional_count = response_info.additional_count();
        let response_code = response_info.response_code();

        info!("request:{id} src:{proto}://{addr}#{port} {op}:{query}:{qtype}:{class} qflags:{qflags} response:{code:?} rr:{answers}/{authorities}/{additionals} rflags:{rflags}",
            id = rid,
            proto = self.protocol,
            addr = self.src_addr.ip(),
            port = self.src_addr.port(),
            op = self.request_header.op_code(),
            query = self.query.name(),
            qtype = self.query.query_type(),
            class = self.query.query_class(),
            qflags = self.request_header.flags(),
            code = response_code,
            answers = answer_count,
            authorities = authority_count,
            additionals = additional_count,
            rflags = rflags
        );

        Ok(response_info)
    }
}

pub(crate) async fn handle_request<R: ResponseHandler, T: RequestHandler>(
    message_bytes: &[u8],
    src_addr: SocketAddr,
    protocol: Protocol,
    request_handler: Arc<Mutex<T>>,
    response_handler: R,
) {
    let mut decoder = BinDecoder::new(message_bytes);

    // method to handle the request
    let inner_handle_request = |message: MessageRequest, response_handler: R| async move {
        let id = message.id();
        let qflags = message.header().flags();
        let qop_code = message.op_code();
        let message_type = message.message_type();
        let is_dnssec = message.edns().map_or(false, Edns::dnssec_ok);

        let request = Request::new(message, src_addr, protocol);

        let info = request.request_info();
        let query = info.query.clone();
        let query_name = info.query.name();
        let query_type = info.query.query_type();
        let query_class = info.query.query_class();

        debug!(
            "request:{id} src:{proto}://{addr}#{port} type:{message_type} dnssec:{is_dnssec} {op}:{query}:{qtype}:{class} qflags:{qflags}",
            id = id,
            proto = protocol,
            addr = src_addr.ip(),
            port = src_addr.port(),
            message_type= message_type,
            is_dnssec = is_dnssec,
            op = qop_code,
            query = query_name,
            qtype = query_type,
            class = query_class,
            qflags = qflags,
        );

        // The reporter will handle making sure to log the result of the request
        let reporter = ReportingResponseHandler {
            request_header: *request.header(),
            query,
            protocol,
            src_addr,
            handler: response_handler,
        };

        request_handler
            .lock()
            .await
            .handle_request(request, reporter)
            .await;
    };

    // Attempt to decode the message
    match MessageRequest::read(&mut decoder) {
        Ok(message) => {
            inner_handle_request(message, response_handler).await;
        }
        Err(ProtoError { kind, .. }) if kind.as_form_error().is_some() => {
            // We failed to parse the request due to some issue in the message, but the header is available, so we can respond
            let (header, error) = kind
                .into_form_error()
                .expect("as form_error already confirmed this is a FormError");
            let query = LowerQuery::query(Query::default());

            // debug for more info on why the message parsing failed
            debug!(
                "request:{id} src:{proto}://{addr}#{port} type:{message_type} {op}:FormError:{error}",
                id = header.id(),
                proto = protocol,
                addr = src_addr.ip(),
                port = src_addr.port(),
                message_type= header.message_type(),
                op = header.op_code(),
                error = error,
            );

            // The reporter will handle making sure to log the result of the request
            let mut reporter = ReportingResponseHandler {
                request_header: header,
                query,
                protocol,
                src_addr,
                handler: response_handler,
            };

            let response = MessageResponseBuilder::new(None);
            let result = reporter
                .send_response(response.error_msg(&header, ResponseCode::FormErr))
                .await;

            if let Err(e) = result {
                warn!("failed to return FormError to client: {}", e);
            }
        }
        Err(e) => warn!("failed to read message: {}", e),
    }
}
