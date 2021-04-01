// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::{future, FutureExt, StreamExt};
use log::{debug, info, warn};
#[cfg(feature = "dns-over-rustls")]
use rustls::{Certificate, PrivateKey};
use tokio::net;
use tokio::task::JoinHandle;

use crate::authority::MessageRequest;
use crate::proto::error::ProtoError;
use crate::proto::iocompat::AsyncIoTokioAsStd;
use crate::proto::op::Edns;
use crate::proto::serialize::binary::{BinDecodable, BinDecoder};
use crate::proto::tcp::TcpStream;
use crate::proto::udp::UdpStream;
use crate::proto::xfer::SerialMessage;
use crate::proto::BufDnsStreamHandle;
use crate::server::{Request, RequestHandler, ResponseHandle, ResponseHandler, TimeoutStream};
#[cfg(all(feature = "dns-over-openssl", not(feature = "dns-over-rustls")))]
use trust_dns_openssl::tls_server::*;

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
                        self::handle_raw_request(message, handler, stream_handle).await;
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
        use openssl::ssl::Ssl;
        use tokio_openssl::SslStream as TokioSslStream;
        use trust_dns_openssl::{tls_server, TlsStream};

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
        use tokio_rustls::TlsAcceptor;
        use trust_dns_rustls::{tls_from_stream, tls_server};

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

        use crate::server::https_handler::h2_handler;
        use trust_dns_rustls::tls_server;

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

pub(crate) fn handle_raw_request<T: RequestHandler>(
    message: SerialMessage,
    request_handler: Arc<Mutex<T>>,
    response_handler: BufDnsStreamHandle,
) -> HandleRawRequest<T::ResponseFuture> {
    let src_addr = message.addr();
    let response_handler = ResponseHandle::new(message.addr(), response_handler);

    // TODO: rather than decoding the message here, this RequestStream should instead
    //       forward the request to another sender such that we could pull serialization off
    //       the IO thread.
    // decode any messages that are ready
    let mut decoder = BinDecoder::new(message.bytes());
    match MessageRequest::read(&mut decoder) {
        Ok(message) => {
            let handle_request =
                self::handle_request(message, src_addr, request_handler, response_handler);
            HandleRawRequest::HandleRequest(handle_request)
        }
        Err(e) => HandleRawRequest::Result(e.into()),
    }
}

pub(crate) fn handle_request<R: ResponseHandler, T: RequestHandler>(
    message: MessageRequest,
    src_addr: SocketAddr,
    request_handler: Arc<Mutex<T>>,
    response_handler: R,
) -> T::ResponseFuture {
    let request = Request {
        message,
        src: src_addr,
    };

    info!(
        "request: {} type: {:?} op_code: {:?} dnssec: {} {}",
        request.message.id(),
        request.message.message_type(),
        request.message.op_code(),
        request.message.edns().map_or(false, Edns::dnssec_ok),
        request
            .message
            .queries()
            .first()
            .map(|q| q.original().to_string())
            .unwrap_or_else(|| "empty_queries".to_string()),
    );

    request_handler
        .lock()
        .expect("poisoned lock")
        .handle_request(request, response_handler)
}

#[must_use = "futures do nothing unless polled"]
pub(crate) enum HandleRawRequest<F: Future<Output = ()>> {
    HandleRequest(F),
    Result(io::Error),
}

impl<F: Future<Output = ()> + Unpin> Future for HandleRawRequest<F> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match *self {
            HandleRawRequest::HandleRequest(ref mut f) => f.poll_unpin(cx),
            HandleRawRequest::Result(ref res) => {
                warn!("failed to handle message: {}", res);
                Poll::Ready(())
            }
        }
    }
}
