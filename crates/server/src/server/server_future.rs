// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use futures::{future, Future, FutureExt, StreamExt};

#[cfg(feature = "dns-over-rustls")]
use rustls::{Certificate, PrivateKey};
use tokio::net;
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

use proto::error::ProtoError;
use proto::op::Edns;
use proto::serialize::binary::{BinDecodable, BinDecoder};
use proto::tcp::TcpStream;
use proto::udp::UdpStream;
use proto::xfer::SerialMessage;
use proto::BufStreamHandle;
#[cfg(all(feature = "dns-over-openssl", not(feature = "dns-over-rustls")))]
use trust_dns_openssl::tls_server::*;

use crate::authority::MessageRequest;
use crate::server::{Request, RequestHandler, ResponseHandle, ResponseHandler, TimeoutStream};

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
    pub fn register_socket(&mut self, socket: net::UdpSocket, runtime: &Runtime) {
        debug!("registering udp: {:?}", socket);

        let spawner = runtime.handle().clone();

        // create the new UdpStream
        let (mut buf_stream, stream_handle) = UdpStream::with_bound(socket);
        //let request_stream = RequestStream::new(buf_stream, stream_handle);
        let handler = self.handler.clone();

        // this spawns a ForEach future which handles all the requests into a Handler.
        let join_handle = runtime.spawn(async move {
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
                let stream_handle = stream_handle.clone();

                spawner.spawn(async move {
                    self::handle_raw_request(message, handler, stream_handle).await;
                });
            }

            // TODO: let's consider capturing all the initial configuration details so that the socket could be recreated...
            Err(ProtoError::from("unexpected close of UDP socket"))
        });

        self.joins.push(join_handle);
    }

    /// Register a UDP socket. Should be bound before calling this function.
    pub fn register_socket_std(&mut self, socket: std::net::UdpSocket, runtime: &Runtime) {
        self.register_socket(
            net::UdpSocket::from_std(socket).expect("bad handle?"),
            runtime,
        )
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
    pub fn register_listener(
        &mut self,
        listener: net::TcpListener,
        timeout: Duration,
        runtime: &Runtime,
    ) -> io::Result<()> {
        debug!("register tcp: {:?}", listener);

        let spawner = runtime.handle().clone();
        let handler = self.handler.clone();

        // for each incoming request...
        let join = runtime.spawn(async move {
            let mut listener = listener;
            let mut incoming = listener.incoming();

            while let Some(tcp_stream) = incoming.next().await {
                let tcp_stream = match tcp_stream {
                    Ok(t) => t,
                    Err(e) => {
                        debug!("error receiving TCP tcp_stream error: {}", e);
                        continue;
                    }
                };

                let handler = handler.clone();

                // and spawn to the io_loop
                spawner.spawn(async move {
                    let src_addr = tcp_stream.peer_addr().unwrap();
                    debug!("accepted request from: {}", src_addr);
                    // take the created stream...
                    let (buf_stream, stream_handle) = TcpStream::from_stream(tcp_stream, src_addr);
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
                        self::handle_raw_request(message, handler.clone(), stream_handle.clone())
                            .await;
                    }
                });
            }

            Err(ProtoError::from("unexpected close of TCP socket"))
        });

        self.joins.push(join);
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
    pub fn register_listener_std(
        &mut self,
        listener: std::net::TcpListener,
        timeout: Duration,
        runtime: &Runtime,
    ) -> io::Result<()> {
        self.register_listener(net::TcpListener::from_std(listener)?, timeout, runtime)
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
    pub fn register_tls_listener(
        &mut self,
        listener: net::TcpListener,
        timeout: Duration,
        certificate_and_key: ((X509, Option<Stack<X509>>), PKey<Private>),
        runtime: &Runtime,
    ) -> io::Result<()> {
        use trust_dns_openssl::{tls_server, TlsStream};

        let ((cert, chain), key) = certificate_and_key;

        let spawner = runtime.handle().clone();
        let handler = self.handler.clone();
        debug!("registered tcp: {:?}", listener);

        let tls_acceptor = Box::pin(tls_server::new_acceptor(cert, chain, key)?);

        // for each incoming request...
        let join = runtime.spawn(async move {
            let mut listener = listener;
            let mut incoming = listener.incoming();

            while let Some(tcp_stream) = incoming.next().await {
                let tcp_stream = match tcp_stream {
                    Ok(t) => t,
                    Err(e) => {
                        debug!("error receiving TLS tcp_stream error: {}", e);
                        continue;
                    }
                };

                let handler = handler.clone();
                let tls_acceptor = tls_acceptor.clone();

                // kick out to a different task immediately, let them do the TLS handshake
                spawner.spawn(async move {
                    let src_addr = tcp_stream.peer_addr().unwrap();
                    debug!("starting TLS request from: {}", src_addr);

                    // perform the TLS
                    let tls_stream = tokio_openssl::accept(&*tls_acceptor, tcp_stream).await;

                    let tls_stream = match tls_stream {
                        Ok(tls_stream) => tls_stream,
                        Err(e) => {
                            debug!("tls handshake src: {} error: {}", src_addr, e);
                            return ();
                        }
                    };
                    debug!("accepted TLS request from: {}", src_addr);
                    let (buf_stream, stream_handle) = TlsStream::from_stream(tls_stream, src_addr);
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

                        self::handle_raw_request(message, handler.clone(), stream_handle.clone())
                            .await;
                    }
                });
            }

            Err(ProtoError::from("unexpected close of TLS socket"))
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
    pub fn register_tls_listener_std(
        &mut self,
        listener: std::net::TcpListener,
        timeout: Duration,
        certificate_and_key: ((X509, Option<Stack<X509>>), PKey<Private>),
        runtime: &Runtime,
    ) -> io::Result<()> {
        self.register_tls_listener(
            net::TcpListener::from_std(listener)?,
            timeout,
            certificate_and_key,
            runtime,
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
    pub fn register_tls_listener(
        &mut self,
        listener: net::TcpListener,
        timeout: Duration,
        certificate_and_key: (Vec<Certificate>, PrivateKey),
        runtime: &Runtime,
    ) -> io::Result<()> {
        use tokio_rustls::TlsAcceptor;
        use trust_dns_rustls::{tls_from_stream, tls_server};

        let spawner = runtime.handle().clone();
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
        let join = runtime.spawn(async move {
            let mut listener = listener;
            let mut incoming = listener.incoming();

            while let Some(tcp_stream) = incoming.next().await {
                let tcp_stream = match tcp_stream {
                    Ok(t) => t,
                    Err(e) => {
                        debug!("error receiving TLS tcp_stream error: {}", e);
                        continue;
                    }
                };

                let handler = handler.clone();
                let tls_acceptor = tls_acceptor.clone();

                // kick out to a different task immediately, let them do the TLS handshake
                spawner.spawn(async move {
                    let src_addr = tcp_stream.peer_addr().unwrap();
                    debug!("starting TLS request from: {}", src_addr);

                    // perform the TLS
                    let tls_stream = tls_acceptor.accept(tcp_stream).await;

                    let tls_stream = match tls_stream {
                        Ok(tls_stream) => tls_stream,
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

                        self::handle_raw_request(message, handler.clone(), stream_handle.clone())
                            .await;
                    }
                });
            }

            Err(ProtoError::from("unexpected close of TLS socket"))
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
    pub fn register_https_listener(
        &self,
        listener: tcp::TcpListener,
        timeout: Duration,
        pkcs12: ParsedPkcs12,
        runtime: &Runtime,
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
    pub fn register_https_listener(
        &mut self,
        listener: net::TcpListener,
        // TODO: need to set a timeout between requests.
        _timeout: Duration,
        certificate_and_key: (Vec<Certificate>, PrivateKey),
        dns_hostname: String,
        runtime: &Runtime,
    ) -> io::Result<()> {
        use tokio_rustls::TlsAcceptor;

        use crate::server::https_handler::h2_handler;
        use trust_dns_rustls::tls_server;

        let spawner = runtime.handle().clone();
        let dns_hostname = Arc::new(dns_hostname);
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
        let join = runtime.spawn(async move {
            let mut listener = listener;
            let mut incoming = listener.incoming();

            let dns_hostname = dns_hostname;

            while let Some(tcp_stream) = incoming.next().await {
                let tcp_stream = match tcp_stream {
                    Ok(t) => t,
                    Err(e) => {
                        debug!("error receiving HTTPS tcp_stream error: {}", e);
                        continue;
                    }
                };

                let handler = handler.clone();
                let tls_acceptor = tls_acceptor.clone();
                let dns_hostname = dns_hostname.clone();

                spawner.spawn(async move {
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

            Err(ProtoError::from("unexpected close of HTTPS socket"))
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
    response_handler: BufStreamHandle,
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

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match *self {
            HandleRawRequest::HandleRequest(ref mut f) => f.poll_unpin(cx),
            HandleRawRequest::Result(ref res) => {
                warn!("failed to handle message: {}", res);
                Poll::Ready(())
            }
        }
    }
}
