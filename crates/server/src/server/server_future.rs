// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::pin::Pin;
use std::task::Context;

use futures::{future, Future, FutureExt, Poll, StreamExt};

#[cfg(feature = "dns-over-rustls")]
use rustls::{Certificate, PrivateKey};
use tokio_executor;
use tokio_net::driver::Handle;
use tokio_net::{tcp, udp};

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
}

impl<T: RequestHandler> ServerFuture<T> {
    /// Creates a new ServerFuture with the specified Handler.
    pub fn new(handler: T) -> ServerFuture<T> {
        ServerFuture {
            handler: Arc::new(Mutex::new(handler)),
        }
    }

    /// Register a UDP socket. Should be bound before calling this function.
    pub fn register_socket(&self, socket: udp::UdpSocket) {
        debug!("registered udp: {:?}", socket);

        // create the new UdpStream
        let (buf_stream, stream_handle) = UdpStream::with_bound(socket);
        //let request_stream = RequestStream::new(buf_stream, stream_handle);
        let handler = self.handler.clone();

        // this spawns a ForEach future which handles all the requests into a Handler.
        tokio_executor::spawn(
            buf_stream
                .map(|r: Result<_, _>| match r {
                    Ok(t) => t,
                    Err(e) => panic!("error in UDP request_stream handler: {}", e),
                })
                // TODO: use for_each_concurrent
                .for_each(move |message| {
                    let src_addr = message.addr();
                    debug!("received udp request from: {}", src_addr);
                    self::handle_raw_request(message, handler.clone(), stream_handle.clone())
                }),
        );
    }

    /// Register a UDP socket. Should be bound before calling this function.
    pub fn register_socket_std(&self, socket: std::net::UdpSocket) {
        self.register_socket(
            udp::UdpSocket::from_std(socket, &Handle::default()).expect("bad handle?"),
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
        &self,
        listener: tcp::TcpListener,
        timeout: Duration,
    ) -> io::Result<()> {
        let handler = self.handler.clone();
        debug!("registered tcp: {:?}", listener);

        // for each incoming request...
        tokio_executor::spawn(
            listener
                .incoming()
                .for_each(move |tcp_stream| {
                    let tcp_stream = match tcp_stream {
                        Ok(t) => t,
                        Err(e) => {
                            debug!(
                                "error receiving TCP request_stream error: {}", e
                            );

                            return future::ready(());
                        },
                    };

                    let src_addr = tcp_stream.peer_addr().unwrap();
                    debug!("accepted request from: {}", src_addr);
                    // take the created stream...
                    let (buf_stream, stream_handle) = TcpStream::from_stream(tcp_stream, src_addr);
                    let timeout_stream = TimeoutStream::new(buf_stream, timeout);
                    //let request_stream = RequestStream::new(timeout_stream, stream_handle);
                    let handler = handler.clone();

                    // and spawn to the io_loop
                    tokio_executor::spawn(
                        timeout_stream
                            .for_each(move |message| {
                                message.map(|message| {
                                    Box::pin(self::handle_raw_request(
                                        message,
                                        handler.clone(),
                                        stream_handle.clone(),
                                    )) as Pin<Box<dyn Future<Output = ()> + Send>>
                                }).unwrap_or_else(|e| {
                                    debug!(
                                        "error in TCP request_stream src: {:?} error: {}",
                                        src_addr, e
                                    );
                                    Box::pin(future::ready(())) as Pin<Box<dyn Future<Output = ()> + Send>>
                                })
                            }),
                    );

                    future::ready(())
                })
        );

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
        &self,
        listener: std::net::TcpListener,
        timeout: Duration,
    ) -> io::Result<()> {
        self.register_listener(
            tcp::TcpListener::from_std(listener, &Handle::default())?,
            timeout,
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
    #[cfg(all(feature = "dns-over-openssl", not(feature = "dns-over-rustls")))]
    pub fn register_tls_listener(
        &self,
        listener: tcp::TcpListener,
        timeout: Duration,
        certificate_and_key: ((X509, Option<Stack<X509>>), PKey<Private>),
    ) -> io::Result<()> {
        use futures::future;
        use trust_dns_openssl::{tls_server, TlsStream};

        let ((cert, chain), key) = certificate_and_key;
        let handler = self.handler.clone();
        debug!("registered tcp: {:?}", listener);

        let tls_acceptor = tls_server::new_acceptor(cert, chain, key)?;

        // for each incoming request...
        tokio_executor::spawn(future::lazy(move || {
            listener
                .incoming()
                .for_each(move |tcp_stream| {
                    let src_addr = tcp_stream.peer_addr().unwrap();
                    debug!("accepted request from: {}", src_addr);
                    let handler = handler.clone();

                    // take the created stream...
                    tls_acceptor
                        .accept_async(tcp_stream)
                        .map_err(|e| {
                            io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                format!("tls error: {}", e),
                            )
                        })
                        .and_then(move |tls_stream| {
                            let (buf_stream, stream_handle) =
                                TlsStream::from_stream(tls_stream, src_addr);
                            let timeout_stream = TimeoutStream::new(buf_stream, timeout);
                            //let request_stream = RequestStream::new(timeout_stream, stream_handle);
                            let handler = handler.clone();

                            // and spawn to the io_loop
                            tokio_executor::spawn(
                                timeout_stream
                                    .map_err(move |e| {
                                        debug!(
                                            "error in TLS request_stream src: {:?} error: {}",
                                            src_addr, e
                                        )
                                    })
                                    .for_each(move |message| {
                                        self::handle_raw_request(
                                            message,
                                            handler.clone(),
                                            stream_handle.clone(),
                                        )
                                    })
                                    .map_err(move |_| {
                                        debug!("error in TLS request_stream src: {:?}", src_addr)
                                    }),
                            );

                            Ok(())
                        })
                    // FIXME: need to map this error to Ok, otherwise this is a DOS potential
                    // .map_err(move |e| {
                    //     debug!("error TLS handshake: {:?} error: {:?}", src_addr, e)
                    // })
                })
                .map_err(|e| panic!("error in inbound tls_stream: {}", e))
        }));

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
        &self,
        listener: std::net::TcpListener,
        timeout: Duration,
        certificate_and_key: ((X509, Option<Stack<X509>>), PKey<Private>),
    ) -> io::Result<()> {
        self.register_tls_listener(
            tcp::TcpListener::from_std(listener, &Handle::default())?,
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
    pub fn register_tls_listener(
        &self,
        listener: tcp::TcpListener,
        timeout: Duration,
        certificate_and_key: (Vec<Certificate>, PrivateKey),
    ) -> io::Result<()> {
        use futures::future;
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
        tokio_executor::spawn(future::lazy(move || {
            listener
                .incoming()
                // TODO: use for_each_concurrent
                .for_each(move |tcp_stream| {
                    let src_addr = tcp_stream.peer_addr().unwrap();
                    debug!("accepted request from: {}", src_addr);
                    let handler = handler.clone();

                    // TODO: need to consider timeout of total connect...
                    // take the created stream...
                    tls_acceptor
                        .accept(tcp_stream)
                        .map_err(|e| {
                            io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                format!("tls error: {}", e),
                            )
                        })
                        .and_then(move |tls_stream| {
                            let (buf_stream, stream_handle) = tls_from_stream(tls_stream, src_addr);
                            let timeout_stream = TimeoutStream::new(buf_stream, timeout);
                            //let request_stream = RequestStream::new(timeout_stream, stream_handle);
                            let handler = handler.clone();

                            // and spawn to the io_loop
                            tokio_executor::spawn(
                                timeout_stream
                                    .map_err(move |e| {
                                        debug!(
                                            "error in TLS request_stream src: {:?} error: {}",
                                            src_addr, e
                                        )
                                    })
                                    .for_each(move |message| {
                                        self::handle_raw_request(
                                            message,
                                            handler.clone(),
                                            stream_handle.clone(),
                                        )
                                    })
                                    .map_err(move |_| {
                                        debug!("error in TLS request_stream src: {:?}", src_addr)
                                    }),
                            );

                            Ok(())
                        })
                    // FIXME: need to map this error to Ok, otherwise this is a DOS potential
                    // .map_err(move |e| {
                    //     debug!("error HTTPS handshake: {:?} error: {:?}", src_addr, e)
                    // })
                })
                .map_err(|e| panic!("error in inbound https_stream: {}", e))
        }));

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
        &self,
        listener: tcp::TcpListener,
        // TODO: need to set a timeout between requests.
        _timeout: Duration,
        certificate_and_key: (Vec<Certificate>, PrivateKey),
        dns_hostname: String,
    ) -> io::Result<()> {
        use futures::future;
        use tokio_rustls::TlsAcceptor;

        use server::https_handler::h2_handler;
        use trust_dns_rustls::tls_server;

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
        let dns_hostname = dns_hostname.clone();
        tokio_executor::spawn(future::lazy(move || {
            let dns_hostname = dns_hostname.clone();

            listener
                .incoming()
                .map_err(|e| warn!("error in inbound https_stream: {}", e))
                .for_each(move |tcp_stream| {
                    let src_addr = tcp_stream.peer_addr().unwrap();
                    debug!("accepted request from: {}", src_addr);
                    let handler = handler.clone();
                    let dns_hostname = dns_hostname.clone();

                    // TODO: need to consider timeout of total connect...
                    // take the created stream...
                    tls_acceptor
                        .accept(tcp_stream)
                        .map_err(|e| warn!("tls error: {}", e))
                        .and_then(move |tls_stream| {
                            h2_handler(handler, tls_stream, src_addr, dns_hostname)
                        })
                    // FIXME: need to map this error to Ok, otherwise this is a DOS potential
                    // .map_err(move |e| {
                    //     debug!("error HTTPS handshake: {:?} error: {:?}", src_addr, e)
                    // })
                })
                .map_err(|_| panic!("error in inbound https_stream"))
        }));

        Ok(())
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
pub(crate) enum HandleRawRequest<F: Future<Output = Result<(), ()>>> {
    HandleRequest(F),
    Result(io::Error),
}

// TODO: output ()
impl<F: Future<Output = Result<(), ()>> + Unpin> Future for HandleRawRequest<F> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match *self {
            HandleRawRequest::HandleRequest(ref mut f) => f.poll_unpin(cx).map(|_: Result<_,_>| ()),
            HandleRawRequest::Result(ref res) => {
                warn!("failed to handle message: {}", res);
                Poll::Ready(())
            }
        }
    }
}
