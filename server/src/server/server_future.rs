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

use futures::{Async, Future, future, Poll, Stream};

use tokio_core::reactor::Core;
use tokio_reactor::Handle;
use tokio_tcp;
use tokio_udp;

use trust_dns::error::*;
use trust_dns::serialize::binary::{BinDecodable, BinDecoder};
use trust_dns::tcp::TcpStream;
use trust_dns::udp::UdpStream;
use trust_dns::BufStreamHandle;

#[cfg(feature = "dns-over-openssl")]
use trust_dns_openssl::{tls_server, TlsStream};

#[cfg(feature = "dns-over-openssl")]
use trust_dns_openssl::tls_server::*;

use authority::MessageRequest;
use server::{Request, RequestHandler, ResponseHandle, TimeoutStream};

// TODO, would be nice to have a Slab for buffers here...

/// A Futures based implementation of a DNS server
pub struct ServerFuture<T: RequestHandler + Send + 'static> {
    io_loop: Core,
    handler: Arc<Mutex<T>>,
}

impl<T: RequestHandler + Send> ServerFuture<T> {
    /// Creates a new ServerFuture with the specified Handler.
    pub fn new(handler: T) -> io::Result<ServerFuture<T>> {
        Ok(ServerFuture {
            io_loop: Core::new()?,
            handler: Arc::new(Mutex::new(handler)),
        })
    }

    /// Register a UDP socket. Should be bound before calling this function.
    pub fn register_socket(&self, socket: tokio_udp::UdpSocket) {
        debug!("registered udp: {:?}", socket);

        // create the new UdpStream
        let (buf_stream, stream_handle) = UdpStream::with_bound(socket);
        //let request_stream = RequestStream::new(buf_stream, stream_handle);
        let handler = self.handler.clone();

        // this spawns a ForEach future which handles all the requests into a Handler.
        self.io_loop.handle().spawn(
            buf_stream
                .for_each(move |(buffer, src_addr)| {
                    Self::handle_request(buffer, src_addr, stream_handle.clone(), handler.clone())
                        .map_err(move |e| {
                            debug!("error parsing UDP request src: {:?} error: {}", src_addr, e)
                        })
                        .ok();

                    // continue processing...
                    Ok(())
                })
                .map_err(|e| panic!("error in UDP request_stream handler: {}", e)),
        );
    }

    /// Register a UDP socket. Should be bound before calling this function.
    pub fn register_socket_std(&self, socket: std::net::UdpSocket) {
        self.register_socket(tokio_udp::UdpSocket::from_std(socket, &Handle::current()).expect("bad handle?"))
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
        listener: tokio_tcp::TcpListener,
        timeout: Duration,
    ) -> io::Result<()> {
        let handle = self.io_loop.handle();
        let handler = self.handler.clone();
        debug!("registered tcp: {:?}", listener);

        // for each incoming request...
        self.io_loop.handle().spawn(
            listener
                .incoming()
                .for_each(move |tcp_stream| {
                    let src_addr = tcp_stream.peer_addr().unwrap();
                    debug!("accepted request from: {}", src_addr);
                    // take the created stream...
                    let (buf_stream, stream_handle) = TcpStream::from_stream(tcp_stream, src_addr);
                    let timeout_stream = TimeoutStream::new(buf_stream, timeout);
                    //let request_stream = RequestStream::new(timeout_stream, stream_handle);
                    let handler = handler.clone();

                    // and spawn to the io_loop
                    handle.spawn(
                        timeout_stream
                            .for_each(move |(buffer, src_addr)| {
                                Self::handle_request(
                                    buffer,
                                    src_addr,
                                    stream_handle.clone(),
                                    handler.clone(),
                                )
                            })
                            .map_err(move |e| {
                                debug!(
                                    "error in TCP request_stream src: {:?} error: {}",
                                    src_addr, e
                                )
                            }),
                    );

                    Ok(())
                })
                .map_err(|e| panic!("error in inbound tcp_stream: {}", e)),
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
        self.register_listener(tokio_tcp::TcpListener::from_std(listener, &Handle::current())?, timeout)
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
    #[cfg(feature = "dns-over-openssl")]
    pub fn register_tls_listener(
        &self,
        listener: tokio_tcp::TcpListener,
        timeout: Duration,
        pkcs12: ParsedPkcs12,
    ) -> io::Result<()> {
        let handle = self.io_loop.handle();
        let handler = self.handler.clone();
        debug!("registered tcp: {:?}", listener);

        let tls_acceptor = tls_server::new_acceptor(&pkcs12)?;

        // for each incoming request...
        self.io_loop.handle().spawn(future::lazy(move || {
            listener
                .incoming()
                .for_each(move |tcp_stream| {
                    let src_addr = tcp_stream.peer_addr().unwrap();
                    debug!("accepted request from: {}", src_addr);
                    let handle = handle.clone();
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
                            handle.spawn(
                                timeout_stream
                                    .for_each(move |(buffer, addr)| {
                                        Self::handle_request(
                                            buffer,
                                            addr,
                                            stream_handle.clone(),
                                            handler.clone(),
                                        )
                                    })
                                    .map_err(move |e| {
                                        debug!(
                                            "error in TCP request_stream src: {:?} error: {}",
                                            src_addr, e
                                        )
                                    }),
                            );

                            Ok(())
                        })
                    //.map_err(move |e| debug!("error TLS handshake: {:?} error: {:?}", src_addr, e))
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
    #[cfg(feature = "dns-over-openssl")]
    pub fn register_tls_listener_std(
        &self,
        listener: std::net::TcpListener,
        timeout: Duration,
        pkcs12: ParsedPkcs12,
    ) -> io::Result<()> {
        self.register_tls_listener(tokio_tcp::TcpListener::from_std(listener, &Handle::current())?, timeout, pkcs12)
    }

    /// TODO: how to do threads? should we do a bunch of listener threads and then query threads?
    /// Ideally the processing would be n-threads for recieving, which hand off to m-threads for
    ///  request handling. It would generally be the case that n <= m.
    pub fn listen(&mut self) -> io::Result<()> {
        info!("Server starting up");
        self.io_loop.run(Forever)?;

        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "Server stopping due to interruption",
        ))
    }

    /// Returns a reference to the tokio core loop driving this Server instance
    pub fn tokio_core(&mut self) -> &mut Core {
        &mut self.io_loop
    }

    fn handle_request(
        buffer: Vec<u8>,
        src_addr: SocketAddr,
        stream_handle: BufStreamHandle<ClientError>,
        handler: Arc<Mutex<T>>,
    ) -> io::Result<()> {
        let response_handle = ResponseHandle::new(src_addr, stream_handle);

        // TODO: rather than decoding the message here, this RequestStream should instead
        //       forward the request to another sender such that we could pull serialization off
        //       the IO thread.
        // decode any messages that are ready
        let mut decoder = BinDecoder::new(&buffer);
        let message = MessageRequest::read(&mut decoder)?;

        let request = Request {
            message: message,
            src: src_addr,
        };

        info!(
            "request: {} type: {:?} op_code: {:?} dnssec: {} {}",
            request.message.id(),
            request.message.message_type(),
            request.message.op_code(),
            request
                .message
                .edns()
                .map_or(false, |edns| edns.dnssec_ok()),
            request
                .message
                .queries()
                .first()
                .map(|q| q.original().to_string())
                .unwrap_or_else(|| "empty_queries".to_string()),
        );

        handler.lock().unwrap().handle_request(&request, response_handle)
    }
}

struct Forever;

impl Future for Forever {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // run forever...
        Ok(Async::NotReady)
    }
}
