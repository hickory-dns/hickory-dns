// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use futures::{Async, Future, Poll, Stream};
use native_tls::Pkcs12;
use native_tls::Protocol::Tlsv12;
use native_tls::TlsAcceptor;
use tokio_core;
use tokio_core::reactor::Core;
use tokio_tls::TlsAcceptorExt;

use trust_dns::op::RequestHandler;
use trust_dns::udp::UdpStream;
use trust_dns::tcp::TcpStream;
use trust_dns::tls::TlsStream;

use server::{Request, RequestStream, ResponseHandle, TimeoutStream};
use authority::Catalog;

// TODO, would be nice to have a Slab for buffers here...
pub struct ServerFuture {
    io_loop: Core,
    catalog: Arc<Catalog>, // should the catalog just be static?
}

impl ServerFuture {
    /// Creates a new ServerFuture with the specified Catalog of Zones.
    pub fn new(catalog: Catalog) -> io::Result<ServerFuture> {
        Ok(ServerFuture {
            io_loop: try!(Core::new()),
            catalog: Arc::new(catalog),
        })
    }

    /// Register a UDP socket. Should be bound before calling this function.
    pub fn register_socket(&self, socket: std::net::UdpSocket) {
        debug!("registered udp: {:?}", socket);

        // create the new UdpStream
        let (buf_stream, stream_handle) = UdpStream::with_bound(socket, self.io_loop.handle());
        let request_stream = RequestStream::new(buf_stream, stream_handle);
        let catalog = self.catalog.clone();

        // this spawns a ForEach future which handles all the requests into a Catalog.
        self.io_loop.handle().spawn(// TODO dedup with below into generic func
                                    request_stream.for_each(move |(request, response_handle)| {
                Self::handle_request(request, response_handle, catalog.clone())
            })
            .map_err(|e| debug!("error in UDP request_stream handler: {}", e)));
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
    pub fn register_listener(&self,
                             listener: std::net::TcpListener,
                             timeout: Duration)
                             -> io::Result<()> {
        let handle = self.io_loop.handle();
        let catalog = self.catalog.clone();
        // TODO: this is an awkward interface with socketaddr...
        let addr = try!(listener.local_addr());
        let listener = tokio_core::net::TcpListener::from_listener(listener, &addr, &handle)
            .expect("could not register listener");
        debug!("registered tcp: {:?}", listener);

        // for each incoming request...
        self.io_loop.handle().spawn(listener.incoming()
            .for_each(move |(tcp_stream, src_addr)| {
                debug!("accepted request from: {}", src_addr);
                // take the created stream...
                let (buf_stream, stream_handle) = TcpStream::from_stream(tcp_stream, src_addr);
                let timeout_stream = try!(TimeoutStream::new(buf_stream, timeout, handle.clone()));
                let request_stream = RequestStream::new(timeout_stream, stream_handle);
                let catalog = catalog.clone();

                // and spawn to the io_loop
                handle.spawn(request_stream.for_each(move |(request, response_handle)| {
                        Self::handle_request(request, response_handle, catalog.clone())
                    })
                    .map_err(move |e| {
                        debug!("error in TCP request_stream src: {:?} error: {}",
                               src_addr,
                               e)
                    }));

                Ok(())
            })
            .map_err(|e| debug!("error in inbound tcp_stream: {}", e)));

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
    pub fn register_tls_listener(&self,
                                 listener: std::net::TcpListener,
                                 timeout: Duration,
                                 pkcs12: Pkcs12)
                                 -> io::Result<()> {
        let handle = self.io_loop.handle();
        let catalog = self.catalog.clone();
        // TODO: this is an awkward interface with socketaddr...
        let addr = listener.local_addr().expect("listener is not bound?");
        let listener = tokio_core::net::TcpListener::from_listener(listener, &addr, &handle)
            .expect("could not register listener");
        debug!("registered tcp: {:?}", listener);

        let mut builder = try!(TlsAcceptor::builder(pkcs12).map_err(|e| {
            io::Error::new(io::ErrorKind::ConnectionRefused,
                           format!("tls error: {}", e))
        }));
        try!(builder.supported_protocols(&[Tlsv12]).map_err(|e| {
            io::Error::new(io::ErrorKind::ConnectionRefused,
                           format!("tls error: {}", e))
        }));
        let tls_acceptor = try!(builder.build().map_err(|e| {
            io::Error::new(io::ErrorKind::ConnectionRefused,
                           format!("tls error: {}", e))
        }));

        // for each incoming request...
        self.io_loop.handle().spawn(
      listener.incoming()
              .for_each(move |(tcp_stream, src_addr)| {
                debug!("accepted request from: {}", src_addr);
                let timeout = timeout.clone();
                let handle = handle.clone();
                let catalog = catalog.clone();

                // take the created stream...
                tls_acceptor.accept_async(tcp_stream)
                            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, format!("tls error: {}", e)))
                            .and_then(move |tls_stream| {
                              let (buf_stream, stream_handle) = TlsStream::from_stream(tls_stream, src_addr.clone());
                              let timeout_stream = try!(TimeoutStream::new(buf_stream, timeout, handle.clone()));
                              let request_stream = RequestStream::new(timeout_stream, stream_handle);
                              let catalog = catalog.clone();

                              // and spawn to the io_loop
                              handle.spawn(
                                request_stream.for_each(move |(request, response_handle)| {
                                  Self::handle_request(request, response_handle, catalog.clone())
                                })
                                .map_err(move |e| debug!("error in TCP request_stream src: {:?} error: {}", src_addr, e))
                              );

                              Ok(())
                            })
                            //.map_err(move |e| debug!("error TLS handshake: {:?} error: {:?}", src_addr, e))
              })
              .map_err(|e| debug!("error in inbound tcp_stream: {}", e))
    );

        Ok(())
    }

    /// TODO how to do threads? should we do a bunch of listener threads and then query threads?
    /// Ideally the processing would be n-threads for recieving, which hand off to m-threads for
    ///  request handling. It would generally be the case that n <= m.
    pub fn listen(&mut self) -> io::Result<()> {
        info!("Server starting up");
        try!(self.io_loop.run(Forever));

        Err(io::Error::new(io::ErrorKind::Interrupted,
                           "Server stopping due to interruption"))
    }

    fn handle_request(request: Request,
                      mut response_handle: ResponseHandle,
                      catalog: Arc<Catalog>)
                      -> io::Result<()> {
        let response = catalog.handle_request(&request.message);
        response_handle.send(response)
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
