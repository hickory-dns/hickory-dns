// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TCP based DNS client connection for Client impls

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;

use crate::client::{ClientConnection, Signer};
use crate::error::*;
use crate::proto::iocompat::AsyncIoTokioAsStd;
use crate::proto::tcp::{TcpClientConnect, TcpClientStream};
use crate::proto::xfer::{DnsMultiplexer, DnsMultiplexerConnect};

/// Tcp client connection
///
/// Use with `trust_dns_client::client::Client` impls
#[derive(Clone, Copy)]
pub struct TcpClientConnection {
    name_server: SocketAddr,
    bind_addr: Option<SocketAddr>,
    timeout: Duration,
}

impl TcpClientConnection {
    /// Creates a new client connection.
    ///
    /// *Note* this has side affects of establishing the connection to the specified DNS server and
    ///        starting the event_loop. Expect this to change in the future.
    ///
    /// Default connection timeout is 5 seconds
    ///
    /// # Arguments
    ///
    /// * `name_server` - address of the name server to use for queries
    pub fn new(name_server: SocketAddr) -> ClientResult<Self> {
        Self::with_timeout(name_server, Duration::from_secs(5))
    }

    /// Creates a new client connection.
    ///
    /// *Note* this has side affects of establishing the connection to the specified DNS server and
    ///        starting the event_loop. Expect this to change in the future.
    ///
    /// # Arguments
    ///
    /// * `name_server` - address of the name server to use for queries
    /// * `timeout` - connection timeout
    pub fn with_timeout(name_server: SocketAddr, timeout: Duration) -> ClientResult<Self> {
        Self::with_bind_addr_and_timeout(name_server, None, timeout)
    }

    /// Creates a new client connection.
    ///
    /// *Note* this has side affects of establishing the connection to the specified DNS server and
    ///        starting the event_loop. Expect this to change in the future.
    ///
    /// # Arguments
    ///
    /// * `name_server` - address of the name server to use for queries
    /// * `bind_addr` - IP address and port to connect from
    /// * `timeout` - connection timeout
    pub fn with_bind_addr_and_timeout(
        name_server: SocketAddr,
        bind_addr: Option<SocketAddr>,
        timeout: Duration,
    ) -> ClientResult<Self> {
        Ok(Self {
            name_server,
            bind_addr,
            timeout,
        })
    }
}

impl ClientConnection for TcpClientConnection {
    type Sender = DnsMultiplexer<TcpClientStream<AsyncIoTokioAsStd<TcpStream>>, Signer>;
    type SenderFuture = DnsMultiplexerConnect<
        TcpClientConnect<AsyncIoTokioAsStd<TcpStream>>,
        TcpClientStream<AsyncIoTokioAsStd<TcpStream>>,
        Signer,
    >;

    fn new_stream(&self, signer: Option<Arc<Signer>>) -> Self::SenderFuture {
        let (tcp_client_stream, handle) =
            TcpClientStream::<AsyncIoTokioAsStd<TcpStream>>::with_bind_addr_and_timeout(
                self.name_server,
                self.bind_addr,
                self.timeout,
            );
        DnsMultiplexer::new(tcp_client_stream, handle, signer)
    }
}
