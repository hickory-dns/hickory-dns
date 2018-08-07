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

use tokio_tcp::TcpStream;
use trust_dns_proto::tcp::TcpClientStream;
use trust_dns_proto::xfer::{
    DnsExchange, DnsExchangeConnect, DnsMultiplexer, DnsMultiplexerConnect, DnsRequestSender,
    DnsRequestStreamHandle,
};

use client::ClientConnection;
use error::*;
use rr::dnssec::Signer;

/// Tcp client connection
///
/// Use with `trust_dns::client::Client` impls
#[derive(Clone)]
pub struct TcpClientConnection {
    name_server: SocketAddr,
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
    pub fn with_timeout(name_server: SocketAddr, timeout: Duration) -> ClientResult<Self> {
        Ok(TcpClientConnection {
            name_server,
            timeout,
        })
    }
}

impl ClientConnection for TcpClientConnection {
    type Sender = DnsMultiplexer<TcpClientStream<TcpStream>, Signer>;
    type Response = <Self::Sender as DnsRequestSender>::DnsResponseFuture;
    type SenderFuture = DnsMultiplexerConnect<TcpClientStream<TcpStream>, Signer>;

    fn new_stream(
        &self,
        signer: Option<Arc<Signer>>,
    ) -> (
        DnsExchangeConnect<Self::SenderFuture, Self::Sender, Self::Response>,
        DnsRequestStreamHandle<Self::Response>,
    ) {
        let (tcp_client_stream, handle) =
            TcpClientStream::<TcpStream>::with_timeout(self.name_server, self.timeout);
        let mp = DnsMultiplexer::new(Box::new(tcp_client_stream), handle, signer);
        DnsExchange::connect(mp)
    }
}
