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

use crate::client::{ClientConnection, Signer};
use crate::error::*;
use crate::proto::tcp::{TcpClientConnect, TcpClientStream, TcpConnector};
use crate::proto::xfer::{DnsMultiplexer, DnsMultiplexerConnect};

/// Tcp client connection
///
/// Use with `trust_dns_client::client::Client` impls
#[derive(Clone, Copy)]
pub struct TcpClientConnection<S: TcpConnector> {
    name_server: SocketAddr,
    timeout: Duration,
    connector: S,
}

impl<S: TcpConnector> TcpClientConnection<S> {
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
    pub fn new(name_server: SocketAddr, connector: S) -> ClientResult<Self> {
        Self::with_timeout(name_server, Duration::from_secs(5), connector)
    }

    /// Creates a new client connection.
    ///
    /// *Note* this has side affects of establishing the connection to the specified DNS server and
    ///        starting the event_loop. Expect this to change in the future.
    ///
    /// # Arguments
    ///
    /// * `name_server` - address of the name server to use for queries
    pub fn with_timeout(
        name_server: SocketAddr,
        timeout: Duration,
        connector: S,
    ) -> ClientResult<Self> {
        Ok(TcpClientConnection {
            name_server,
            timeout,
            connector,
        })
    }
}

impl<S: TcpConnector> ClientConnection for TcpClientConnection<S>
where
    <S as TcpConnector>::Socket: tokio::io::AsyncRead + tokio::io::AsyncWrite,
{
    type Sender = DnsMultiplexer<TcpClientStream<S::Socket>, Signer>;
    type SenderFuture =
        DnsMultiplexerConnect<TcpClientConnect<S::Socket>, TcpClientStream<S::Socket>, Signer>;

    fn new_stream(&self, signer: Option<Arc<Signer>>) -> Self::SenderFuture {
        let (tcp_client_stream, handle) = TcpClientStream::<S::Socket>::with_timeout(
            self.name_server,
            self.timeout,
            self.connector.clone(),
        );
        DnsMultiplexer::new(tcp_client_stream, handle, signer)
    }
}
