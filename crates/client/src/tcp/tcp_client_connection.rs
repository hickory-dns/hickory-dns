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
use crate::proto::tcp::{TcpClientConnect, TcpClientStream};
use crate::proto::xfer::{DnsMultiplexer, DnsMultiplexerConnect};
use crate::proto::RuntimeProvider;

/// Tcp client connection
///
/// Use with `trust_dns_client::client::Client` impls
#[derive(Clone, Copy)]
pub struct TcpClientConnection<R: RuntimeProvider> {
    name_server: SocketAddr,
    timeout: Duration,
    runtime: R,
}

impl<R: RuntimeProvider> TcpClientConnection<R> {
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
    pub fn new(name_server: SocketAddr, runtime: R) -> ClientResult<Self> {
        Self::with_timeout(name_server, Duration::from_secs(5), runtime)
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
        runtime: R,
    ) -> ClientResult<Self> {
        Ok(TcpClientConnection {
            name_server,
            timeout,
            runtime,
        })
    }
}

impl<R: RuntimeProvider> ClientConnection for TcpClientConnection<R>
where
    R::TcpConnection: tokio::io::AsyncRead + tokio::io::AsyncWrite,
{
    type Sender = DnsMultiplexer<TcpClientStream<R::TcpConnection>, Signer>;
    type SenderFuture = DnsMultiplexerConnect<
        TcpClientConnect<R::TcpConnection>,
        TcpClientStream<R::TcpConnection>,
        Signer,
    >;

    fn new_stream(&self, signer: Option<Arc<Signer>>) -> Self::SenderFuture {
        let (tcp_client_stream, handle) = TcpClientStream::<R::TcpConnection>::with_timeout(
            self.name_server,
            self.timeout,
            self.runtime.clone(),
        );
        DnsMultiplexer::new(tcp_client_stream, handle, signer)
    }
}
