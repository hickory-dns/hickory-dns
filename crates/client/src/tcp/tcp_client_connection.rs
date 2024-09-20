// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TCP based DNS client connection for Client impls

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::error::ProtoError;
use hickory_proto::runtime::RuntimeProvider;

use crate::client::{ClientConnection, Signer};
use crate::error::ClientResult;
use crate::proto::tcp::TcpClientStream;
use crate::proto::xfer::{DnsMultiplexer, DnsMultiplexerConnect};

/// Tcp client connection
///
/// Use with `hickory_client::client::Client` impls
#[derive(Clone, Copy)]
pub struct TcpClientConnection<P> {
    provider: P,
    name_server: SocketAddr,
    bind_addr: Option<SocketAddr>,
    timeout: Duration,
}

impl<P> TcpClientConnection<P> {
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
    pub fn new(name_server: SocketAddr, provider: P) -> ClientResult<Self> {
        Self::with_timeout(name_server, Duration::from_secs(5), provider)
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
    pub fn with_timeout(
        name_server: SocketAddr,
        timeout: Duration,
        provider: P,
    ) -> ClientResult<Self> {
        Self::with_bind_addr_and_timeout(name_server, None, timeout, provider)
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
        provider: P,
    ) -> ClientResult<Self> {
        Ok(Self {
            provider,
            name_server,
            bind_addr,
            timeout,
        })
    }
}

impl<P: RuntimeProvider> ClientConnection for TcpClientConnection<P> {
    type Sender = DnsMultiplexer<TcpClientStream<P::Tcp>, Signer>;
    type SenderFuture = DnsMultiplexerConnect<
        Pin<Box<dyn Future<Output = Result<TcpClientStream<P::Tcp>, ProtoError>> + Send>>,
        TcpClientStream<P::Tcp>,
        Signer,
    >;

    fn new_stream(&self, signer: Option<Arc<Signer>>) -> Self::SenderFuture {
        let provider = self.provider.clone();
        let (stream, sender) = TcpClientStream::new(
            self.name_server,
            self.bind_addr,
            Some(self.timeout),
            provider,
        );
        DnsMultiplexer::new(stream, sender, signer)
    }
}
