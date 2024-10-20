// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! UDP based DNS client connection for Client impls

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::client::ClientConnection;
use crate::error::ClientResult;
use crate::proto::udp::{UdpClientConnect, UdpClientStream};
use hickory_proto::op::MessageFinalizer;
use hickory_proto::runtime::TokioRuntimeProvider;

/// UDP based DNS Client connection
///
/// Use with `hickory_client::client::Client` impls
#[derive(Clone, Copy)]
pub struct UdpClientConnection {
    name_server: SocketAddr,
    bind_addr: Option<SocketAddr>,
    timeout: Duration,
}

impl UdpClientConnection {
    /// Creates a new client connection. With a default timeout of 5 seconds
    ///
    /// # Arguments
    ///
    /// * `name_server` - address of the name server to use for queries
    pub fn new(name_server: SocketAddr) -> ClientResult<Self> {
        Self::with_timeout(name_server, Duration::from_secs(5))
    }

    /// Allows a custom timeout
    pub fn with_timeout(name_server: SocketAddr, timeout: Duration) -> ClientResult<Self> {
        Self::with_bind_addr_and_timeout(name_server, None, timeout)
    }

    /// Creates a new client connection. With a default timeout of 5 seconds
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

impl ClientConnection for UdpClientConnection {
    type Sender = UdpClientStream<TokioRuntimeProvider>;
    type SenderFuture = UdpClientConnect<TokioRuntimeProvider>;

    fn new_stream(&self, signer: Option<Arc<dyn MessageFinalizer>>) -> Self::SenderFuture {
        UdpClientStream::builder(self.name_server, TokioRuntimeProvider::new())
            .with_signer(signer)
            .with_timeout(Some(self.timeout))
            .with_bind_addr(self.bind_addr)
            .build()
    }
}
