// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! UDP based DNS client connection for Client impls

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::proto::udp::{UdpClientConnect, UdpClientStream, UdpSocketBinder};

use crate::client::ClientConnection;
use crate::client::Signer;
use crate::error::*;

/// UDP based DNS Client connection
///
/// Use with `trust_dns_client::client::Client` impls
#[derive(Clone, Copy)]
pub struct UdpClientConnection<S> {
    name_server: SocketAddr,
    timeout: Duration,
    binder: S,
}

impl<S: UdpSocketBinder + 'static> UdpClientConnection<S> {
    /// Creates a new client connection. With a default timeout of 5 seconds
    ///
    /// # Arguments
    ///
    /// * `name_server` - address of the name server to use for queries
    /// * `binder` - binder for creating UDP sockets
    pub fn new(name_server: SocketAddr, binder: S) -> ClientResult<Self> {
        Self::with_timeout(name_server, binder, Duration::from_secs(5))
    }

    /// Allows a custom timeout
    pub fn with_timeout(
        name_server: SocketAddr,
        binder: S,
        timeout: Duration,
    ) -> ClientResult<Self> {
        Ok(UdpClientConnection {
            name_server,
            timeout,
            binder,
        })
    }
}

impl<S: UdpSocketBinder + 'static> ClientConnection for UdpClientConnection<S> {
    type Sender = UdpClientStream<S, Signer>;
    type SenderFuture = UdpClientConnect<S, Signer>;

    fn new_stream(&self, signer: Option<Arc<Signer>>) -> Self::SenderFuture {
        UdpClientStream::with_timeout_and_signer(
            self.name_server,
            self.timeout,
            signer,
            self.binder.clone(),
        )
    }
}
