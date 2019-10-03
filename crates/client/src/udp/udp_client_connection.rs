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

use proto::udp::{UdpClientConnect, UdpClientStream};
use proto::xfer::DnsRequestSender;

use crate::client::ClientConnection;
use crate::error::*;
use crate::rr::dnssec::Signer;

use tokio_net::udp::UdpSocket;

/// UDP based DNS Client connection
///
/// Use with `trust_dns::client::Client` impls
#[derive(Clone)]
pub struct UdpClientConnection {
    name_server: SocketAddr,
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
        Ok(UdpClientConnection {
            name_server,
            timeout,
        })
    }
}

impl ClientConnection for UdpClientConnection {
    type Sender = UdpClientStream<UdpSocket, Signer>;
    type Response = <Self::Sender as DnsRequestSender>::DnsResponseFuture;
    type SenderFuture = UdpClientConnect<UdpSocket, Signer>;

    fn new_stream(&self, signer: Option<Arc<Signer>>) -> Self::SenderFuture {
        UdpClientStream::with_timeout_and_signer(self.name_server, self.timeout, signer)
    }
}
