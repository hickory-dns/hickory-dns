// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! UDP based DNS client connection for Client impls

use std::net::SocketAddr;
use std::sync::Arc;

use trust_dns_proto::udp::UdpClientStream;
use trust_dns_proto::xfer::{
    DnsExchange, DnsExchangeConnect, DnsMultiplexer, DnsMultiplexerConnect, DnsRequestSender,
    DnsRequestStreamHandle,
};

use client::ClientConnection;
use error::*;
use rr::dnssec::Signer;

/// UDP based DNS Client connection
///
/// Use with `trust_dns::client::Client` impls
#[derive(Clone)]
pub struct UdpClientConnection {
    name_server: SocketAddr,
}

impl UdpClientConnection {
    /// Creates a new client connection.
    ///
    /// *Note* this has side affects of binding the socket to 0.0.0.0 and starting the listening
    ///        event_loop. Expect this to change in the future.
    ///
    /// # Arguments
    ///
    /// * `name_server` - address of the name server to use for queries
    pub fn new(name_server: SocketAddr) -> ClientResult<Self> {
        Ok(UdpClientConnection { name_server })
    }
}

impl ClientConnection for UdpClientConnection {
    type Sender = DnsMultiplexer<UdpClientStream, Signer>;
    type Response = <Self::Sender as DnsRequestSender>::DnsResponseFuture;
    type SenderFuture = DnsMultiplexerConnect<UdpClientStream, Signer>;

    fn new_stream(
        &self,
        signer: Option<Arc<Signer>>,
    ) -> (
        DnsExchangeConnect<Self::SenderFuture, Self::Sender, Self::Response>,
        DnsRequestStreamHandle<Self::Response>,
    ) {
        let (udp_client_stream, handle) = UdpClientStream::new(self.name_server);
        let mp = DnsMultiplexer::new(Box::new(udp_client_stream), handle, signer);
        DnsExchange::connect(mp)
    }
}
