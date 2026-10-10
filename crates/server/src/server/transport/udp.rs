// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::sync::Arc;

use tokio::task::JoinSet;
use tracing::debug;

use super::Transport;
use crate::{
    net::{
        BufDnsStreamHandle, NetError,
        runtime::DnsUdpSocket,
        udp::{UdpListener, UdpStream},
        xfer::Protocol,
    },
    proto::op::SerialMessage,
    server::{
        ServerContext, request_handler::RequestHandler, utils::is_unrecoverable_socket_error,
    },
};

/// Builder and transport implementation for UDP.
///
/// Wraps an already-bound UDP socket and handles incoming DNS datagrams.
#[derive(Debug)]
pub struct Udp<S: DnsUdpSocket> {
    listener: UdpListener<S>,
    stream_handle: BufDnsStreamHandle,
}

impl<S: DnsUdpSocket> Udp<S> {
    /// Constructs a new UDP transport.
    ///
    /// The `socket` must be already bound to the desired local address.
    pub fn new(socket: S) -> Self {
        // The placeholder remote address is replaced with each request's source address.
        let (stream, stream_handle) =
            UdpStream::with_bound(socket, ([127, 255, 255, 254], 0).into());
        Self {
            listener: UdpListener::new(stream),
            stream_handle,
        }
    }
}

impl<S> Transport for Udp<S>
where
    S: DnsUdpSocket + 'static,
{
    async fn accept<H: RequestHandler>(
        &mut self,
        cx: Arc<ServerContext<H>>,
        tasks: &mut JoinSet<()>,
    ) -> Result<bool, NetError> {
        let message = match self.listener.receive().await {
            Some(Ok(message)) => message,
            Some(Err(error)) => {
                debug!(%error, protocol = %Protocol::Udp, "error receiving transport input");
                return Ok(!is_unrecoverable_socket_error(&error));
            }
            None => {
                // End of stream
                // TODO: let's consider capturing all the initial configuration details so that the socket could be recreated...
                return Ok(false);
            }
        };

        let src_addr = message.addr();
        let stream_handle = self.stream_handle.with_remote_addr(src_addr);
        tasks.spawn(async move {
            debug!(%src_addr, protocol = %Protocol::Udp, "starting request processing");

            Self::handle(message, stream_handle, cx).await;
        });

        Ok(true)
    }
}

impl<S: DnsUdpSocket> Udp<S> {
    async fn handle(
        message: SerialMessage,
        stream_handle: BufDnsStreamHandle,
        cx: Arc<ServerContext<impl RequestHandler>>,
    ) {
        cx.handle_raw_request(message, Protocol::Udp, stream_handle)
            .await;
    }
}
