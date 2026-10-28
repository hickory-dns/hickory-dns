// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::sync::Arc;

use futures_util::StreamExt;
use tokio::task::JoinSet;
use tracing::{debug, warn};

use super::Transport;
use crate::{
    net::{NetError, runtime::DnsUdpSocket, udp::UdpStream, xfer::Protocol},
    proto::op::DEFAULT_MAX_PAYLOAD_LEN,
    server::{
        ServerContext, is_unrecoverable_socket_error, reap_tasks, request_handler::RequestHandler,
        sanitize_src_address,
    },
};

/// Builder and transport implementation for UDP.
///
/// Wraps an already-bound UDP socket and handles incoming DNS datagrams.
#[derive(Debug)]
pub struct Udp<S: DnsUdpSocket> {
    socket: S,
    max_payload_size: u16,
}

impl<S: DnsUdpSocket> Udp<S> {
    /// Constructs a new UDP transport.
    ///
    /// The `socket` must be already bound to the desired local address.
    /// The max payload size defaults to [`DEFAULT_MAX_PAYLOAD_LEN`].
    pub fn new(socket: S) -> Self {
        Self {
            socket,
            max_payload_size: DEFAULT_MAX_PAYLOAD_LEN,
        }
    }

    /// Sets the largest datagram the server is willing to receive.
    ///
    /// Datagrams larger than this size are truncated by the kernel and fail to parse.
    /// This should match the payload size the server advertises in its EDNS responses.
    pub fn max_payload_size(self, max_payload_size: u16) -> Self {
        Self {
            max_payload_size,
            ..self
        }
    }
}

impl<S> Transport for Udp<S>
where
    S: DnsUdpSocket + 'static,
{
    async fn run<H: RequestHandler>(self, cx: Arc<ServerContext<H>>) -> Result<(), NetError> {
        handle_udp(self.socket, self.max_payload_size, cx).await
    }
}

async fn handle_udp<S: DnsUdpSocket>(
    socket: S,
    max_payload_size: u16,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    // create the new UdpStream, the IP address isn't relevant, and ideally goes essentially no where.
    //   the address used is acquired from the inbound queries
    let (mut stream, stream_handle) =
        UdpStream::with_bound(socket, ([127, 255, 255, 254], 0).into(), max_payload_size);

    let mut inner_join_set = JoinSet::new();
    loop {
        let Some(option) = cx.shutdown.run_until_cancelled(stream.next()).await else {
            // Graceful shutdown
            break;
        };
        let Some(message_res) = option else {
            // End of stream
            break;
        };

        let message = match message_res {
            Err(error) => {
                warn!(%error, "error receiving message on udp_socket");
                if is_unrecoverable_socket_error(&error) {
                    break;
                }
                continue;
            }
            Ok(message) => message,
        };

        let src_addr = message.addr();
        debug!("received udp request from: {}", src_addr);

        // verify that the src address is safe for responses
        if let Err(e) = sanitize_src_address(src_addr) {
            warn!(
                "address can not be responded to {src_addr}: {e}",
                src_addr = src_addr,
                e = e
            );
            continue;
        }

        let cx = cx.clone();
        let stream_handle = stream_handle.with_remote_addr(src_addr);
        inner_join_set.spawn(async move {
            cx.handle_raw_request(message, Protocol::Udp, stream_handle)
                .await;
        });

        reap_tasks(&mut inner_join_set);
    }

    if cx.shutdown.is_cancelled() {
        Ok(())
    } else {
        // TODO: let's consider capturing all the initial configuration details so that the socket could be recreated...
        Err(NetError::from("unexpected close of UDP socket"))
    }
}
