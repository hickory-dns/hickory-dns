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
use crate::net::sanitize_src_address;
use crate::{
    net::{NetError, runtime::DnsUdpSocket, udp::UdpStream, xfer::Protocol},
    server::{
        ServerContext,
        request_handler::RequestHandler,
        utils::{is_unrecoverable_socket_error, reap_tasks},
    },
};

/// Builder and transport implementation for UDP.
///
/// Wraps an already-bound UDP socket and handles incoming DNS datagrams.
#[derive(Debug)]
pub struct Udp<S: DnsUdpSocket> {
    socket: S,
}

impl<S: DnsUdpSocket> Udp<S> {
    /// Constructs a new UDP transport.
    ///
    /// The `socket` must be already bound to the desired local address.
    pub fn new(socket: S) -> Self {
        Self { socket }
    }
}

impl<S> Transport for Udp<S>
where
    S: DnsUdpSocket + 'static,
{
    async fn run<H: RequestHandler>(self, cx: Arc<ServerContext<H>>) -> Result<(), NetError> {
        handle_udp(self.socket, cx).await
    }
}

async fn handle_udp<S: DnsUdpSocket>(
    socket: S,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    // create the new UdpStream, the IP address isn't relevant, and ideally goes essentially no where.
    //   the address used is acquired from the inbound queries
    let (mut stream, stream_handle) =
        UdpStream::with_bound(socket, ([127, 255, 255, 254], 0).into());

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
