// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{sync::Arc, time::Duration};

use futures_util::StreamExt;
use tokio::task::JoinSet;
use tracing::{debug, warn};

use super::Transport;
use crate::{
    net::{
        NetError,
        runtime::{Accepted, DnsTcpListener},
        tcp::{TcpListener, TcpStream},
        xfer::Protocol,
    },
    server::{
        ServerContext, request_handler::RequestHandler, timeout_stream::TimeoutStream,
        utils::is_unrecoverable_socket_error,
    },
};

/// Builder and transport implementation for TCP.
///
/// Wraps an already-bound TCP listener and handles incoming connections.
#[derive(Debug)]
pub struct Tcp<L: DnsTcpListener> {
    listener: TcpListener<L>,
    stream_timeout: Option<Duration>,
    response_buffer_size: usize,
}

impl<L: DnsTcpListener> Tcp<L> {
    /// Constructs a new TCP transport.
    ///
    /// The `listener` must be already bound to the desired local address.
    /// Default `stream_timeout` is `None` (no timeout).
    pub fn new(listener: L, response_buffer_size: usize) -> Self {
        Self {
            listener: TcpListener::new(listener),
            stream_timeout: None,
            response_buffer_size,
        }
    }

    /// Sets the timeout duration for inactive streams.
    ///
    /// Use [`Self::maybe_stream_timeout`] to disable the stream timeout.
    pub fn stream_timeout(self, stream_timeout: Duration) -> Self {
        self.maybe_stream_timeout(Some(stream_timeout))
    }

    /// Sets the stream timeout; pass `None` to disable it.
    pub fn maybe_stream_timeout(self, stream_timeout: Option<Duration>) -> Self {
        Self {
            stream_timeout,
            ..self
        }
    }
}

impl<L: DnsTcpListener> Transport for Tcp<L> {
    async fn accept<H: RequestHandler>(
        &mut self,
        cx: Arc<ServerContext<H>>,
        tasks: &mut JoinSet<()>,
    ) -> Result<bool, NetError> {
        let accepted = match self.listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                debug!(%error, protocol = %Protocol::Tcp, "error receiving transport input");
                return Ok(!is_unrecoverable_socket_error(&error));
            }
        };

        // and spawn to the io_loop
        let stream_timeout = self.stream_timeout;
        let response_buffer_size = self.response_buffer_size;
        tasks.spawn(async move {
            let src_addr = accepted.src_addr;
            debug!(%src_addr, protocol = %Protocol::Tcp, "starting request processing");

            let result = Self::handle(accepted, stream_timeout, response_buffer_size, cx).await;

            if let Err(error) = result {
                warn!(%src_addr, %error, protocol = %Protocol::Tcp, "request processing failed");
            }
        });

        Ok(true)
    }
}

impl<L: DnsTcpListener> Tcp<L> {
    async fn handle(
        accepted: Accepted<L::Stream>,
        stream_timeout: Option<Duration>,
        response_buffer_size: usize,
        cx: Arc<ServerContext<impl RequestHandler>>,
    ) -> Result<(), NetError> {
        let src_addr = accepted.src_addr;
        // take the created stream...
        let (buf_stream, stream_handle) = TcpStream::from_stream_with_buffer_size(
            accepted.connection,
            src_addr,
            response_buffer_size,
        );
        let mut timeout_stream = TimeoutStream::new(buf_stream, stream_timeout);

        while let Some(message) = timeout_stream.next().await {
            let message = match message {
                Ok(message) => message,
                Err(error) => {
                    // we're going to bail on this connection...
                    return Err(error.into());
                }
            };

            // we don't spawn here to limit clients from getting too many resources
            cx.handle_raw_request(message, Protocol::Tcp, stream_handle.clone())
                .await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::net::TcpListener;

    use super::Tcp;

    #[tokio::test]
    async fn test_tcp_builder_configuration() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

        let tcp = Tcp::new(listener, 64).stream_timeout(Duration::from_secs(10));

        assert_eq!(tcp.stream_timeout, Some(Duration::from_secs(10)));
        assert_eq!(tcp.response_buffer_size, 64);
    }
}
