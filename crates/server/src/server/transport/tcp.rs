// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{sync::Arc, time::Duration};

use futures_util::StreamExt;
use tokio::task::JoinSet;
use tracing::debug;

use super::Transport;
use crate::{
    net::{
        NetError,
        runtime::DnsTcpListener,
        tcp::{TcpListener, TcpStream},
        xfer::Protocol,
    },
    server::{
        ServerContext,
        request_handler::RequestHandler,
        timeout_stream::TimeoutStream,
        utils::{is_unrecoverable_socket_error, reap_tasks},
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
    async fn run<H: RequestHandler>(self, cx: Arc<ServerContext<H>>) -> Result<(), NetError> {
        handle_tcp(
            self.listener,
            self.stream_timeout,
            self.response_buffer_size,
            cx,
        )
        .await
    }
}

async fn handle_tcp<L: DnsTcpListener>(
    mut listener: TcpListener<L>,
    stream_timeout: Option<Duration>,
    response_buffer_size: usize,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    let mut inner_join_set = JoinSet::new();
    loop {
        let Some(result) = cx.shutdown.run_until_cancelled(listener.accept()).await else {
            // A graceful shutdown was initiated. Break out of the loop.
            break;
        };
        let accepted = match result {
            Ok(accepted) => accepted,
            Err(error) => {
                debug!(%error, "error receiving TCP tcp_stream error");
                if is_unrecoverable_socket_error(&error) {
                    break;
                }
                continue;
            }
        };

        // and spawn to the io_loop
        let cx = cx.clone();
        inner_join_set.spawn(async move {
            let src_addr = accepted.src_addr;
            debug!(%src_addr, "accepted TCP request");
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
                        debug!(%src_addr, %error, "error in TCP request stream");
                        // we're going to bail on this connection...
                        return;
                    }
                };

                // we don't spawn here to limit clients from getting too many resources
                cx.handle_raw_request(message, Protocol::Tcp, stream_handle.clone())
                    .await;
            }
        });

        reap_tasks(&mut inner_join_set);
    }

    if cx.shutdown.is_cancelled() {
        Ok(())
    } else {
        Err(NetError::from("unexpected close of socket"))
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
