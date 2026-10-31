// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use rustls::server::ResolvesServerCert;
use tokio::{net, task::JoinSet};
use tracing::{debug, warn};

use super::{
    ServerContext, optional_timeout, reap_tasks, request_handler::RequestHandler,
    sanitize_src_address,
};
use crate::net::{
    NetError,
    quic::{DoqErrorCode, QuicServer, QuicStreams},
    xfer::Protocol,
};

pub(super) async fn handle_quic(
    socket: net::UdpSocket,
    handshake_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    server_cert_resolver: Arc<dyn ResolvesServerCert>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    debug!(?socket, "registered quic");
    handle_quic_with_server(
        QuicServer::with_socket(socket, server_cert_resolver)?,
        handshake_timeout,
        idle_timeout,
        request_timeout,
        cx,
    )
    .await
}

pub(super) async fn handle_quic_with_server(
    mut server: QuicServer,
    handshake_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    let mut inner_join_set = JoinSet::new();
    loop {
        let future = cx.shutdown.run_until_cancelled(server.next());
        let Some(incoming_opt) = future.await else {
            break; // A graceful shutdown was initiated. Break out of the loop.
        };
        let Some(incoming) = incoming_opt else {
            break; // Connection is closed.
        };

        // If the remote address isn't validated, send a retry packet to request that the client try
        // connecting again, with address validation.
        if !incoming.remote_address_validated() {
            if let Err(error) = incoming.retry() {
                warn!(%error, "could not send retry packet");
            }
            continue;
        }

        // Verify that the source address is safe for responses.
        let src_addr = incoming.remote_address();
        if let Err(error) = sanitize_src_address(src_addr) {
            warn!(
                %error, %src_addr,
                "address can not be responded to",
            );
            continue;
        }

        let connecting = match incoming.accept() {
            Ok(connecting) => connecting,
            Err(error) => {
                debug!(%error, "error accepting incoming quic connection");
                continue;
            }
        };

        let cx = cx.clone();
        inner_join_set.spawn(async move {
            let handshake_future = QuicStreams::new(connecting);
            let Ok(streams_result) = optional_timeout(handshake_timeout, handshake_future).await
            else {
                warn!("quic timeout expired during handshake");
                return;
            };
            let streams = match streams_result {
                Ok(streams) => streams,
                Err(error) => {
                    debug!(%error, "error completing incoming quic connection");
                    return;
                }
            };

            debug!("starting quic stream request from: {src_addr}");

            let result = quic_handler(streams, src_addr, idle_timeout, request_timeout, cx).await;

            if let Err(error) = result {
                warn!(%error, %src_addr, "quic stream processing failed")
            }
        });

        reap_tasks(&mut inner_join_set);
    }

    Ok(())
}

pub(crate) async fn quic_handler(
    mut quic_streams: QuicStreams,
    src_addr: SocketAddr,
    idle_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    // TODO: we should make this configurable
    let mut max_requests = 100u32;

    // Accept all inbound quic streams sent over the connection.
    loop {
        let future = cx
            .shutdown
            .run_until_cancelled(optional_timeout(idle_timeout, quic_streams.next()));
        let Some(timeout_result) = future.await else {
            break; // A graceful shutdown was initiated.
        };
        let Ok(stream_option) = timeout_result else {
            break; // Timeout elapsed while waiting for a request.
        };
        let Some(result) = stream_option else {
            break;
        };
        let mut request_stream = match result {
            Ok(next_request) => next_request,
            Err(err) => {
                warn!("error accepting request {}: {}", src_addr, err);
                return Err(err);
            }
        };

        let cx = cx.clone();
        let connection = quic_streams.clone();
        tokio::spawn(async move {
            let Ok(request_res) =
                optional_timeout(request_timeout, request_stream.receive_bytes()).await
            else {
                return; // Timeout while reading body.
            };
            let request = match request_res {
                Ok(bytes_mut) => bytes_mut.freeze(),
                Err(error) => {
                    warn!(%error, %src_addr, "reading quic request failed");
                    return;
                }
            };

            // RFC 9250 section 4.2.1 requires the DNS Message ID to be 0
            if request.get(..2).is_some_and(|id| id != [0, 0]) {
                warn!(%src_addr, "received QUIC request with non-zero message id");
                connection.close(DoqErrorCode::ProtocolError);
                return;
            }

            debug!(
                "Received bytes {} from {src_addr} {request:?}",
                request.len()
            );

            let Some((info, reporter)) = cx.handle_request(request, src_addr, Protocol::Quic).await
            else {
                return;
            };

            let bytes = Bytes::from(info.bytes);
            debug!("sending quic response: {}", bytes.len());
            if let Err(error) = request_stream.send_bytes(bytes).await {
                warn!(%error, "failed to send response");
                return;
            }

            if let Err(error) = request_stream.finish().await {
                warn!(%error, "failed to send response");
                return;
            }

            reporter.report(&info.header);
        });

        max_requests -= 1;
        if max_requests == 0 {
            warn!("exceeded request count, shutting down quic conn: {src_addr}");
            break;
        }
        // we'll continue handling requests from here.
    }

    Ok(())
}
