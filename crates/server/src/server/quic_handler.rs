// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use rustls::server::ResolvesServerCert;
use tokio::{net, task::JoinSet, time::timeout};
use tracing::{debug, warn};

use super::{
    ResponseInfo, ServerContext, reap_tasks, request_handler::RequestHandler,
    response_handler::ResponseHandler, sanitize_src_address,
};
use crate::{
    net::{
        NetError,
        quic::{QuicServer, QuicStream, QuicStreams},
        xfer::Protocol,
    },
    proto::rr::Record,
    zone_handler::MessageResponse,
};

pub(super) async fn handle_quic(
    socket: net::UdpSocket,
    timeout: Duration,
    server_cert_resolver: Arc<dyn ResolvesServerCert>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    debug!(?socket, "registered quic");
    handle_quic_with_server(
        QuicServer::with_socket(socket, server_cert_resolver)?,
        timeout,
        cx,
    )
    .await
}

pub(super) async fn handle_quic_with_server(
    mut server: QuicServer,
    handshake_timeout: Duration,
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
            let Ok(streams_result) = timeout(handshake_timeout, handshake_future).await else {
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

            // TODO: need to consider timeout of total connect...
            let result = quic_handler(streams, src_addr, handshake_timeout, cx).await;

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
    quic_timeout: Duration,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    // TODO: we should make this configurable
    let mut max_requests = 100u32;

    // Accept all inbound quic streams sent over the connection.
    loop {
        let future = cx
            .shutdown
            .run_until_cancelled(timeout(quic_timeout, quic_streams.next()));
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
        tokio::spawn(async move {
            let Ok(request_res) = timeout(quic_timeout, request_stream.receive_bytes()).await
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

            debug!(
                "Received bytes {} from {src_addr} {request:?}",
                request.len()
            );

            cx.handle_request(
                request,
                src_addr,
                Protocol::Quic,
                QuicResponseHandle(request_stream),
            )
            .await;
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

struct QuicResponseHandle(QuicStream);

#[async_trait::async_trait]
impl ResponseHandler for QuicResponseHandle {
    // TODO: rethink this entire interface
    async fn send_response<'a>(
        &mut self,
        mut response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        // The id should always be 0 in DoQ
        response.metadata_mut().id = 0;
        let (info, bytes) = response.encode(Protocol::Quic)?;
        let bytes = Bytes::from(bytes);

        debug!("sending quic response: {}", bytes.len());
        let stream = &mut self.0;
        stream.send_bytes(bytes).await?;
        stream.finish().await?;

        Ok(info)
    }
}
