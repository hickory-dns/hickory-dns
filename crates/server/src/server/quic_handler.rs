// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use futures_util::lock::Mutex;
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
        quic::{DoqErrorCode, QuicServer, QuicStream, QuicStreams},
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
        let future = cx
            .shutdown
            .run_until_cancelled(timeout(handshake_timeout, server.next()));
        let Some(timeout_result) = future.await else {
            break; // A graceful shutdown was initiated. Break out of the loop.
        };
        let Ok(accept_result) = timeout_result else {
            warn!("quic timeout expired during handshake");
            continue;
        };
        let (streams, src_addr) = match accept_result {
            Ok(Some((streams, src_addr))) => (streams, src_addr),
            Ok(None) => break, // Connection is closed.
            Err(error) => {
                debug!(%error, "error receiving quic connection");
                continue;
            }
        };

        // Verify that the source address is safe for responses. We're also relying on the quinn
        // library to actually validate responses before we get here, but this check is still worth
        // doing.
        if let Err(error) = sanitize_src_address(src_addr) {
            warn!(
                %error, %src_addr,
                "address can not be responded to",
            );
            continue;
        }

        let cx = cx.clone();
        inner_join_set.spawn(async move {
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

        let Ok(request_res) = timeout(quic_timeout, request_stream.receive_bytes()).await else {
            break; // Timeout while reading body.
        };
        let request = request_res?;

        debug!(
            "Received bytes {} from {src_addr} {request:?}",
            request.len()
        );

        let stream = Arc::new(Mutex::new(request_stream));
        let responder = QuicResponseHandle(stream.clone());

        cx.handle_request(request.freeze(), src_addr, Protocol::Quic, responder)
            .await;

        max_requests -= 1;
        if max_requests == 0 {
            warn!("exceeded request count, shutting down quic conn: {src_addr}");
            // DOQ_NO_ERROR (0x0): No error. This is used when the connection or stream needs to be closed, but there is no error to signal.
            stream.lock().await.stop(DoqErrorCode::NoError)?;
            break;
        }
        // we'll continue handling requests from here.
    }

    Ok(())
}

#[derive(Clone)]
struct QuicResponseHandle(Arc<Mutex<QuicStream>>);

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
        let mut lock = self.0.lock().await;
        lock.send_bytes(bytes).await?;
        lock.finish().await?;

        Ok(info)
    }
}
