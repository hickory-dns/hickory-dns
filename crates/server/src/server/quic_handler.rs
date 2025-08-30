// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{io, net::SocketAddr, sync::Arc};

use bytes::Bytes;
use futures_util::lock::Mutex;
use rustls::server::ResolvesServerCert;
use tokio::{net, task::JoinSet};
use tracing::{debug, error, warn};

use super::{
    ResponseInfo, ServerContext, reap_tasks,
    request_handler::RequestHandler,
    response_handler::{ResponseHandler, encode_fallback_servfail_response},
    sanitize_src_address,
};
use crate::{
    proto::{
        ProtoError,
        quic::{DoqErrorCode, QuicServer, QuicStream, QuicStreams},
        rr::Record,
        xfer::Protocol,
    },
    zone_handler::MessageResponse,
};

pub(super) async fn handle_quic(
    socket: net::UdpSocket,
    server_cert_resolver: Arc<dyn ResolvesServerCert>,
    dns_hostname: Option<String>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), ProtoError> {
    debug!(?socket, "registered quic");
    handle_quic_with_server(
        QuicServer::with_socket(socket, server_cert_resolver)?,
        dns_hostname,
        cx,
    )
    .await
}

pub(super) async fn handle_quic_with_server(
    mut server: QuicServer,
    dns_hostname: Option<String>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), ProtoError> {
    let dns_hostname = dns_hostname.map(|n| n.into());

    let mut inner_join_set = JoinSet::new();
    loop {
        let shutdown = cx.shutdown.clone();
        let (streams, src_addr) = tokio::select! {
            result = server.next() => match result {
                Ok(Some(c)) => c,
                Ok(None) => continue,
                Err(error) => {
                    debug!(%error, "error receiving quic connection");
                    continue;
                }
            },
            _ = shutdown.cancelled() => {
                // A graceful shutdown was initiated. Break out of the loop.
                break;
            },
        };

        // verify that the src address is safe for responses
        // TODO: we're relying the quinn library to actually validate responses before we get here, but this check is still worth doing
        if let Err(error) = sanitize_src_address(src_addr) {
            warn!(
                %error, %src_addr,
                "address can not be responded to",
            );
            continue;
        }

        let cx = cx.clone();
        let dns_hostname = dns_hostname.clone();
        inner_join_set.spawn(async move {
            debug!("starting quic stream request from: {src_addr}");

            // TODO: need to consider timeout of total connect...
            let result = quic_handler(streams, src_addr, dns_hostname, cx).await;

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
    _dns_hostname: Option<Arc<str>>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), ProtoError> {
    // TODO: we should make this configurable
    let mut max_requests = 100u32;

    // Accept all inbound quic streams sent over the connection.
    loop {
        let mut request_stream = tokio::select! {
            result = quic_streams.next() => match result {
                Some(Ok(next_request)) => next_request,
                Some(Err(err)) => {
                    warn!("error accepting request {}: {}", src_addr, err);
                    return Err(err);
                }
                None => {
                    break;
                }
            },
            _ = cx.shutdown.cancelled() => {
                // A graceful shutdown was initiated.
                break;
            },
        };

        let request = request_stream.receive_bytes().await?;

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
    ) -> io::Result<ResponseInfo> {
        use crate::proto::serialize::binary::BinEncoder;

        // The id should always be 0 in DoQ
        response.header_mut().set_id(0);

        let id = response.header().id();
        let mut bytes = Vec::with_capacity(512);
        let info = {
            let mut encoder = BinEncoder::new(&mut bytes);
            response.destructive_emit(&mut encoder).or_else(|error| {
                error!(%error, "error encoding message");
                encode_fallback_servfail_response(id, &mut bytes)
            })?
        };
        let bytes = Bytes::from(bytes);

        debug!("sending quic response: {}", bytes.len());
        let mut lock = self.0.lock().await;
        lock.send_bytes(bytes).await?;
        lock.finish().await?;

        Ok(info)
    }
}
