// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{io, net::SocketAddr, sync::Arc};

use bytes::{Buf, Bytes};
use futures_util::lock::Mutex;
use h3::server::RequestStream;
use h3_quinn::BidiStream;
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
        h3::{
            H3Error,
            h3_server::{H3Connection, H3Server},
        },
        http::Version,
        rr::Record,
        xfer::Protocol,
    },
    zone_handler::MessageResponse,
};

pub(super) async fn handle_h3(
    socket: net::UdpSocket,
    server_cert_resolver: Arc<dyn ResolvesServerCert>,
    dns_hostname: Option<String>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), ProtoError> {
    debug!("registered h3: {:?}", socket);
    handle_h3_with_server(
        H3Server::with_socket(socket, server_cert_resolver)?,
        dns_hostname,
        cx,
    )
    .await
}

pub(super) async fn handle_h3_with_server(
    mut server: H3Server,
    dns_hostname: Option<String>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), ProtoError> {
    let dns_hostname = dns_hostname.map(|n| n.into());

    let mut inner_join_set = JoinSet::new();
    loop {
        let shutdown = cx.shutdown.clone();
        let (streams, src_addr) = tokio::select! {
            result = server.accept() => match result {
                Ok(Some(c)) => c,
                Ok(None) => continue,
                Err(error) => {
                    debug!(%error, "error receiving h3 connection");
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
            debug!("starting h3 stream request from: {src_addr}");

            // TODO: need to consider timeout of total connect...
            let result = h3_handler(streams, src_addr, dns_hostname, cx).await;

            if let Err(error) = result {
                warn!(%error, %src_addr, "h3 stream processing failed")
            }
        });

        reap_tasks(&mut inner_join_set);
    }

    Ok(())
}

pub(crate) async fn h3_handler(
    mut connection: H3Connection,
    src_addr: SocketAddr,
    _dns_hostname: Option<Arc<str>>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), ProtoError> {
    // TODO: we should make this configurable
    let mut max_requests = 100u32;

    // Accept all inbound requests sent over the connection.
    loop {
        let (_, mut stream) = tokio::select! {
            result = connection.accept() => match result {
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

        let request = match stream
            .recv_data()
            .await
            .map_err(|e| ProtoError::from(format!("h3 stream receive data failed: {e}")))?
        {
            Some(mut request) => request.copy_to_bytes(request.remaining()),
            None => continue,
        };

        debug!(
            "Received bytes {} from {src_addr} {request:?}",
            request.remaining()
        );

        let cx = cx.clone();
        let stream = Arc::new(Mutex::new(stream));
        let responder = H3ResponseHandle(stream.clone());
        tokio::spawn(async move {
            cx.handle_request(request, src_addr, Protocol::H3, responder)
                .await
        });

        max_requests -= 1;
        if max_requests == 0 {
            warn!("exceeded request count, shutting down h3 conn: {src_addr}");
            connection.shutdown().await?;
            break;
        }
        // we'll continue handling requests from here.
    }

    Ok(())
}

#[derive(Clone)]
struct H3ResponseHandle(Arc<Mutex<RequestStream<BidiStream<Bytes>, Bytes>>>);

#[async_trait::async_trait]
impl ResponseHandler for H3ResponseHandle {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> io::Result<ResponseInfo> {
        use crate::proto::http::response;
        use crate::proto::serialize::binary::BinEncoder;

        let id = response.header().id();
        let mut bytes = Vec::with_capacity(512);
        // mut block
        let info = {
            let mut encoder = BinEncoder::new(&mut bytes);
            response.destructive_emit(&mut encoder).or_else(|error| {
                error!(%error, "error encoding message");
                encode_fallback_servfail_response(id, &mut bytes)
            })?
        };
        let bytes = Bytes::from(bytes);
        let response = response::new(Version::Http3, bytes.len())?;

        debug!("sending response: {:#?}", response);
        let mut stream = self.0.lock().await;
        stream
            .send_response(response)
            .await
            .map_err(H3Error::from)?;
        stream.send_data(bytes).await.map_err(H3Error::from)?;
        stream.finish().await.map_err(H3Error::from)?;

        Ok(info)
    }
}
