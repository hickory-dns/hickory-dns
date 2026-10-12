// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{net::SocketAddr, sync::Arc, task::Context, time::Duration};

use bytes::{Buf, Bytes};
use h3::server::RequestStream;
use h3_quinn::SendStream;
use rustls::server::ResolvesServerCert;
use tokio::{net, task::JoinSet};
use tracing::{debug, warn};

use super::{
    ResponseInfo, ServerContext, reap_tasks, request_handler::RequestHandler,
    response_handler::ResponseHandler, sanitize_src_address,
};
use crate::{
    net::{
        NetError,
        h3::{
            BodyStream,
            h3_server::{H3Connection, H3Server},
        },
        http::{self, Version},
        xfer::Protocol,
    },
    proto::rr::Record,
    server::optional_timeout,
    zone_handler::MessageResponse,
};

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_h3(
    socket: net::UdpSocket,
    handshake_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    server_cert_resolver: Arc<dyn ResolvesServerCert>,
    dns_hostname: Option<String>,
    http_endpoint: String,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    debug!("registered h3: {:?}", socket);
    handle_h3_with_server(
        H3Server::with_socket(socket, server_cert_resolver)?,
        handshake_timeout,
        idle_timeout,
        request_timeout,
        dns_hostname,
        http_endpoint,
        cx,
    )
    .await
}

pub(super) async fn handle_h3_with_server(
    mut server: H3Server,
    handshake_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    dns_hostname: Option<String>,
    http_endpoint: String,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    let dns_hostname = dns_hostname.map(|n| n.into());
    let http_endpoint: Arc<str> = Arc::from(http_endpoint);

    let mut inner_join_set = JoinSet::new();
    loop {
        let future = cx.shutdown.run_until_cancelled(server.accept());
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
                debug!(%error, "error accepting incoming h3 connection");
                continue;
            }
        };

        let cx = cx.clone();
        let dns_hostname = dns_hostname.clone();
        let http_endpoint = http_endpoint.clone();
        inner_join_set.spawn(async move {
            let handshake_future = H3Connection::new(connecting);
            let Ok(connection_result) = optional_timeout(handshake_timeout, handshake_future).await
            else {
                warn!("h3 timeout expired during handshake");
                return;
            };
            let connection = match connection_result {
                Ok(connection) => connection,
                Err(error) => {
                    debug!(%error, "error establishing incoming h3 connection");
                    return;
                }
            };

            debug!("starting h3 stream request from: {src_addr}");

            let result = h3_handler(
                connection,
                src_addr,
                idle_timeout,
                request_timeout,
                dns_hostname,
                http_endpoint,
                cx,
            )
            .await;

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
    idle_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    dns_hostname: Option<Arc<str>>,
    http_endpoint: Arc<str>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    // TODO: we should make this configurable
    let mut max_requests = 100u32;

    // Accept all inbound requests sent over the connection.
    loop {
        let future = cx
            .shutdown
            .run_until_cancelled(optional_timeout(idle_timeout, connection.accept()));
        let Some(timeout_result) = future.await else {
            break; // A graceful shutdown was initiated.
        };
        let Ok(accept_result) = timeout_result else {
            break; // Timeout elapsed while waiting for a request.
        };
        let request_resolver_opt = match accept_result {
            Ok(request_resolver_opt) => request_resolver_opt,
            Err(error) => {
                warn!(%src_addr, %error, "error accepting request");
                return Err(error);
            }
        };
        let Some(request_resolver) = request_resolver_opt else {
            break; // The connection is closed.
        };

        let cx = cx.clone();
        let dns_hostname = dns_hostname.clone();
        let http_endpoint = http_endpoint.clone();
        tokio::spawn(async move {
            let (request, stream) = match request_resolver.resolve_request().await {
                Ok((request, stream)) => (request, stream),
                Err(error) => {
                    warn!(%error, "error receiving request headers");
                    return;
                }
            };

            debug!("Received request: {:#?}", request);

            let (send, mut recv) = stream.split();

            let body_stream = BodyStream::from(move |cx: &mut Context<'_>| recv.poll_recv_data(cx));
            let request = request.map(|()| body_stream);
            let message_future =
                http::message_from(Version::Http3, dns_hostname, http_endpoint, request);
            let Ok(result) = optional_timeout(request_timeout, message_future).await else {
                return; // Timeout while reading request.
            };
            let body = match result {
                Ok(bytes) => bytes,
                Err(error) => {
                    warn!(%error, %src_addr, "error while handling request");
                    return;
                }
            };

            debug!(
                %src_addr,
                bytes = body.remaining(),
                ?body,
                "Received request body"
            );

            cx.handle_request(
                body.freeze(),
                src_addr,
                Protocol::H3,
                H3ResponseHandle(send),
            )
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

struct H3ResponseHandle(RequestStream<SendStream<Bytes>, Bytes>);

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
    ) -> Result<ResponseInfo, NetError> {
        let (info, bytes) = response.encode(Protocol::H3)?;
        let bytes = Bytes::from(bytes);

        let cache_max_age = crate::proto::op::Message::from_vec(&bytes)
            .ok()
            .and_then(|m| m.cache_ttl());

        let response = http::response(Version::Http3, bytes.len(), cache_max_age)?;

        debug!("sending response: {:#?}", response);
        let stream = &mut self.0;
        stream.send_response(response).await?;
        stream.send_data(bytes).await?;
        stream.finish().await?;

        Ok(info)
    }
}
