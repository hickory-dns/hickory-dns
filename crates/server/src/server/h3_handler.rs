// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{net::SocketAddr, sync::Arc, task::Context, time::Duration};

use bytes::{Buf, Bytes};
use h3::server::RequestStream;
use h3_quinn::BidiStream;
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
        h3::{
            BodyStream,
            h3_server::{H3Connection, H3Server},
        },
        http::{self, Version, fetch_body},
        xfer::Protocol,
    },
    proto::rr::Record,
    zone_handler::MessageResponse,
};

pub(super) async fn handle_h3(
    socket: net::UdpSocket,
    timeout: Duration,
    server_cert_resolver: Arc<dyn ResolvesServerCert>,
    dns_hostname: Option<String>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    debug!("registered h3: {:?}", socket);
    handle_h3_with_server(
        H3Server::with_socket(socket, server_cert_resolver)?,
        timeout,
        dns_hostname,
        cx,
    )
    .await
}

pub(super) async fn handle_h3_with_server(
    mut server: H3Server,
    handshake_timeout: Duration,
    dns_hostname: Option<String>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    let dns_hostname = dns_hostname.map(|n| n.into());

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
        inner_join_set.spawn(async move {
            let handshake_future = H3Connection::new(connecting);
            let Ok(connection_result) = timeout(handshake_timeout, handshake_future).await else {
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

            // TODO: need to consider timeout of total connect...
            let result =
                h3_handler(connection, src_addr, handshake_timeout, dns_hostname, cx).await;

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
    h3_timeout: Duration,
    _dns_hostname: Option<Arc<str>>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    // TODO: we should make this configurable
    let mut max_requests = 100u32;

    // Accept all inbound requests sent over the connection.
    loop {
        let future = cx
            .shutdown
            .run_until_cancelled(timeout(h3_timeout, connection.accept()));
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
        tokio::spawn(async move {
            let mut stream = match request_resolver.resolve_request().await {
                Ok((_request, stream)) => stream,
                Err(error) => {
                    warn!(%error, "error receiving request headers");
                    return;
                }
            };

            let fetch_future = fetch_body(
                BodyStream::from(|cx: &mut Context<'_>| stream.poll_recv_data(cx)),
                None,
            );
            let Ok(request_res) = timeout(h3_timeout, fetch_future).await else {
                return; //Timeout while reading request.
            };
            let request = match request_res {
                Ok(bytes_mut) => bytes_mut.freeze(),
                Err(error) => {
                    warn!(%error, "error receiving request body");
                    return;
                }
            };

            debug!(
                %src_addr,
                bytes = request.remaining(),
                ?request,
                "Received request body"
            );

            cx.handle_request(request, src_addr, Protocol::H3, H3ResponseHandle(stream))
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

struct H3ResponseHandle(RequestStream<BidiStream<Bytes>, Bytes>);

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
        let response = http::response(Version::Http3, bytes.len())?;

        debug!("sending response: {:#?}", response);
        let stream = &mut self.0;
        stream.send_response(response).await?;
        stream.send_data(bytes).await?;
        stream.finish().await?;

        Ok(info)
    }
}
