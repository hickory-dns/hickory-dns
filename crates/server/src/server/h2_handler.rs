// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use ::h2::server;
use bytes::Bytes;
use futures_util::lock::Mutex;
use rustls::server::ResolvesServerCert;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, warn};

use super::{
    ResponseInfo, ServerContext, default_tls_server_config, is_unrecoverable_socket_error,
    reap_tasks,
    request_handler::RequestHandler,
    response_handler::{ResponseHandler, encode_fallback_servfail_response},
    sanitize_src_address,
};
use crate::{
    proto::{ProtoError, h2, http::Version, rr::Record, xfer::Protocol},
    zone_handler::MessageResponse,
};

/// handle h2 using the default TLS server config.
pub(super) async fn handle_h2(
    listener: TcpListener,
    // TODO: need to set a timeout between requests.
    handshake_timeout: Duration,
    server_cert_resolver: Arc<dyn ResolvesServerCert>,
    dns_hostname: Option<String>,
    http_endpoint: String,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), ProtoError> {
    handle_h2_with_acceptor(
        listener,
        handshake_timeout,
        TlsAcceptor::from(Arc::new(default_tls_server_config(
            b"h2",
            server_cert_resolver,
        )?)),
        dns_hostname,
        http_endpoint,
        cx,
    )
    .await
}

/// handle h2 using a specific TlsAcceptor.
pub(super) async fn handle_h2_with_acceptor(
    listener: TcpListener,
    // TODO: need to set a timeout between requests.
    handshake_timeout: Duration,
    tls_acceptor: TlsAcceptor,
    dns_hostname: Option<String>,
    http_endpoint: String,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), ProtoError> {
    let dns_hostname: Option<Arc<str>> = dns_hostname.map(|n| n.into());
    let http_endpoint: Arc<str> = Arc::from(http_endpoint);
    debug!("registered https: {listener:?}");

    let mut inner_join_set = JoinSet::new();
    loop {
        let shutdown = cx.shutdown.clone();
        let (tcp_stream, src_addr) = tokio::select! {
            tcp_stream = listener.accept() => match tcp_stream {
                Ok((t, s)) => (t, s),
                Err(error) => {
                    debug!(%error, "error receiving HTTPS tcp_stream error");
                    if is_unrecoverable_socket_error(&error) {
                        break;
                    }
                    continue;
                },
            },
            _ = shutdown.cancelled() => {
                // A graceful shutdown was initiated. Break out of the loop.
                break;
            },
        };

        // verify that the src address is safe for responses
        if let Err(error) = sanitize_src_address(src_addr) {
            warn!(%error, %src_addr, "address can not be responded to");
            continue;
        }

        let cx = cx.clone();
        let tls_acceptor = tls_acceptor.clone();
        let dns_hostname = dns_hostname.clone();
        let http_endpoint = http_endpoint.clone();
        inner_join_set.spawn(async move {
            debug!("starting HTTPS request from: {src_addr}");

            // TODO: need to consider timeout of total connect...
            // take the created stream...
            let Ok(tls_stream) = timeout(handshake_timeout, tls_acceptor.accept(tcp_stream)).await
            else {
                warn!("https timeout expired during handshake");
                return;
            };

            let tls_stream = match tls_stream {
                Ok(tls_stream) => tls_stream,
                Err(e) => {
                    debug!("https handshake src: {src_addr} error: {e}");
                    return;
                }
            };
            debug!("accepted HTTPS request from: {src_addr}");

            h2_handler(tls_stream, src_addr, dns_hostname, http_endpoint, cx).await;
        });

        reap_tasks(&mut inner_join_set);
    }

    if cx.shutdown.is_cancelled() {
        Ok(())
    } else {
        Err(ProtoError::from("unexpected close of socket"))
    }
}

pub(crate) async fn h2_handler(
    io: impl AsyncRead + AsyncWrite + Unpin,
    src_addr: SocketAddr,
    dns_hostname: Option<Arc<str>>,
    http_endpoint: Arc<str>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) {
    let dns_hostname = dns_hostname.clone();
    let http_endpoint = http_endpoint.clone();

    // Start the HTTP/2.0 connection handshake
    let mut h2 = match server::handshake(io).await {
        Ok(h2) => h2,
        Err(err) => {
            warn!("handshake error from {}: {}", src_addr, err);
            return;
        }
    };

    // Accept all inbound HTTP/2.0 streams sent over the
    // connection.
    loop {
        let (request, respond) = tokio::select! {
            result = h2.accept() => match result {
                Some(Ok(next_request)) => next_request,
                Some(Err(err)) => {
                    warn!("error accepting request {}: {}", src_addr, err);
                        return;
                }
                None => {
                    return;
                }
            },
            _ = cx.shutdown.cancelled() => {
                // A graceful shutdown was initiated.
                return
            },
        };

        debug!("Received request: {:#?}", request);
        let cx = cx.clone();
        let dns_hostname = dns_hostname.clone();
        let http_endpoint = http_endpoint.clone();
        let responder = HttpsResponseHandle(Arc::new(Mutex::new(respond)));
        tokio::spawn(async move {
            let body = match h2::message_from(dns_hostname, http_endpoint, request).await {
                Ok(bytes) => bytes,
                Err(err) => {
                    warn!("error while handling request from {}: {}", src_addr, err);
                    return;
                }
            };

            cx.handle_request(body.freeze(), src_addr, Protocol::Https, responder)
                .await
        });

        // we'll continue handling requests from here.
    }
}

#[derive(Clone)]
struct HttpsResponseHandle(Arc<Mutex<server::SendResponse<Bytes>>>);

#[async_trait::async_trait]
impl ResponseHandler for HttpsResponseHandle {
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
        use crate::proto::h2::HttpsError;
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
        let response = response::new(Version::Http2, bytes.len())?;

        debug!("sending response: {:#?}", response);
        let mut stream = self
            .0
            .lock()
            .await
            .send_response(response, false)
            .map_err(HttpsError::from)?;
        stream.send_data(bytes, true).map_err(HttpsError::from)?;

        Ok(info)
    }
}
