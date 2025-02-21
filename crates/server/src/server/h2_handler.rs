// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{io, net::SocketAddr, sync::Arc};

use bytes::{Bytes, BytesMut};
use futures_util::lock::Mutex;
use h2::server;
use hickory_proto::{http::Version, rr::Record};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    access::AccessControl,
    authority::MessageResponse,
    proto::h2::h2_server,
    proto::xfer::Protocol,
    server::{
        ResponseInfo, request_handler::RequestHandler, response_handler::ResponseHandler,
        server_future,
    },
};

pub(crate) async fn h2_handler<T, I>(
    access: Arc<AccessControl>,
    handler: Arc<T>,
    io: I,
    src_addr: SocketAddr,
    dns_hostname: Option<Arc<str>>,
    http_endpoint: Arc<str>,
    shutdown: CancellationToken,
) where
    T: RequestHandler,
    I: AsyncRead + AsyncWrite + Unpin,
{
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
            _ = shutdown.cancelled() => {
                // A graceful shutdown was initiated.
                return
            },
        };

        debug!("Received request: {:#?}", request);
        let dns_hostname = dns_hostname.clone();
        let http_endpoint = http_endpoint.clone();
        let handler = handler.clone();
        let access = access.clone();
        let responder = HttpsResponseHandle(Arc::new(Mutex::new(respond)));

        tokio::spawn(async move {
            match h2_server::message_from(dns_hostname, http_endpoint, request).await {
                Ok(bytes) => handle_request(bytes, src_addr, access, handler, responder).await,
                Err(err) => warn!("error while handling request from {}: {}", src_addr, err),
            };
        });

        // we'll continue handling requests from here.
    }
}

async fn handle_request<T>(
    bytes: BytesMut,
    src_addr: SocketAddr,
    access: Arc<AccessControl>,
    handler: Arc<T>,
    responder: HttpsResponseHandle,
) where
    T: RequestHandler,
{
    server_future::handle_request(
        &bytes,
        src_addr,
        Protocol::Https,
        access,
        handler,
        responder,
    )
    .await
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

        let mut bytes = Vec::with_capacity(512);
        // mut block
        let info = {
            let mut encoder = BinEncoder::new(&mut bytes);
            response.destructive_emit(&mut encoder)?
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
