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
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    access::AccessControl,
    authority::MessageResponse,
    server::{
        ResponseInfo, request_handler::RequestHandler, response_handler::ResponseHandler,
        server_future,
    },
};
use hickory_proto::{
    ProtoError,
    h3::{H3Error, h3_server::H3Connection},
    http::Version,
    rr::Record,
    xfer::Protocol,
};

pub(crate) async fn h3_handler<T>(
    access: Arc<AccessControl>,
    handler: Arc<T>,
    mut connection: H3Connection,
    src_addr: SocketAddr,
    _dns_hostname: Option<Arc<str>>,
    shutdown: CancellationToken,
) -> Result<(), ProtoError>
where
    T: RequestHandler,
{
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
            _ = shutdown.cancelled() => {
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
        let handler = handler.clone();
        let access = access.clone();
        let stream = Arc::new(Mutex::new(stream));
        let responder = H3ResponseHandle(stream.clone());

        tokio::spawn(handle_request(
            request, src_addr, access, handler, responder,
        ));

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

async fn handle_request<T>(
    bytes: Bytes,
    src_addr: SocketAddr,
    access: Arc<AccessControl>,
    handler: Arc<T>,
    responder: H3ResponseHandle,
) where
    T: RequestHandler,
{
    server_future::handle_request(&bytes, src_addr, Protocol::H3, access, handler, responder).await
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

        let mut bytes = Vec::with_capacity(512);
        // mut block
        let info = {
            let mut encoder = BinEncoder::new(&mut bytes);
            response.destructive_emit(&mut encoder)?
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
