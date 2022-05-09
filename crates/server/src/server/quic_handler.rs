// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{io, net::SocketAddr, sync::Arc};

use bytes::{Bytes, BytesMut};
use futures_util::lock::Mutex;
use tracing::{debug, warn};
use trust_dns_proto::{
    error::ProtoError,
    quic::{DoqErrorCode, QuicStream},
    rr::Record,
};

use crate::{
    authority::MessageResponse,
    proto::quic::QuicStreams,
    server::{
        request_handler::RequestHandler, response_handler::ResponseHandler, server_future,
        Protocol, ResponseInfo,
    },
};

pub(crate) async fn quic_handler<T>(
    handler: Arc<T>,
    mut quic_streams: QuicStreams,
    src_addr: SocketAddr,
    _dns_hostname: Arc<str>,
) -> Result<(), ProtoError>
where
    T: RequestHandler,
{
    // TODO: we should make this configurable
    let mut max_requests = 100u32;

    // Accept all inbound quic streams sent over the connection.
    while let Some(next_request) = quic_streams.next().await {
        let mut request_stream = match next_request {
            Ok(next_request) => next_request,
            Err(err) => {
                warn!("error accepting request {}: {}", src_addr, err);
                return Err(err);
            }
        };

        let request = request_stream.receive_bytes().await?;

        debug!(
            "Received bytes {} from {src_addr} {request:?}",
            request.len()
        );
        let handler = handler.clone();
        let stream = Arc::new(Mutex::new(request_stream));
        let responder = QuicResponseHandle(stream.clone());

        handle_request(request, src_addr, handler, responder).await;

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

async fn handle_request<T>(
    bytes: BytesMut,
    src_addr: SocketAddr,
    handler: Arc<T>,
    responder: QuicResponseHandle,
) where
    T: RequestHandler,
{
    server_future::handle_request(&bytes, src_addr, Protocol::Quic, handler, responder).await
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

        let mut bytes = Vec::with_capacity(512);
        let info = {
            let mut encoder = BinEncoder::new(&mut bytes);
            response.destructive_emit(&mut encoder)?
        };
        let bytes = Bytes::from(bytes);

        debug!("sending quic response: {}", bytes.len());
        let mut lock = self.0.lock().await;
        lock.send_bytes(bytes).await?;
        lock.finish().await?;

        Ok(info)
    }
}
