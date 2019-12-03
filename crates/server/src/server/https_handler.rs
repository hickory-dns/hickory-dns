// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::{Bytes, BytesMut};
use h2::server;
use proto::serialize::binary::BinDecodable;
use tokio::io::{AsyncRead, AsyncWrite};
use trust_dns_https::https_server;

use crate::authority::{MessageRequest, MessageResponse};
use crate::server::request_handler::RequestHandler;
use crate::server::response_handler::ResponseHandler;
use crate::server::server_future;

pub async fn h2_handler<T, I>(
    handler: Arc<Mutex<T>>,
    io: I,
    src_addr: SocketAddr,
    dns_hostname: Arc<String>,
) where
    T: RequestHandler,
    I: AsyncRead + AsyncWrite + Unpin,
{
    let dns_hostname = dns_hostname.clone();

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
    while let Some(next_request) = h2.accept().await {
        let (request, respond) = match next_request {
            Ok(next_request) => next_request,
            Err(err) => {
                warn!("error accepting request {}: {}", src_addr, err);
                return;
            }
        };

        debug!("Received request: {:#?}", request);
        let dns_hostname = dns_hostname.clone();
        let handler = handler.clone();
        let responder = HttpsResponseHandle(Arc::new(Mutex::new(respond)));

        match https_server::message_from(dns_hostname, request).await {
            Ok(bytes) => handle_request(bytes, src_addr, handler, responder).await,
            Err(err) => warn!("error while handling request from {}: {}", src_addr, err),
        };

        // we'll continue handling requests from here.
    }
}

async fn handle_request<T>(
    bytes: BytesMut,
    src_addr: SocketAddr,
    handler: Arc<Mutex<T>>,
    responder: HttpsResponseHandle,
) where
    T: RequestHandler,
{
    let message: MessageRequest = match BinDecodable::from_bytes(&bytes) {
        Ok(message) => message,
        Err(e) => {
            warn!("could not decode message: {}", e);
            return;
        }
    };

    debug!("received message: {:?}", message);

    server_future::handle_request(message, src_addr, handler, responder).await
}

#[derive(Clone)]
struct HttpsResponseHandle(Arc<Mutex<::h2::server::SendResponse<Bytes>>>);

impl ResponseHandler for HttpsResponseHandle {
    fn send_response(&self, response: MessageResponse) -> io::Result<()> {
        use proto::serialize::binary::BinEncoder;
        use trust_dns_https::response;
        use trust_dns_https::HttpsError;

        let mut bytes = Vec::with_capacity(512);
        // mut block
        {
            let mut encoder = BinEncoder::new(&mut bytes);
            response.destructive_emit(&mut encoder)?;
        };
        let bytes = Bytes::from(bytes);
        let response = response::new(bytes.len())?;

        debug!("sending response: {:#?}", response);
        let mut stream = self
            .0
            .lock()
            .expect("https poisoned")
            .send_response(response, false)
            .map_err(HttpsError::from)?;
        stream.send_data(bytes, true).map_err(HttpsError::from)?;

        Ok(())
    }
}
