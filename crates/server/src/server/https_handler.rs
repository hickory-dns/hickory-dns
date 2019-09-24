// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use futures::{Future, Stream};
use h2::server;
use proto::serialize::binary::BinDecodable;
use tokio_io::{AsyncRead, AsyncWrite};
use trust_dns_https::https_server;

use authority::MessageResponse;
use server::request_handler::RequestHandler;
use server::response_handler::ResponseHandler;
use server::server_future;

pub fn h2_handler<T, I>(
    handler: Arc<Mutex<T>>,
    io: I,
    src_addr: SocketAddr,
    dns_hostname: Arc<String>,
) -> impl Future<Output = Result<(), ()>>
where
    T: RequestHandler,
    I: AsyncRead + AsyncWrite,
{
    // Start the HTTP/2.0 connection handshake
    server::handshake(io)
        .map_err(|e| warn!("h2 handshake error: {}", e))
        .and_then(move |h2| {
            let dns_hostname = dns_hostname.clone();
            // Accept all inbound HTTP/2.0 streams sent over the
            // connection.
            h2.map_err(|e| warn!("h2 failed to receive message: {}", e))
                .for_each(move |(request, respond)| {
                    debug!("Received request: {:#?}", request);
                    let dns_hostname = dns_hostname.clone();
                    let handler = handler.clone();
                    let responder = HttpsResponseHandle(Arc::new(Mutex::new(respond)));

                    https_server::message_from(dns_hostname, request)
                        .map_err(|e| warn!("h2 failed to receive message: {}", e))
                        .and_then(|bytes| {
                            BinDecodable::from_bytes(&bytes)
                                .map_err(|e| warn!("could not decode message: {}", e))
                        })
                        .and_then(move |message| {
                            debug!("received message: {:?}", message);

                            server_future::handle_request(
                                message,
                                src_addr,
                                handler.clone(),
                                responder,
                            )
                        })
                })
        })
        .map_err(|_| warn!("error in h2 handler"))
}

#[derive(Clone)]
struct HttpsResponseHandle(Arc<Mutex<::h2::server::SendResponse<::bytes::Bytes>>>);

impl ResponseHandler for HttpsResponseHandle {
    fn send_response(&self, response: MessageResponse) -> io::Result<()> {
        use bytes::Bytes;

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
