// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::SocketAddr;
use std::sync::Arc;
use std::pin::Pin;

use futures::{Future, TryFutureExt};
use rustls::ClientConfig;
use tokio_tcp::TcpStream as TokioTcpStream;

use trust_dns_proto::error::ProtoError;
use trust_dns_proto::tcp::TcpClientStream;
use trust_dns_proto::xfer::BufDnsStreamHandle;

use crate::tls_stream::tls_connect;

pub type TlsClientStream = TcpClientStream<tokio_rustls::client::TlsStream<TokioTcpStream>>;

/// Creates a new TlsStream to the specified name_server
///
/// # Arguments
///
/// * `name_server` - IP and Port for the remote DNS resolver
/// * `dns_name` - The DNS name, Subject Public Key Info (SPKI) name, as associated to a certificate
pub fn tls_client_connect(
    name_server: SocketAddr,
    dns_name: String,
    client_config: Arc<ClientConfig>,
) -> (
    Pin<Box<dyn Future<Output = Result<TlsClientStream, ProtoError>> + Send + Unpin>>,
    BufDnsStreamHandle,
) {
    let (stream_future, sender) = tls_connect(name_server, dns_name, client_config);

    let new_future = Box::pin(
        stream_future
            .map_ok(TcpClientStream::from_stream)
            .map_err(ProtoError::from),
    );

    let sender = BufDnsStreamHandle::new(name_server, sender);

    (new_future, sender)
}
