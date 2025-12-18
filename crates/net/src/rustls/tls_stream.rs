// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! DNS over TLS I/O stream implementation for Rustls

use core::net::SocketAddr;

use rustls::pki_types::ServerName;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::{self, time::timeout};
use tokio_rustls::TlsConnector;
use tracing::debug;

use crate::error::NetError;
use crate::runtime::iocompat::{AsyncIoStdAsTokio, AsyncIoTokioAsStd};
use crate::runtime::{DnsTcpStream, RuntimeProvider};
use crate::tcp::TcpStream;
use crate::xfer::{BufDnsStreamHandle, CONNECT_TIMEOUT, StreamReceiver};

/// Predefined type for abstracting the TlsClientStream with TokioTls
pub type TokioTlsClientStream<S> = tokio_rustls::client::TlsStream<AsyncIoStdAsTokio<S>>;

/// Predefined type for abstracting the TlsServerStream with TokioTls
pub type TokioTlsServerStream = tokio_rustls::server::TlsStream<TokioTcpStream>;

/// Predefined type for abstracting the base I/O TlsStream with TokioTls
pub type TlsStream<S> = TcpStream<S>;

/// Initializes a TlsStream with an existing tokio_tls::TlsStream.
///
/// This is intended for use with a TlsListener and Incoming connections
pub fn tls_from_stream<S: DnsTcpStream>(
    stream: S,
    peer_addr: SocketAddr,
) -> (TlsStream<S>, BufDnsStreamHandle) {
    let (message_sender, outbound_messages) = BufDnsStreamHandle::new(peer_addr);
    let stream = TcpStream::from_stream_with_receiver(stream, peer_addr, outbound_messages);
    (stream, message_sender)
}

pub(super) async fn connect_tls_stream<S: DnsTcpStream>(
    tls_connector: TlsConnector,
    stream: S,
    name_server: SocketAddr,
    server_name: ServerName<'static>,
    outbound_messages: StreamReceiver,
) -> Result<TcpStream<AsyncIoTokioAsStd<TokioTlsClientStream<S>>>, NetError> {
    let stream = AsyncIoStdAsTokio(stream);
    let s = match timeout(CONNECT_TIMEOUT, tls_connector.connect(server_name, stream)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(NetError::from(e)),
        Err(_) => {
            debug!(%name_server, "TLS connect timeout");
            return Err(NetError::Timeout);
        }
    };

    Ok(TcpStream::from_stream_with_receiver(
        AsyncIoTokioAsStd(s),
        name_server,
        outbound_messages,
    ))
}
