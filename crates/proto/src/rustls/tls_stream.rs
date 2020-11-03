// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! DNS over TLS I/O stream implementation for Rustls

use std::convert::TryInto;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use futures_util::TryFutureExt;
use rustls::ClientConfig;
use tokio;
use tokio::net::TcpStream as TokioTcpStream;
use tokio_rustls::TlsConnector;

use crate::iocompat::{AsyncIoStdAsTokio, AsyncIoTokioAsStd};
use crate::tcp::Connect;
use crate::tcp::{DnsTcpStream, TcpStream};
use crate::xfer::{BufDnsStreamHandle, StreamReceiver};

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

/// Creates a new TlsStream to the specified name_server
///
/// [RFC 7858](https://tools.ietf.org/html/rfc7858), DNS over TLS, May 2016
///
/// ```text
/// 3.2.  TLS Handshake and Authentication
///
///   Once the DNS client succeeds in connecting via TCP on the well-known
///   port for DNS over TLS, it proceeds with the TLS handshake [RFC5246],
///   following the best practices specified in [BCP195].
///
///   The client will then authenticate the server, if required.  This
///   document does not propose new ideas for authentication.  Depending on
///   the privacy profile in use (Section 4), the DNS client may choose not
///   to require authentication of the server, or it may make use of a
///   trusted Subject Public Key Info (SPKI) Fingerprint pin set.
///
///   After TLS negotiation completes, the connection will be encrypted and
///   is now protected from eavesdropping.
/// ```
///
/// # Arguments
///
/// * `name_server` - IP and Port for the remote DNS resolver
/// * `bind_addr` - IP and port to connect from
/// * `dns_name` - The DNS name,  Subject Public Key Info (SPKI) name, as associated to a certificate
#[allow(clippy::type_complexity)]
pub fn tls_connect<S: Connect>(
    name_server: SocketAddr,
    dns_name: String,
    client_config: Arc<ClientConfig>,
) -> (
    Pin<
        Box<
            dyn Future<
                    Output = Result<
                        TlsStream<AsyncIoTokioAsStd<TokioTlsClientStream<S>>>,
                        io::Error,
                    >,
                > + Send,
        >,
    >,
    BufDnsStreamHandle,
) {
    tls_connect_with_bind_addr(name_server, None, dns_name, client_config)
}

/// Creates a new TlsStream to the specified name_server connecting from a specific address.
///
/// # Arguments
///
/// * `name_server` - IP and Port for the remote DNS resolver
/// * `bind_addr` - IP and port to connect from
/// * `dns_name` - The DNS name,  Subject Public Key Info (SPKI) name, as associated to a certificate
#[allow(clippy::type_complexity)]
pub fn tls_connect_with_bind_addr<S: Connect>(
    name_server: SocketAddr,
    bind_addr: Option<SocketAddr>,
    dns_name: String,
    client_config: Arc<ClientConfig>,
) -> (
    Pin<
        Box<
            dyn Future<
                    Output = Result<
                        TlsStream<AsyncIoTokioAsStd<TokioTlsClientStream<S>>>,
                        io::Error,
                    >,
                > + Send,
        >,
    >,
    BufDnsStreamHandle,
) {
    let (message_sender, outbound_messages) = BufDnsStreamHandle::new(name_server);
    let early_data_enabled = client_config.enable_early_data;
    let tls_connector = TlsConnector::from(client_config).early_data(early_data_enabled);

    // This set of futures collapses the next tcp socket into a stream which can be used for
    //  sending and receiving tcp packets.
    let stream = Box::pin(connect_tls(
        tls_connector,
        name_server,
        bind_addr,
        dns_name,
        outbound_messages,
    ));

    (stream, message_sender)
}

async fn connect_tls<S: Connect>(
    tls_connector: TlsConnector,
    name_server: SocketAddr,
    bind_addr: Option<SocketAddr>,
    dns_name: String,
    outbound_messages: StreamReceiver,
) -> io::Result<TcpStream<AsyncIoTokioAsStd<TokioTlsClientStream<S>>>> {
    let tcp = S::connect_with_bind(name_server, bind_addr).await?;

    let dns_name = match dns_name.as_str().try_into() {
        Ok(name) => name,
        Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad dns_name")),
    };

    let s = tls_connector
        .connect(dns_name, AsyncIoStdAsTokio(tcp))
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("tls error: {}", e),
            )
        })
        .await?;

    Ok(TcpStream::from_stream_with_receiver(
        AsyncIoTokioAsStd(s),
        name_server,
        outbound_messages,
    ))
}
