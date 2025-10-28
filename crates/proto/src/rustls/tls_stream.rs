// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! DNS over TLS I/O stream implementation for Rustls

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::net::SocketAddr;
use std::io;

use futures_util::future::BoxFuture;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;

use crate::runtime::{RuntimeProvider, Time};
use crate::tcp::{DnsTcpStream, TcpStream};
use crate::xfer::{BufDnsStreamHandle, CONNECT_TIMEOUT, StreamReceiver};

/// Predefined type for abstracting the base I/O TlsStream with Rustls
pub type TlsStream<S> = TcpStream<S>;

/// Initializes a TlsStream with an existing TLS stream.
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
/// * `server_name` - The DNS name associated with a certificate
/// * `client_config` - Rustls client TLS configuration
/// * `provider` - Async runtime provider, for I/O and timers
#[allow(clippy::type_complexity)]
pub fn tls_connect<P: RuntimeProvider>(
    name_server: SocketAddr,
    server_name: ServerName<'static>,
    client_config: Arc<ClientConfig>,
    provider: P,
) -> (
    BoxFuture<'static, Result<TlsStream<P::Tls>, io::Error>>,
    BufDnsStreamHandle,
) {
    tls_connect_with_bind_addr(name_server, None, server_name, client_config, provider)
}

/// Creates a new TlsStream to the specified name_server connecting from a specific address.
///
/// # Arguments
///
/// * `name_server` - IP and Port for the remote DNS resolver
/// * `bind_addr` - IP and port to connect from
/// * `server_name` - The DNS name associated with a certificate
/// * `client_config` - Rustls client TLS configuration
/// * `provider` - Async runtime provider, for I/O and timers
#[allow(clippy::type_complexity)]
pub fn tls_connect_with_bind_addr<P: RuntimeProvider>(
    name_server: SocketAddr,
    bind_addr: Option<SocketAddr>,
    server_name: ServerName<'static>,
    client_config: Arc<ClientConfig>,
    provider: P,
) -> (
    BoxFuture<'static, Result<TlsStream<P::Tls>, io::Error>>,
    BufDnsStreamHandle,
) {
    let (message_sender, outbound_messages) = BufDnsStreamHandle::new(name_server);

    // This set of futures collapses the next tcp socket into a stream which can be used for
    //  sending and receiving tcp packets.
    let stream = Box::pin(connect_tls(
        name_server,
        bind_addr,
        server_name,
        client_config,
        outbound_messages,
        provider,
    ));

    (stream, message_sender)
}

/// Creates a new TlsStream from an existing TCP connection future.
///
/// # Arguments
///
/// * `future` - A future producing a TCP connection
/// * `name_server` - IP and Port for the remote DNS resolver
/// * `server_name` - The DNS name associated with a certificate
/// * `client_config` - Rustls client TLS configuration
/// * `provider` - Async runtime provider, for I/O and timers
#[allow(clippy::type_complexity)]
pub fn tls_connect_with_future<P, F>(
    future: F,
    name_server: SocketAddr,
    server_name: ServerName<'static>,
    client_config: Arc<ClientConfig>,
    provider: P,
) -> (
    BoxFuture<'static, Result<TlsStream<P::Tls>, io::Error>>,
    BufDnsStreamHandle,
)
where
    P: RuntimeProvider,
    F: Future<Output = io::Result<P::Tcp>> + Send + Unpin + 'static,
{
    let (message_sender, outbound_messages) = BufDnsStreamHandle::new(name_server);

    // This set of futures collapses the next tcp socket into a stream which can be used for
    //  sending and receiving tcp packets.
    let stream = Box::pin(connect_tls_with_future(
        future,
        name_server,
        server_name,
        client_config,
        outbound_messages,
        provider,
    ));

    (stream, message_sender)
}

async fn connect_tls<P: RuntimeProvider>(
    name_server: SocketAddr,
    bind_addr: Option<SocketAddr>,
    server_name: ServerName<'static>,
    client_config: Arc<ClientConfig>,
    outbound_messages: StreamReceiver,
    provider: P,
) -> io::Result<TcpStream<P::Tls>> {
    let tcp = provider.connect_tcp(name_server, bind_addr, None);
    connect_tls_with_future(
        tcp,
        name_server,
        server_name,
        client_config,
        outbound_messages,
        provider,
    )
    .await
}

async fn connect_tls_with_future<P: RuntimeProvider, F>(
    future: F,
    name_server: SocketAddr,
    server_name: ServerName<'static>,
    client_config: Arc<ClientConfig>,
    outbound_messages: StreamReceiver,
    provider: P,
) -> io::Result<TcpStream<P::Tls>>
where
    F: Future<Output = io::Result<P::Tcp>> + Send + Unpin,
{
    let stream = future.await?;
    let s = match P::Timer::timeout(
        CONNECT_TIMEOUT,
        provider.connect_tls(stream, server_name, client_config),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("tls error: {e}"),
            ));
        }
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("TLS handshake timed out after {CONNECT_TIMEOUT:?}"),
            ));
        }
    };

    Ok(TcpStream::from_stream_with_receiver(
        s,
        name_server,
        outbound_messages,
    ))
}
