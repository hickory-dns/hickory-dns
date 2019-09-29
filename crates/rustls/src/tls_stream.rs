// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::pin::Pin;

use futures::channel::mpsc::unbounded;
use futures::{future, Future, TryFutureExt};
use rustls::ClientConfig;
use tokio_io;
use tokio_rustls::TlsConnector;
use tokio_tcp::TcpStream as TokioTcpStream;
use webpki::{DNSName, DNSNameRef};

use trust_dns_proto::tcp::TcpStream;
use trust_dns_proto::xfer::BufStreamHandle;

pub type TokioTlsClientStream = tokio_rustls::client::TlsStream<TokioTcpStream>;
pub type TokioTlsServerStream = tokio_rustls::server::TlsStream<TokioTcpStream>;

pub type TlsStream<S> = TcpStream<S>;

/// Initializes a TlsStream with an existing tokio_tls::TlsStream.
///
/// This is intended for use with a TlsListener and Incoming connections
pub fn tls_from_stream<S: tokio_io::AsyncRead + tokio_io::AsyncWrite>(stream: S, peer_addr: SocketAddr) -> (TlsStream<S>, BufStreamHandle) {
    let (message_sender, outbound_messages) = unbounded();
    let message_sender = BufStreamHandle::new(message_sender);

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
/// * `dns_name` - The DNS name,  Subject Public Key Info (SPKI) name, as associated to a certificate
pub fn tls_connect(
    name_server: SocketAddr,
    dns_name: String,
    client_config: Arc<ClientConfig>,
) -> (
    Pin<Box<dyn Future<Output = Result<TlsStream<TokioTlsClientStream>, io::Error>> + Send + Unpin>>,
    BufStreamHandle,
) {
    let (message_sender, outbound_messages) = unbounded();
    let message_sender = BufStreamHandle::new(message_sender);

    let tls_connector = TlsConnector::from(client_config);
    let tcp = TokioTcpStream::connect(&name_server);

    // This set of futures collapses the next tcp socket into a stream which can be used for
    //  sending and receiving tcp packets.
    let stream = Box::pin(
        tcp.and_then(move |tcp_stream| {
            let dns_name = DNSNameRef::try_from_ascii_str(&dns_name).map(DNSName::from);

            future::ready(
                dns_name
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad dns_name")))
                .and_then(move |dns_name| {
                    tls_connector
                        .connect(dns_name.as_ref(), tcp_stream)
                        .map_ok(move |s| {
                            TcpStream::from_stream_with_receiver(s, name_server, outbound_messages)
                        })
                        .map_err(|e| {
                            io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                format!("tls error: {}", e),
                            )
                        })
                })
        })
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("tls error: {}", e),
            )
        }),
    );

    (stream, message_sender)
}
