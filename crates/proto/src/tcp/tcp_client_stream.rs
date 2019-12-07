// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt::{self, Display};
#[cfg(feature = "tokio-compat")]
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

#[cfg(feature = "tokio-compat")]
use async_trait::async_trait;
use futures::{Future, Stream, StreamExt, TryFutureExt};
use log::warn;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::ProtoError;
use crate::tcp::{Connect, TcpStream};
use crate::xfer::{DnsClientStream, SerialMessage};
use crate::{BufDnsStreamHandle, DnsStreamHandle};

/// Tcp client stream
///
/// Use with `trust_dns_client::client::DnsMultiplexer` impls
#[must_use = "futures do nothing unless polled"]
pub struct TcpClientStream<S> {
    tcp_stream: TcpStream<S>,
}

impl<S: Connect + 'static + Send> TcpClientStream<S> {
    /// Constructs a new TcpStream for a client to the specified SocketAddr.
    ///
    /// Defaults to a 5 second timeout
    ///
    /// # Arguments
    ///
    /// * `name_server` - the IP and Port of the DNS server to connect to
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        name_server: SocketAddr,
    ) -> (
        TcpClientConnect<S::Transport>,
        Box<dyn DnsStreamHandle + Send>,
    ) {
        Self::with_timeout(name_server, Duration::from_secs(5))
    }

    /// Constructs a new TcpStream for a client to the specified SocketAddr.
    ///
    /// # Arguments
    ///
    /// * `name_server` - the IP and Port of the DNS server to connect to
    /// * `timeout` - connection timeout
    pub fn with_timeout(
        name_server: SocketAddr,
        timeout: Duration,
    ) -> (
        TcpClientConnect<S::Transport>,
        Box<dyn DnsStreamHandle + Send>,
    ) {
        let (stream_future, sender) = TcpStream::<S>::with_timeout(name_server, timeout);

        let new_future = Box::pin(
            stream_future
                .map_ok(move |tcp_stream| TcpClientStream { tcp_stream })
                .map_err(ProtoError::from),
        );

        let sender = Box::new(BufDnsStreamHandle::new(name_server, sender));

        (TcpClientConnect(new_future), sender)
    }
}

impl<S: AsyncRead + AsyncWrite + Send> TcpClientStream<S> {
    /// Wraps the TcpStream in TcpClientStream
    pub fn from_stream(tcp_stream: TcpStream<S>) -> Self {
        TcpClientStream { tcp_stream }
    }
}

impl<S: AsyncRead + AsyncWrite + Send> Display for TcpClientStream<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(formatter, "TCP({})", self.tcp_stream.peer_addr())
    }
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> DnsClientStream for TcpClientStream<S> {
    fn name_server_addr(&self) -> SocketAddr {
        self.tcp_stream.peer_addr()
    }
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> Stream for TcpClientStream<S> {
    type Item = Result<SerialMessage, ProtoError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let message = try_ready_stream!(self.tcp_stream.poll_next_unpin(cx));

        // this is busted if the tcp connection doesn't have a peer
        let peer = self.tcp_stream.peer_addr();
        if message.addr() != peer {
            // TODO: this should be an error, right?
            warn!("{} does not match name_server: {}", message.addr(), peer)
        }

        Poll::Ready(Some(Ok(message)))
    }
}

// TODO: create unboxed future for the TCP Stream
/// A future that resolves to an TcpClientStream
pub struct TcpClientConnect<S>(
    Pin<Box<dyn Future<Output = Result<TcpClientStream<S>, ProtoError>> + Send + 'static>>,
);

impl<S> Future for TcpClientConnect<S> {
    type Output = Result<TcpClientStream<S>, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}

#[cfg(feature = "tokio-compat")]
use tokio::net::TcpStream as TokioTcpStream;

#[cfg(feature = "tokio-compat")]
#[async_trait]
impl Connect for TokioTcpStream {
    type Transport = TokioTcpStream;

    async fn connect(addr: &SocketAddr) -> io::Result<Self::Transport> {
        TokioTcpStream::connect(addr).await
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "linux"))]
    use std::net::Ipv6Addr;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::{net::TcpStream as TokioTcpStream, runtime::Runtime};

    use crate::tests::tcp_client_stream_test;
    #[test]
    // this fails on linux for some reason. It appears that a buffer somewhere is dirty
    //  and subsequent reads of a message buffer reads the wrong length. It works for 2 iterations
    //  but not 3?
    // #[cfg(not(target_os = "linux"))]
    fn test_tcp_stream_ipv4() {
        let io_loop = Runtime::new().expect("failed to create tokio runtime");
        tcp_client_stream_test::<TokioTcpStream, Runtime>(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            io_loop,
        )
    }

    #[test]
    #[cfg(not(target_os = "linux"))] // ignored until Travis-CI fixes IPv6
    fn test_tcp_stream_ipv6() {
        let io_loop = Runtime::new().expect("failed to create tokio runtime");
        tcp_client_stream_test::<TokioTcpStream, Runtime>(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            io_loop,
        )
    }
}
