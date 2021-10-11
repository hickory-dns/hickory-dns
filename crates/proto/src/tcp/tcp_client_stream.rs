// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt::{self, Display};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::{stream::Stream, StreamExt, TryFutureExt};
use log::warn;

use crate::error::ProtoError;
#[cfg(feature = "tokio-runtime")]
use crate::iocompat::AsyncIoTokioAsStd;
use crate::tcp::{DnsTcpStream, TcpStream};
use crate::xfer::{DnsClientStream, SerialMessage};
use crate::BufDnsStreamHandle;
use crate::RuntimeProvider;
#[cfg(feature = "tokio-runtime")]
use crate::TokioTime;

/// Tcp client stream
///
/// Use with `trust_dns_client::client::DnsMultiplexer` impls
#[must_use = "futures do nothing unless polled"]
pub struct TcpClientStream<S>
where
    S: DnsTcpStream,
{
    tcp_stream: TcpStream<S>,
}

impl<S: DnsTcpStream> TcpClientStream<S> {
    /// Constructs a new TcpStream for a client to the specified SocketAddr.
    ///
    /// Defaults to a 5 second timeout
    ///
    /// # Arguments
    ///
    /// * `name_server` - the IP and Port of the DNS server to connect to
    /// * `runtime` - runtime responsible for creating the TCP socket
    #[allow(clippy::new_ret_no_self)]
    pub fn new<R: RuntimeProvider<TcpConnection = S> + 'static>(
        name_server: SocketAddr,
        runtime: R,
    ) -> (TcpClientConnect<S>, BufDnsStreamHandle) {
        Self::with_timeout(name_server, Duration::from_secs(5), runtime)
    }

    /// Constructs a new TcpStream for a client to the specified SocketAddr.
    ///
    /// # Arguments
    ///
    /// * `name_server` - the IP and Port of the DNS server to connect to
    /// * `timeout` - connection timeout
    /// * `runtime` - runtime for creating the TCP socket
    pub fn with_timeout<R: RuntimeProvider<TcpConnection = S> + 'static>(
        name_server: SocketAddr,
        timeout: Duration,
        runtime: R,
    ) -> (TcpClientConnect<S>, BufDnsStreamHandle) {
        let (stream_future, sender) = TcpStream::<S>::with_timeout(name_server, timeout, runtime);

        let new_future = Box::pin(
            stream_future
                .map_ok(move |tcp_stream| TcpClientStream { tcp_stream })
                .map_err(ProtoError::from),
        );

        (TcpClientConnect(new_future), sender)
    }
}

impl<S: DnsTcpStream> TcpClientStream<S> {
    /// Wraps the TcpStream in TcpClientStream
    pub fn from_stream(tcp_stream: TcpStream<S>) -> Self {
        TcpClientStream { tcp_stream }
    }
}

impl<S: DnsTcpStream> Display for TcpClientStream<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(formatter, "TCP({})", self.tcp_stream.peer_addr())
    }
}

impl<S: DnsTcpStream> DnsClientStream for TcpClientStream<S> {
    type Time = S::Time;

    fn name_server_addr(&self) -> SocketAddr {
        self.tcp_stream.peer_addr()
    }
}

impl<S: DnsTcpStream> Stream for TcpClientStream<S> {
    type Item = Result<SerialMessage, ProtoError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
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
pub struct TcpClientConnect<S: DnsTcpStream>(
    Pin<Box<dyn Future<Output = Result<TcpClientStream<S>, ProtoError>> + Send + 'static>>,
);

impl<S: DnsTcpStream> Future for TcpClientConnect<S> {
    type Output = Result<TcpClientStream<S>, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}

#[cfg(feature = "tokio-runtime")]
impl<T> DnsTcpStream for AsyncIoTokioAsStd<T>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + Sized + 'static,
{
    type Time = TokioTime;
}

#[cfg(test)]
#[cfg(feature = "tokio-runtime")]
mod tests {
    #[cfg(not(target_os = "linux"))]
    use std::net::Ipv6Addr;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::runtime::Runtime;

    use crate::tests::tcp_client_stream_test;
    use crate::{TokioRuntime, TokioTime};
    #[test]
    fn test_tcp_stream_ipv4() {
        let io_loop = Runtime::new().expect("failed to create tokio runtime");
        tcp_client_stream_test::<TokioRuntime, Runtime, TokioTime>(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            io_loop,
            TokioRuntime,
        )
    }

    #[test]
    #[cfg(not(target_os = "linux"))] // ignored until Travis-CI fixes IPv6
    fn test_tcp_stream_ipv6() {
        let io_loop = Runtime::new().expect("failed to create tokio runtime");
        tcp_client_stream_test::<TokioRuntime, Runtime, TokioTime>(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            io_loop,
            TokioRuntime,
        )
    }
}
