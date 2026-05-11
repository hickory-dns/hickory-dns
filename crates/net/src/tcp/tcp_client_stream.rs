// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::net::SocketAddr;
use core::pin::Pin;
use core::task::{Context, Poll, ready};
use core::time::Duration;
use std::future::Future;

use futures_util::{StreamExt, stream::Stream};
use tracing::warn;

use crate::error::NetError;
use crate::proto::op::SerialMessage;
#[cfg(feature = "tokio")]
use crate::runtime::TokioTime;
#[cfg(feature = "tokio")]
use crate::runtime::iocompat::AsyncIoTokioAsStd;
use crate::runtime::{DnsTcpStream, RuntimeProvider, Spawn};
use crate::tcp::TcpStream;
use crate::xfer::{DnsClientStream, DnsExchange};
use crate::{BufDnsStreamHandle, DnsMultiplexer};

/// Tcp client stream
///
/// Use with `hickory_client::client::DnsMultiplexer` impls
#[must_use = "futures do nothing unless polled"]
pub struct TcpClientStream<S>
where
    S: DnsTcpStream,
{
    tcp_stream: TcpStream<S>,
}

impl<S: DnsTcpStream> TcpClientStream<S> {
    /// Create a new [`DnsExchange`] wrapped around a multiplexed [`TcpClientStream`]
    ///
    /// # Arguments
    ///
    /// * `remote_addr` - Address of the remote nameserver
    /// * `bind_addr` - Optional local address to bind to
    /// * `connect_timeout` - Timeout for establishing the TCP connection
    /// * `request_timeout` - Timeout for individual DNS requests
    /// * `max_active_requests` - Optional limit on concurrent in-flight requests.
    ///   If `None`, uses the default (32).
    /// * `provider` - Runtime provider for spawning background tasks
    pub async fn exchange<P: RuntimeProvider<Tcp = S>>(
        remote_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        connect_timeout: Duration,
        request_timeout: Duration,
        max_active_requests: Option<usize>,
        provider: P,
    ) -> Result<DnsExchange<P>, NetError> {
        let mut handle = provider.create_handle();
        let (future, sender) = Self::new(remote_addr, bind_addr, Some(connect_timeout), provider);

        // TODO: need config for Signer...
        let mut multiplexer =
            DnsMultiplexer::new(future.await?, sender).with_timeout(request_timeout);
        if let Some(max) = max_active_requests {
            multiplexer = multiplexer.with_max_active_requests(max);
        }
        let (exchange, bg) = DnsExchange::from_stream(multiplexer);
        handle.spawn_bg(bg);
        Ok(exchange)
    }

    /// Create a new TcpClientStream
    pub fn new<P: RuntimeProvider<Tcp = S>>(
        peer_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
        provider: P,
    ) -> (
        impl Future<Output = Result<Self, NetError>> + Send + 'static,
        BufDnsStreamHandle,
    ) {
        let (sender, outbound_messages) = BufDnsStreamHandle::new(peer_addr);
        (
            async move {
                let tcp = provider.connect_tcp(peer_addr, bind_addr, timeout).await?;
                Ok(Self::from_stream(TcpStream::from_stream_with_receiver(
                    tcp,
                    peer_addr,
                    outbound_messages,
                )))
            },
            sender,
        )
    }

    /// Wraps the TcpStream in TcpClientStream
    pub fn from_stream(tcp_stream: TcpStream<S>) -> Self {
        Self { tcp_stream }
    }
}

impl<S: DnsTcpStream> DnsClientStream for TcpClientStream<S> {
    type Time = S::Time;

    fn name_server_addr(&self) -> SocketAddr {
        self.tcp_stream.peer_addr()
    }
}

impl<S: DnsTcpStream> Stream for TcpClientStream<S> {
    type Item = Result<SerialMessage, NetError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let message = match ready!(self.tcp_stream.poll_next_unpin(cx)) {
            Some(Ok(t)) => t,
            Some(Err(e)) => return Poll::Ready(Some(Err(NetError::from(e)))),
            None => return Poll::Ready(None),
        };

        // this is busted if the tcp connection doesn't have a peer
        let peer = self.tcp_stream.peer_addr();
        if message.addr() != peer {
            // TODO: this should be an error, right?
            warn!("{} does not match name_server: {}", message.addr(), peer)
        }

        Poll::Ready(Some(Ok(message)))
    }
}

#[cfg(feature = "tokio")]
impl<T> DnsTcpStream for AsyncIoTokioAsStd<T>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + Sized + 'static,
{
    type Time = TokioTime;
}

#[cfg(test)]
#[cfg(feature = "tokio")]
mod tests {
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use test_support::subscribe;

    use crate::runtime::TokioRuntimeProvider;
    use crate::tcp::tests::tcp_client_stream_test;
    #[tokio::test]
    async fn test_tcp_stream_ipv4() {
        subscribe();
        tcp_client_stream_test(IpAddr::V4(Ipv4Addr::LOCALHOST), TokioRuntimeProvider::new()).await;
    }

    #[tokio::test]
    async fn test_tcp_stream_ipv6() {
        subscribe();
        tcp_client_stream_test(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            TokioRuntimeProvider::new(),
        )
        .await;
    }
}
