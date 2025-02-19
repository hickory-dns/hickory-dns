// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use alloc::boxed::Box;
use core::fmt::{self, Display};
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::net::SocketAddr;

use futures_util::{StreamExt, stream::Stream};
use tracing::warn;

use crate::BufDnsStreamHandle;
use crate::error::ProtoError;
use crate::runtime::RuntimeProvider;
#[cfg(feature = "tokio")]
use crate::runtime::TokioTime;
#[cfg(feature = "tokio")]
use crate::runtime::iocompat::AsyncIoTokioAsStd;
use crate::tcp::{DnsTcpStream, TcpStream};
use crate::xfer::{DnsClientStream, SerialMessage};

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
    /// Create a new TcpClientStream
    #[allow(clippy::type_complexity)]
    pub fn new<P: RuntimeProvider<Tcp = S>>(
        peer_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
        provider: P,
    ) -> (
        Pin<Box<dyn Future<Output = Result<Self, ProtoError>> + Send + 'static>>,
        BufDnsStreamHandle,
    ) {
        let (sender, outbound_messages) = BufDnsStreamHandle::new(peer_addr);
        (
            Box::pin(async move {
                let tcp = provider.connect_tcp(peer_addr, bind_addr, timeout).await?;
                Ok(Self::from_stream(TcpStream::from_stream_with_receiver(
                    tcp,
                    peer_addr,
                    outbound_messages,
                )))
            }),
            sender,
        )
    }

    /// Wraps the TcpStream in TcpClientStream
    pub fn from_stream(tcp_stream: TcpStream<S>) -> Self {
        Self { tcp_stream }
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use test_support::subscribe;

    use crate::runtime::TokioRuntimeProvider;
    use crate::tests::tcp_client_stream_test;
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
