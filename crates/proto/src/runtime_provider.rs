//! Runtime abstraction component for DNS clients
use crate::{error::ProtoError, tcp::DnsTcpStream, udp::UdpSocket, Time};
use std::{future::Future, io, net::SocketAddr, pin::Pin};

/// RuntimeProvider defines which async runtime that handles IO and timers.
#[async_trait::async_trait]
pub trait RuntimeProvider: Clone + 'static + Send + Sync + Unpin {
    /// Time implementation used for this type
    type Time: Time + Unpin + Send;
    /// Type of socket that would be bound by the trait implementation. E.g. for tokio, it would be
    /// `tokio::net::UdpSocket`.
    type UdpSocket: UdpSocket + Send + 'static;

    /// A succesfully established TCP connection.
    type TcpConnection: DnsTcpStream;

    /// Bind an UDP socket to the given socket address.
    fn bind_udp(
        &self,
        addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::UdpSocket>> + Send>>;

    /// Create a socket and connect to the specified socket address.
    fn connect_tcp(
        &self,
        addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::TcpConnection>> + Send>>;

    /// Spawn a future on the given runtime.
    fn spawn_bg<F>(&self, future: F)
    where
        F: Future<Output = Result<(), ProtoError>> + Send + 'static;
}

#[cfg(feature = "tokio-runtime")]
pub use tokio_runtime::TokioRuntime;

#[cfg(feature = "tokio-runtime")]
mod tokio_runtime {
    use super::*;
    use crate::iocompat::AsyncIoTokioAsStd;

    /// An implementation of a runtime provider using the tokio runtime.
    #[derive(Clone, Default, Copy)]
    pub struct TokioRuntime;

    impl RuntimeProvider for TokioRuntime {
        type Time = crate::TokioTime;
        type UdpSocket = tokio::net::UdpSocket;
        type TcpConnection = AsyncIoTokioAsStd<tokio::net::TcpStream>;

        #[inline(always)]
        fn bind_udp(
            &self,
            addr: std::net::SocketAddr,
        ) -> Pin<Box<dyn Future<Output = io::Result<Self::UdpSocket>> + Send>> {
            Box::pin(async move { tokio::net::UdpSocket::bind(addr).await })
        }

        fn connect_tcp(
            &self,
            addr: std::net::SocketAddr,
        ) -> Pin<Box<dyn Future<Output = io::Result<Self::TcpConnection>> + Send>> {
            Box::pin(async move {
                tokio::net::TcpStream::connect(addr)
                    .await
                    .map(AsyncIoTokioAsStd)
            })
        }

        fn spawn_bg<F>(&self, future: F)
        where
            F: Future<Output = Result<(), ProtoError>> + Send + 'static,
        {
            let _join = tokio::spawn(future);
        }
    }
}
