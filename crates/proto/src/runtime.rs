//! Abstractions to deal with different async runtimes.

use alloc::boxed::Box;
#[cfg(feature = "__quic")]
use alloc::sync::Arc;
use core::future::Future;
use core::marker::Send;
use core::pin::Pin;
use core::time::Duration;
use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
#[cfg(any(test, feature = "tokio"))]
use tokio::runtime::Runtime;
#[cfg(any(test, feature = "tokio"))]
use tokio::task::JoinHandle;

use crate::error::ProtoError;
use crate::tcp::DnsTcpStream;
use crate::udp::DnsUdpSocket;

/// Spawn a background task, if it was present
#[cfg(any(test, feature = "tokio"))]
pub fn spawn_bg<F: Future<Output = R> + Send + 'static, R: Send + 'static>(
    runtime: &Runtime,
    background: F,
) -> JoinHandle<R> {
    runtime.spawn(background)
}

#[cfg(feature = "tokio")]
#[doc(hidden)]
pub mod iocompat {
    use core::pin::Pin;
    use core::task::{Context, Poll};
    use std::io;

    use futures_io::{AsyncRead, AsyncWrite};
    use tokio::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite, ReadBuf};

    /// Conversion from `tokio::io::{AsyncRead, AsyncWrite}` to `std::io::{AsyncRead, AsyncWrite}`
    pub struct AsyncIoTokioAsStd<T: TokioAsyncRead + TokioAsyncWrite>(pub T);

    impl<T: TokioAsyncRead + TokioAsyncWrite + Unpin> Unpin for AsyncIoTokioAsStd<T> {}
    impl<R: TokioAsyncRead + TokioAsyncWrite + Unpin> AsyncRead for AsyncIoTokioAsStd<R> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut buf = ReadBuf::new(buf);
            let polled = Pin::new(&mut self.0).poll_read(cx, &mut buf);

            polled.map_ok(|_| buf.filled().len())
        }
    }

    impl<W: TokioAsyncRead + TokioAsyncWrite + Unpin> AsyncWrite for AsyncIoTokioAsStd<W> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    /// Conversion from `std::io::{AsyncRead, AsyncWrite}` to `tokio::io::{AsyncRead, AsyncWrite}`
    pub struct AsyncIoStdAsTokio<T: AsyncRead + AsyncWrite>(pub T);

    impl<T: AsyncRead + AsyncWrite + Unpin> Unpin for AsyncIoStdAsTokio<T> {}
    impl<R: AsyncRead + AsyncWrite + Unpin> TokioAsyncRead for AsyncIoStdAsTokio<R> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0)
                .poll_read(cx, buf.initialized_mut())
                .map_ok(|len| buf.advance(len))
        }
    }

    impl<W: AsyncRead + AsyncWrite + Unpin> TokioAsyncWrite for AsyncIoStdAsTokio<W> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Pin::new(&mut self.get_mut().0).poll_close(cx)
        }
    }
}

#[cfg(feature = "tokio")]
#[allow(unreachable_pub)]
mod tokio_runtime {
    use alloc::sync::Arc;
    use std::sync::Mutex;

    use futures_util::FutureExt;
    #[cfg(feature = "__quic")]
    use quinn::Runtime;
    use tokio::net::{TcpSocket, TcpStream, UdpSocket as TokioUdpSocket};
    use tokio::task::JoinSet;
    use tokio::time::timeout;

    use super::iocompat::AsyncIoTokioAsStd;
    use super::*;
    use crate::xfer::CONNECT_TIMEOUT;

    /// A handle to the Tokio runtime
    #[derive(Clone, Default)]
    pub struct TokioHandle {
        join_set: Arc<Mutex<JoinSet<Result<(), ProtoError>>>>,
    }

    impl Spawn for TokioHandle {
        fn spawn_bg<F>(&mut self, future: F)
        where
            F: Future<Output = Result<(), ProtoError>> + Send + 'static,
        {
            let mut join_set = self.join_set.lock().unwrap();
            join_set.spawn(future);
            reap_tasks(&mut join_set);
        }
    }

    /// The Tokio Runtime for async execution
    #[derive(Clone, Default)]
    pub struct TokioRuntimeProvider(TokioHandle);

    impl TokioRuntimeProvider {
        /// Create a Tokio runtime
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl RuntimeProvider for TokioRuntimeProvider {
        type Handle = TokioHandle;
        type Timer = TokioTime;
        type Udp = TokioUdpSocket;
        type Tcp = AsyncIoTokioAsStd<TcpStream>;

        fn create_handle(&self) -> Self::Handle {
            self.0.clone()
        }

        fn connect_tcp(
            &self,
            server_addr: SocketAddr,
            bind_addr: Option<SocketAddr>,
            wait_for: Option<Duration>,
        ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
            Box::pin(async move {
                let socket = match server_addr {
                    SocketAddr::V4(_) => TcpSocket::new_v4(),
                    SocketAddr::V6(_) => TcpSocket::new_v6(),
                }?;

                if let Some(bind_addr) = bind_addr {
                    socket.bind(bind_addr)?;
                }

                socket.set_nodelay(true)?;
                let future = socket.connect(server_addr);
                let wait_for = wait_for.unwrap_or(CONNECT_TIMEOUT);
                match timeout(wait_for, future).await {
                    Ok(Ok(socket)) => Ok(AsyncIoTokioAsStd(socket)),
                    Ok(Err(e)) => Err(e),
                    Err(_) => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("connection to {server_addr:?} timed out after {wait_for:?}"),
                    )),
                }
            })
        }

        fn bind_udp(
            &self,
            local_addr: SocketAddr,
            _server_addr: SocketAddr,
        ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
            Box::pin(tokio::net::UdpSocket::bind(local_addr))
        }

        #[cfg(feature = "__quic")]
        fn quic_binder(&self) -> Option<&dyn QuicSocketBinder> {
            Some(&TokioQuicSocketBinder)
        }
    }

    /// Reap finished tasks from a `JoinSet`, without awaiting or blocking.
    fn reap_tasks(join_set: &mut JoinSet<Result<(), ProtoError>>) {
        while FutureExt::now_or_never(join_set.join_next())
            .flatten()
            .is_some()
        {}
    }

    #[cfg(feature = "__quic")]
    struct TokioQuicSocketBinder;

    #[cfg(feature = "__quic")]
    impl QuicSocketBinder for TokioQuicSocketBinder {
        fn bind_quic(
            &self,
            local_addr: SocketAddr,
            _server_addr: SocketAddr,
        ) -> Result<Arc<dyn quinn::AsyncUdpSocket>, io::Error> {
            let socket = std::net::UdpSocket::bind(local_addr)?;
            quinn::TokioRuntime.wrap_udp_socket(socket)
        }
    }
}

#[cfg(feature = "tokio")]
pub use tokio_runtime::{TokioHandle, TokioRuntimeProvider};

/// RuntimeProvider defines which async runtime that handles IO and timers.
pub trait RuntimeProvider: Clone + Send + Sync + Unpin + 'static {
    /// Handle to the executor;
    type Handle: Clone + Send + Spawn + Sync + Unpin;

    /// Timer
    type Timer: Time + Send + Unpin;

    /// UdpSocket
    type Udp: DnsUdpSocket + Send;

    /// TcpStream
    type Tcp: DnsTcpStream;

    /// Create a runtime handle
    fn create_handle(&self) -> Self::Handle;

    /// Create a TCP connection with custom configuration.
    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>>;

    /// Create a UDP socket bound to `local_addr`. The returned value should **not** be connected to `server_addr`.
    /// *Notice: the future should be ready once returned at best effort. Otherwise UDP DNS may need much more retries.*
    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>>;

    /// Yields an object that knows how to bind a QUIC socket.
    //
    // Use some indirection here to avoid exposing the `quinn` crate in the public API
    // even for runtimes that might not (want to) provide QUIC support.
    fn quic_binder(&self) -> Option<&dyn QuicSocketBinder> {
        None
    }
}

/// Noop trait for when the `quinn` dependency is not available.
#[cfg(not(feature = "__quic"))]
pub trait QuicSocketBinder {}

/// Create a UDP socket for QUIC usage.
/// This trait is designed for customization.
#[cfg(feature = "__quic")]
pub trait QuicSocketBinder {
    /// Create a UDP socket for QUIC usage.
    fn bind_quic(
        &self,
        _local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Result<Arc<dyn quinn::AsyncUdpSocket>, io::Error>;
}

/// A type defines the Handle which can spawn future.
pub trait Spawn {
    /// Spawn a future in the background
    fn spawn_bg<F>(&mut self, future: F)
    where
        F: Future<Output = Result<(), ProtoError>> + Send + 'static;
}

/// Generic executor.
// This trait is created to facilitate running the tests defined in the tests mod using different types of
// executors. It's used in Fuchsia OS, please be mindful when update it.
pub trait Executor {
    /// Create the implementor itself.
    fn new() -> Self;

    /// Spawns a future object to run synchronously or asynchronously depending on the specific
    /// executor.
    fn block_on<F: Future>(&mut self, future: F) -> F::Output;
}

#[cfg(feature = "tokio")]
impl Executor for Runtime {
    fn new() -> Self {
        Self::new().expect("failed to create tokio runtime")
    }

    fn block_on<F: Future>(&mut self, future: F) -> F::Output {
        Self::block_on(self, future)
    }
}

/// Generic Time for Delay and Timeout.
// This trait is created to allow to use different types of time systems. It's used in Fuchsia OS, please be mindful when update it.
#[async_trait]
pub trait Time {
    /// Return a type that implements `Future` that will wait until the specified duration has
    /// elapsed.
    async fn delay_for(duration: Duration);

    /// Return a type that implement `Future` to complete before the specified duration has elapsed.
    async fn timeout<F: 'static + Future + Send>(
        duration: Duration,
        future: F,
    ) -> Result<F::Output, std::io::Error>;
}

/// New type which is implemented using tokio::time::{Delay, Timeout}
#[cfg(any(test, feature = "tokio"))]
#[derive(Clone, Copy, Debug)]
pub struct TokioTime;

#[cfg(any(test, feature = "tokio"))]
#[async_trait]
impl Time for TokioTime {
    async fn delay_for(duration: Duration) {
        tokio::time::sleep(duration).await
    }

    async fn timeout<F: 'static + Future + Send>(
        duration: Duration,
        future: F,
    ) -> Result<F::Output, std::io::Error> {
        tokio::time::timeout(duration, future)
            .await
            .map_err(move |_| std::io::Error::new(std::io::ErrorKind::TimedOut, "future timed out"))
    }
}
