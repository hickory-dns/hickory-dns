//! async-std runtime implementation.

use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use async_std::future::timeout;
use async_trait::async_trait;
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::future::FutureExt;
use pin_utils::pin_mut;
use socket2::{Domain, Protocol, Socket, Type};

use crate::error::ProtoError;
use crate::runtime::{Executor, RuntimeProvider, Spawn, Time};
use crate::tcp::DnsTcpStream;
use crate::udp::{DnsUdpSocket, UdpSocket};

/// The async_std runtime.
///
/// The runtime provides a task scheduler, timer, and blocking
/// pool, necessary for running asynchronous tasks.
///
/// Instances of [`AsyncStdRuntimeProvider`] can be created using [`Executor::new()`]. However,
/// most users will use the `#[async_std::main]` annotation on their entry point instead.
///
/// # Shutdown
///
/// Shutting down the runtime is done by dropping the value. The current thread
/// will block until the shut down operation has completed.
///
/// * Drain any scheduled work queues.
/// * Drop any futures that have not yet completed.
/// * Drop the reactor.
///
/// Once the reactor has dropped, any outstanding I/O resources bound to
/// that reactor will no longer function. Calling any method on them will
/// result in an error.
#[derive(Clone, Copy, Default)]
pub struct AsyncStdRuntimeProvider;

impl Executor for AsyncStdRuntimeProvider {
    fn new() -> Self {
        Self {}
    }

    fn block_on<F: Future>(&mut self, future: F) -> F::Output {
        async_std::task::block_on(future)
    }
}

impl RuntimeProvider for AsyncStdRuntimeProvider {
    type Handle = AsyncStdRuntimeHandle;
    type Timer = AsyncStdTime;
    type Udp = async_std::net::UdpSocket;
    type Tcp = AsyncStdTcpStream;

    fn create_handle(&self) -> Self::Handle {
        AsyncStdRuntimeHandle {}
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        wait_for: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Tcp>>>> {
        let wait_for = wait_for.unwrap_or_else(|| Duration::from_secs(5));
        Box::pin(async move {
            let stream = match bind_addr {
                Some(bind_addr) => {
                    let domain = match bind_addr {
                        SocketAddr::V4(_) => Domain::IPV4,
                        SocketAddr::V6(_) => Domain::IPV6,
                    };

                    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
                    socket.bind(&bind_addr.into())?;

                    socket.connect_timeout(&server_addr.into(), wait_for)?;
                    let std_stream = std::net::TcpStream::from(socket);
                    async_std::net::TcpStream::from(std_stream)
                }
                None => {
                    let future = async_std::net::TcpStream::connect(server_addr);
                    match timeout(wait_for, future).await {
                        Ok(Ok(socket)) => socket,
                        Ok(Err(e)) => return Err(e),
                        Err(_) => {
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "connection to {server_addr:?} timed out after {wait_for:?}",
                            ));
                        }
                    }
                }
            };

            stream.set_nodelay(true)?;
            Ok(AsyncStdTcpStream(stream))
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>> {
        Box::pin(async_std::net::UdpSocket::bind(local_addr))
    }
}

#[async_trait]
impl DnsUdpSocket for async_std::net::UdpSocket {
    type Time = AsyncStdTime;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let fut = self.recv_from(buf);
        pin_mut!(fut);

        fut.poll_unpin(cx)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from(buf).await
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        let fut = self.send_to(buf, target);
        pin_mut!(fut);

        fut.poll_unpin(cx)
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.send_to(buf, target).await
    }
}

#[async_trait]
impl UdpSocket for async_std::net::UdpSocket {
    async fn connect(addr: SocketAddr) -> io::Result<Self> {
        let bind_addr: SocketAddr = match addr {
            SocketAddr::V4(_addr) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_addr) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        };

        Self::connect_with_bind(addr, bind_addr).await
    }

    async fn connect_with_bind(_addr: SocketAddr, bind_addr: SocketAddr) -> io::Result<Self> {
        let socket = Self::bind(bind_addr).await?;

        // TODO: research connect more, it appears to break receive tests on UDP
        // socket.connect(addr).await?;
        Ok(socket)
    }

    async fn bind(addr: SocketAddr) -> io::Result<Self> {
        Self::bind(addr).await
    }
}

/// async-std TCP stream implementation.
pub struct AsyncStdTcpStream(pub(crate) async_std::net::TcpStream);

impl DnsTcpStream for AsyncStdTcpStream {
    type Time = AsyncStdTime;
}

impl AsyncWrite for AsyncStdTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.0).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}

impl AsyncRead for AsyncStdTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.0).poll_read(cx, bytes)
    }
}

/// async-std timer implementation
#[derive(Clone, Copy)]
pub struct AsyncStdTime;

#[async_trait]
impl Time for AsyncStdTime {
    async fn delay_for(duration: Duration) {
        async_std::task::sleep(duration).await
    }

    async fn timeout<F: 'static + Future + Send>(
        duration: Duration,
        future: F,
    ) -> Result<F::Output, std::io::Error> {
        async_std::future::timeout(duration, future)
            .await
            .map_err(move |_| std::io::Error::new(std::io::ErrorKind::TimedOut, "future timed out"))
    }
}

/// async-std runtime handle.
#[derive(Clone, Copy)]
pub struct AsyncStdRuntimeHandle;

impl Spawn for AsyncStdRuntimeHandle {
    fn spawn_bg<F>(&mut self, future: F)
    where
        F: Future<Output = Result<(), ProtoError>> + Send + 'static,
    {
        let _join = async_std::task::spawn(future);
    }
}
