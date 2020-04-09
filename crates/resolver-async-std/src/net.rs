use std::io;
use std::net::SocketAddr;
use std::pin::Pin;

use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncWrite};
use trust_dns_resolver::proto::tcp::Connect;
use trust_dns_resolver::proto::udp::UdpSocket;

pub struct AsyncStdUdpSocket(async_std::net::UdpSocket);

#[async_trait]
impl UdpSocket for AsyncStdUdpSocket {
    async fn bind(addr: &SocketAddr) -> io::Result<Self> {
        async_std::net::UdpSocket::bind(addr)
            .await
            .map(AsyncStdUdpSocket)
    }

    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from(buf).await
    }

    async fn send_to(&mut self, buf: &[u8], target: &SocketAddr) -> io::Result<usize> {
        self.send_to(buf, target).await
    }
}

pub struct AsyncStdTcpStream(async_std::net::TcpStream);

#[async_trait]
impl Connect for AsyncStdTcpStream {
    type Transport = AsyncStdTcpStream;

    async fn connect(addr: SocketAddr) -> io::Result<Self::Transport> {
        async_std::net::TcpStream::connect(addr)
            .await
            .map(AsyncStdTcpStream)
    }
}

impl AsyncWrite for AsyncStdTcpStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::result::Result<usize, std::io::Error>> {
        Pin::new(&mut self.0).poll_write(cx, bytes)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}

impl AsyncRead for AsyncStdTcpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &mut [u8],
    ) -> std::task::Poll<std::result::Result<usize, std::io::Error>> {
        Pin::new(&mut self.0).poll_read(cx, bytes)
    }
}
