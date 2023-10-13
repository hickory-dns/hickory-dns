// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use async_std::task::spawn_blocking;
use async_trait::async_trait;
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::future::FutureExt;
use hickory_resolver::proto::tcp::{Connect, DnsTcpStream};
use hickory_resolver::proto::udp::{DnsUdpSocket, QuicLocalAddr, UdpSocket};
use pin_utils::pin_mut;
use socket2::{Domain, Protocol, Socket, Type};

use crate::time::AsyncStdTime;

pub struct AsyncStdUdpSocket(async_std::net::UdpSocket);

#[async_trait]
impl DnsUdpSocket for AsyncStdUdpSocket {
    type Time = AsyncStdTime;
    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let fut = self.0.recv_from(buf);
        pin_mut!(fut);

        fut.poll_unpin(cx)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.0.recv_from(buf).await
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        let fut = self.0.send_to(buf, target);
        pin_mut!(fut);

        fut.poll_unpin(cx)
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.0.send_to(buf, target).await
    }
}

impl QuicLocalAddr for AsyncStdUdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

#[async_trait]
impl UdpSocket for AsyncStdUdpSocket {
    async fn connect(addr: SocketAddr) -> io::Result<Self> {
        let bind_addr: SocketAddr = match addr {
            SocketAddr::V4(_addr) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_addr) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        };

        Self::connect_with_bind(addr, bind_addr).await
    }

    async fn connect_with_bind(_addr: SocketAddr, bind_addr: SocketAddr) -> io::Result<Self> {
        let socket = async_std::net::UdpSocket::bind(bind_addr).await?;

        // TODO: research connect more, it appears to break receive tests on UDP
        // socket.connect(addr).await?;
        Ok(Self(socket))
    }

    async fn bind(addr: SocketAddr) -> io::Result<Self> {
        async_std::net::UdpSocket::bind(addr)
            .await
            .map(AsyncStdUdpSocket)
    }
}

pub struct AsyncStdTcpStream(async_std::net::TcpStream);

impl DnsTcpStream for AsyncStdTcpStream {
    type Time = AsyncStdTime;
}

#[async_trait]
impl Connect for AsyncStdTcpStream {
    async fn connect_with_bind(
        addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
    ) -> io::Result<Self> {
        let stream = match bind_addr {
            Some(bind_addr) => {
                spawn_blocking(move || {
                    let domain = match bind_addr {
                        SocketAddr::V4(_) => Domain::IPV4,
                        SocketAddr::V6(_) => Domain::IPV6,
                    };
                    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
                    socket.bind(&bind_addr.into())?;
                    socket.connect(&addr.into())?;
                    let std_stream: std::net::TcpStream = socket.into();
                    let stream = async_std::net::TcpStream::from(std_stream);
                    Ok::<_, io::Error>(stream)
                })
                .await?
            }
            None => async_std::net::TcpStream::connect(addr).await?,
        };
        stream.set_nodelay(true)?;
        Ok(Self(stream))
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
