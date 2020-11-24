// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::future::FutureExt;
use trust_dns_resolver::proto::tcp::{Connect, DnsTcpStream};
use trust_dns_resolver::proto::udp::UdpSocket;

use crate::time::AsyncStdTime;

pub struct AsyncStdUdpSocket(async_std::net::UdpSocket);

#[async_trait]
impl UdpSocket for AsyncStdUdpSocket {
    type Time = AsyncStdTime;

    async fn bind(addr: &SocketAddr) -> io::Result<Self> {
        async_std::net::UdpSocket::bind(addr)
            .await
            .map(AsyncStdUdpSocket)
    }

    fn poll_recv_from(
        &self,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        Box::pin(self.0.recv_from(buf)).poll_unpin(cx)
    }

    fn poll_send_to(
        &self,
        cx: &mut Context,
        buf: &[u8],
        target: &SocketAddr,
    ) -> Poll<io::Result<usize>> {
        Box::pin(self.0.send_to(buf, target)).poll_unpin(cx)
    }
}

pub struct AsyncStdTcpStream(async_std::net::TcpStream);

impl DnsTcpStream for AsyncStdTcpStream {
    type Time = AsyncStdTime;
}

#[async_trait]
impl Connect for AsyncStdTcpStream {
    async fn connect(addr: SocketAddr) -> io::Result<Self> {
        let stream = async_std::net::TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(AsyncStdTcpStream(stream))
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
