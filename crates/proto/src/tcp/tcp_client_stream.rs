// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt::{self, Display};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use std::pin::Pin;
use std::task::Context;

use futures::{Future, Poll, Stream, TryFutureExt, StreamExt};
use tokio_io::{AsyncRead, AsyncWrite};

use crate::error::ProtoError;
use crate::tcp::{Connect, TcpStream};
use crate::xfer::{DnsClientStream, SerialMessage};
use crate::{BufDnsStreamHandle, DnsStreamHandle};

/// Tcp client stream
///
/// Use with `trust_dns::client::DnsMultiplexer` impls
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
    ) -> (TcpClientConnect<S::Transport>, Box<dyn DnsStreamHandle + Send>) {
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
    ) -> (TcpClientConnect<S::Transport>, Box<dyn DnsStreamHandle + Send>) {
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
pub struct TcpClientConnect<S>(Pin<Box<dyn Future<Output = Result<TcpClientStream<S>, ProtoError>> + Send + Unpin + 'static>>);

impl<S> Future for TcpClientConnect<S> {
    type Output = Result<TcpClientStream<S>, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx)
     }
}

#[cfg(feature = "tokio-compat")]
use tokio_tcp::TcpStream as TokioTcpStream;

#[cfg(feature = "tokio-compat")]
impl Connect for TokioTcpStream {
    type Transport = TokioTcpStream;
    // TODO: changet Tokio's TcpStream to return a concrete type
    type Future = impl Future<Output = io::Result<TokioTcpStream>>;
    
    fn connect(addr: &SocketAddr) -> Self::Future {
        TokioTcpStream::connect(addr)
    }
}

#[cfg(not(target_os = "linux"))]
#[cfg(test)]
use std::net::Ipv6Addr;
#[cfg(test)]
use std::net::{IpAddr, Ipv4Addr};

#[test]
// this fails on linux for some reason. It appears that a buffer somewhere is dirty
//  and subsequent reads of a message buffer reads the wrong length. It works for 2 iterations
//  but not 3?
// #[cfg(not(target_os = "linux"))]
fn test_tcp_client_stream_ipv4() {
    tcp_client_stream_test(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
}

#[test]
#[cfg(not(target_os = "linux"))] // ignored until Travis-CI fixes IPv6
fn test_tcp_client_stream_ipv6() {
    tcp_client_stream_test(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
}

#[cfg(test)]
const TEST_BYTES: &[u8; 8] = b"DEADBEEF";
#[cfg(test)]
const TEST_BYTES_LEN: usize = 8;

#[cfg(test)]
fn tcp_client_stream_test(server_addr: IpAddr) {
    use std::io::{Read, Write};
    use tokio::runtime::current_thread::Runtime;

    let succeeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let succeeded_clone = succeeded.clone();
    std::thread::Builder::new()
        .name("thread_killer".to_string())
        .spawn(move || {
            let succeeded = succeeded_clone.clone();
            for _ in 0..15 {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if succeeded.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
            }

            panic!("timeout");
        })
        .unwrap();

    // TODO: need a timeout on listen
    let server = std::net::TcpListener::bind(SocketAddr::new(server_addr, 0)).unwrap();
    let server_addr = server.local_addr().unwrap();

    let send_recv_times = 4;

    // an in and out server
    let server_handle = std::thread::Builder::new()
        .name("test_tcp_client_stream_ipv4:server".to_string())
        .spawn(move || {
            let (mut socket, _) = server.accept().expect("accept failed");

            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap(); // should receive something within 5 seconds...
            socket
                .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap(); // should receive something within 5 seconds...

            for _ in 0..send_recv_times {
                // wait for some bytes...
                let mut len_bytes = [0_u8; 2];
                socket
                    .read_exact(&mut len_bytes)
                    .expect("SERVER: receive failed");
                let length =
                    u16::from(len_bytes[0]) << 8 & 0xFF00 | u16::from(len_bytes[1]) & 0x00FF;
                assert_eq!(length as usize, TEST_BYTES_LEN);

                let mut buffer = [0_u8; TEST_BYTES_LEN];
                socket.read_exact(&mut buffer).unwrap();

                // println!("read bytes iter: {}", i);
                assert_eq!(&buffer, TEST_BYTES);

                // bounce them right back...
                socket
                    .write_all(&len_bytes)
                    .expect("SERVER: send length failed");
                socket
                    .write_all(&buffer)
                    .expect("SERVER: send buffer failed");
                // println!("wrote bytes iter: {}", i);
                std::thread::yield_now();
            }
        })
        .unwrap();

    // setup the client, which is going to run on the testing thread...
    let mut io_loop = Runtime::new().unwrap();

    // the tests should run within 5 seconds... right?
    // TODO: add timeout here, so that test never hangs...
    // let timeout = Timeout::new(Duration::from_secs(5));
    let (stream, mut sender) = TcpClientStream::<TokioTcpStream>::new(server_addr);

    let mut stream = io_loop.block_on(stream).expect("run failed to get stream");

    for _ in 0..send_recv_times {
        // test once
        sender
            .send(SerialMessage::new(TEST_BYTES.to_vec(), server_addr))
            .expect("send failed");
        let (buffer, stream_tmp) = io_loop
            .block_on(stream.into_future());
        stream = stream_tmp;
        let buffer = buffer.expect("no buffer received").expect("error recieving buffer");
        assert_eq!(buffer.bytes(), TEST_BYTES);
    }

    succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
    server_handle.join().expect("server thread failed");
}
