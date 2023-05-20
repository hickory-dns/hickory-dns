// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::error::Error;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use futures::stream::{once, Stream};
use futures::{future, AsyncRead, AsyncWrite, Future};

use trust_dns_client::op::{Message, Query};
use trust_dns_client::rr::rdata::{CNAME, SOA};
use trust_dns_client::rr::{Name, RData, Record};
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::tcp::DnsTcpStream;
use trust_dns_proto::udp::DnsUdpSocket;
#[cfg(feature = "dns-over-quic")]
use trust_dns_proto::udp::QuicLocalAddr;
use trust_dns_proto::xfer::{DnsHandle, DnsRequest, DnsResponse};
use trust_dns_proto::TokioTime;
use trust_dns_resolver::config::{NameServerConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::name_server::{ConnectionProvider, RuntimeProvider};
use trust_dns_resolver::TokioHandle;

pub struct TcpPlaceholder;

impl AsyncRead for TcpPlaceholder {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
}

impl AsyncWrite for TcpPlaceholder {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl DnsTcpStream for TcpPlaceholder {
    type Time = TokioTime;
}

pub struct UdpPlaceholder;

#[cfg(feature = "dns-over-quic")]
impl QuicLocalAddr for UdpPlaceholder {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            9999,
        ))
    }
}

impl DnsUdpSocket for UdpPlaceholder {
    type Time = TokioTime;

    fn poll_recv_from(
        &self,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<(usize, SocketAddr)>> {
        Poll::Ready(Ok((
            buf.len(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 77)), 1),
        )))
    }

    fn poll_send_to(
        &self,
        _cx: &mut Context<'_>,
        buf: &[u8],
        _target: SocketAddr,
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
}

#[derive(Clone, Default)]
pub struct MockRuntimeProvider;

#[allow(clippy::type_complexity)]
impl RuntimeProvider for MockRuntimeProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = UdpPlaceholder;
    type Tcp = TcpPlaceholder;

    fn create_handle(&self) -> Self::Handle {
        TokioHandle::default()
    }

    fn connect_tcp(
        &self,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Tcp>>>> {
        Box::pin(async { Ok(TcpPlaceholder) })
    }

    fn bind_udp(
        &self,
        _local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>> {
        Box::pin(async { Ok(UdpPlaceholder) })
    }
}

#[derive(Clone)]
pub struct MockConnProvider<O: OnSend + Unpin, E> {
    pub on_send: O,
    pub _p: PhantomData<E>,
}

impl<O: OnSend + Unpin> ConnectionProvider for MockConnProvider<O, ResolveError> {
    type Conn = MockClientHandle<O, ResolveError>;
    type FutureConn = Pin<Box<dyn Send + Future<Output = Result<Self::Conn, ResolveError>>>>;
    type RuntimeProvider = MockRuntimeProvider;

    fn new_connection(
        &self,
        _config: &NameServerConfig,
        _options: &ResolverOpts,
    ) -> Self::FutureConn {
        println!("MockConnProvider::new_connection");
        Box::pin(future::ok(MockClientHandle::mock_on_send(
            vec![],
            self.on_send.clone(),
        )))
    }
}

#[derive(Clone)]
pub struct MockClientHandle<O: OnSend, E> {
    messages: Arc<Mutex<Vec<Result<DnsResponse, E>>>>,
    on_send: O,
}

impl<E> MockClientHandle<DefaultOnSend, E> {
    /// constructs a new MockClient which returns each Message one after the other (messages are
    /// popped off the back of `messages`, so they are sent in reverse order).
    pub fn mock(messages: Vec<Result<DnsResponse, E>>) -> Self {
        println!("MockClientHandle::mock message count: {}", messages.len());

        MockClientHandle {
            messages: Arc::new(Mutex::new(messages)),
            on_send: DefaultOnSend,
        }
    }
}

impl<O: OnSend, E> MockClientHandle<O, E> {
    /// constructs a new MockClient which returns each Message one after the other (messages are
    /// popped off the back of `messages`, so they are sent in reverse order).
    pub fn mock_on_send(messages: Vec<Result<DnsResponse, E>>, on_send: O) -> Self {
        println!(
            "MockClientHandle::mock_on_send message count: {}",
            messages.len()
        );

        MockClientHandle {
            messages: Arc::new(Mutex::new(messages)),
            on_send,
        }
    }
}

impl<O: OnSend + Unpin, E> DnsHandle for MockClientHandle<O, E>
where
    E: From<ProtoError> + Error + Clone + Send + Unpin + 'static,
{
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, E>> + Send>>;
    type Error = E;

    fn send<R: Into<DnsRequest>>(&mut self, _: R) -> Self::Response {
        let mut messages = self.messages.lock().expect("failed to lock at messages");
        println!("MockClientHandle::send message count: {}", messages.len());

        Box::pin(once(self.on_send.on_send(messages.pop().unwrap_or_else(
            || {
                error(E::from(ProtoError::from(
                    "Messages exhausted in MockClientHandle",
                )))
            },
        ))))
    }
}

pub fn cname_record(name: Name, cname: Name) -> Record {
    Record::from_rdata(name, 86400, RData::CNAME(CNAME(cname)))
}

pub fn v4_record(name: Name, ip: Ipv4Addr) -> Record {
    Record::from_rdata(name, 86400, RData::A(ip.into()))
}

pub fn soa_record(name: Name, mname: Name) -> Record {
    let soa = SOA::new(mname, Default::default(), 1, 3600, 60, 86400, 3600);
    Record::from_rdata(name, 86400, RData::SOA(soa))
}

pub fn message(
    query: Query,
    answers: Vec<Record>,
    name_servers: Vec<Record>,
    additionals: Vec<Record>,
) -> Message {
    let mut message = Message::new();
    message.add_query(query);
    message.insert_answers(answers);
    message.insert_name_servers(name_servers);
    message.insert_additionals(additionals);
    message
}

pub fn empty() -> Result<DnsResponse, ProtoError> {
    Ok(DnsResponse::from_message(Message::new()).unwrap())
}

pub fn error<E>(error: E) -> Result<DnsResponse, E> {
    Err(error)
}

pub trait OnSend: Clone + Send + Sync + 'static {
    fn on_send<E>(
        &mut self,
        response: Result<DnsResponse, E>,
    ) -> Pin<Box<dyn Future<Output = Result<DnsResponse, E>> + Send>>
    where
        E: From<ProtoError> + Send + 'static,
    {
        Box::pin(future::ready(response))
    }
}

#[derive(Clone)]
pub struct DefaultOnSend;

impl OnSend for DefaultOnSend {}
