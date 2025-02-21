// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::future::{Future, ready};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use futures::stream::{Stream, once};
use futures::{AsyncRead, AsyncWrite, future};

use hickory_proto::ProtoError;
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::rdata::{CNAME, NS, SOA};
use hickory_proto::rr::{Name, RData, Record};
use hickory_proto::runtime::TokioTime;
use hickory_proto::runtime::{RuntimeProvider, TokioHandle};
use hickory_proto::tcp::DnsTcpStream;
use hickory_proto::udp::DnsUdpSocket;
use hickory_proto::xfer::{DnsHandle, DnsRequest, DnsResponse};
use hickory_resolver::config::{NameServerConfig, ResolverOpts};
use hickory_resolver::name_server::ConnectionProvider;

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
        _bind_addr: Option<SocketAddr>,
        _wait_for: Option<std::time::Duration>,
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
pub struct MockConnProvider<O: OnSend + Unpin> {
    pub on_send: O,
}

impl<O: OnSend + Unpin> ConnectionProvider for MockConnProvider<O> {
    type Conn = MockClientHandle<O>;
    type FutureConn = Pin<Box<dyn Send + Future<Output = Result<Self::Conn, ProtoError>>>>;
    type RuntimeProvider = MockRuntimeProvider;

    fn new_connection(
        &self,
        _config: &NameServerConfig,
        _options: &ResolverOpts,
    ) -> Result<Self::FutureConn, io::Error> {
        println!("MockConnProvider::new_connection");
        Ok(Box::pin(future::ok(MockClientHandle::mock_on_send(
            vec![],
            self.on_send.clone(),
        ))))
    }
}

#[derive(Clone)]
pub struct MockClientHandle<O: OnSend> {
    messages: Arc<Mutex<Vec<Result<DnsResponse, ProtoError>>>>,
    on_send: O,
}

impl MockClientHandle<DefaultOnSend> {
    /// constructs a new MockClient which returns each Message one after the other (messages are
    /// popped off the back of `messages`, so they are sent in reverse order).
    pub fn mock(messages: Vec<Result<DnsResponse, ProtoError>>) -> Self {
        println!("MockClientHandle::mock message count: {}", messages.len());

        MockClientHandle {
            messages: Arc::new(Mutex::new(messages)),
            on_send: DefaultOnSend,
        }
    }
}

impl<O: OnSend> MockClientHandle<O> {
    /// constructs a new MockClient which returns each Message one after the other (messages are
    /// popped off the back of `messages`, so they are sent in reverse order).
    pub fn mock_on_send(messages: Vec<Result<DnsResponse, ProtoError>>, on_send: O) -> Self {
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

impl<O: OnSend + Unpin> DnsHandle for MockClientHandle<O> {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send>>;

    fn send<R: Into<DnsRequest>>(&self, _: R) -> Self::Response {
        let mut messages = self.messages.lock().expect("failed to lock at messages");
        println!("MockClientHandle::send message count: {}", messages.len());

        Box::pin(once(self.on_send.on_send(messages.pop().unwrap_or_else(
            || error(ProtoError::from("Messages exhausted in MockClientHandle")),
        ))))
    }
}

pub fn ns_record(name: Name, nsname: Name) -> Record {
    Record::from_rdata(name, 86400, RData::NS(NS(nsname)))
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
        &self,
        response: Result<DnsResponse, E>,
    ) -> Pin<Box<dyn Future<Output = Result<DnsResponse, E>> + Send>>
    where
        E: From<ProtoError> + Send + 'static,
    {
        Box::pin(ready(response))
    }
}

#[derive(Clone)]
pub struct DefaultOnSend;

impl OnSend for DefaultOnSend {}
