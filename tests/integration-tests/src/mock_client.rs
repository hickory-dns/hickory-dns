// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::error::Error;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures::stream::{once, Stream};
use futures::{future, Future};

use trust_dns_client::op::{Message, Query};
use trust_dns_client::rr::{Name, RData, Record};
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::xfer::{DnsHandle, DnsRequest, DnsResponse};

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
    Record::from_rdata(name, 86400, RData::CNAME(cname))
}

pub fn v4_record(name: Name, ip: Ipv4Addr) -> Record {
    Record::from_rdata(name, 86400, RData::A(ip))
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
    Ok(Message::new().into())
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
