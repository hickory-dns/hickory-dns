use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures::{future, Future};

use trust_dns_client::op::{Message, Query};
use trust_dns_client::rr::{Name, RData, Record};
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::xfer::{DnsHandle, DnsRequest, DnsResponse};

#[derive(Clone)]
pub struct MockClientHandle<O: OnSend> {
    messages: Arc<Mutex<Vec<Result<DnsResponse, ProtoError>>>>,
    on_send: O,
}

impl MockClientHandle<DefaultOnSend> {
    /// constructs a new MockClient which returns each Message one after the other
    pub fn mock(messages: Vec<Result<DnsResponse, ProtoError>>) -> Self {
        println!("MockClientHandle::mock message count: {}", messages.len());

        MockClientHandle {
            messages: Arc::new(Mutex::new(messages)),
            on_send: DefaultOnSend,
        }
    }
}

impl<O: OnSend> MockClientHandle<O> {
    /// constructs a new MockClient which returns each Message one after the other
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
    type Response = Pin<Box<dyn Future<Output = Result<DnsResponse, ProtoError>> + Send>>;

    fn send<R: Into<DnsRequest>>(&mut self, _: R) -> Self::Response {
        let mut messages = self.messages.lock().expect("failed to lock at messages");
        println!("MockClientHandle::send message count: {}", messages.len());

        self.on_send.on_send(
            messages.pop().unwrap_or_else(|| {
                error(ProtoError::from("Messages exhausted in MockClientHandle"))
            }),
        )
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
) -> Result<Message, ProtoError> {
    let mut message = Message::new();
    message.add_query(query);
    message.insert_answers(answers);
    message.insert_name_servers(name_servers);
    message.insert_additionals(additionals);
    Ok(message)
}

pub fn empty() -> Result<DnsResponse, ProtoError> {
    Ok(Message::new().into())
}

pub fn error(error: ProtoError) -> Result<DnsResponse, ProtoError> {
    Err(error)
}

pub trait OnSend: Clone + Send + Sync + 'static {
    fn on_send(
        &mut self,
        response: Result<DnsResponse, ProtoError>,
    ) -> Pin<Box<dyn Future<Output = Result<DnsResponse, ProtoError>> + Send>> {
        Box::pin(future::ready(response))
    }
}

#[derive(Clone)]
pub struct DefaultOnSend;

impl OnSend for DefaultOnSend {}
