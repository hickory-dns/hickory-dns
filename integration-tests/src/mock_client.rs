use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use futures::{future, Future};

use trust_dns::client::ClientHandle;
use trust_dns::error::*;
use trust_dns::op::{Message, Query};
use trust_dns::rr::{Name, Record, RData, RecordType};
use trust_dns_proto::DnsHandle;

#[derive(Clone)]
pub struct MockClientHandle {
    messages: Arc<Mutex<Vec<ClientResult<Message>>>>,
}

impl MockClientHandle {
    /// constructs a new MockClient which returns each Message one after the other
    pub fn mock(messages: Vec<ClientResult<Message>>) -> Self {
        MockClientHandle { messages: Arc::new(Mutex::new(messages)) }
    }
}

impl DnsHandle for MockClientHandle {
    type Error = ClientError;

    fn send(&mut self, _: Message) -> Box<Future<Item = Message, Error = Self::Error>> {
        Box::new(future::result(
            self.messages.lock().unwrap().pop().unwrap_or(empty()),
        ))
    }
}

impl ClientHandle for MockClientHandle {
    fn is_verifying_dnssec(&self) -> bool {
        false
    }
}

pub fn cname_record(name: Name, cname: Name) -> Record {
    Record::from_rdata(name, 86400, RecordType::CNAME, RData::CNAME(cname))
}

pub fn v4_record(name: Name, ip: Ipv4Addr) -> Record {
    Record::from_rdata(name, 86400, RecordType::A, RData::A(ip))
}

pub fn message(
    query: Query,
    answers: Vec<Record>,
    name_servers: Vec<Record>,
    additionals: Vec<Record>,
) -> ClientResult<Message> {
    let mut message = Message::new();
    message.add_query(query);
    message.insert_answers(answers);
    message.insert_name_servers(name_servers);
    message.insert_additionals(additionals);
    Ok(message)
}

pub fn empty() -> ClientResult<Message> {
    Ok(Message::new())
}

pub fn error() -> ClientResult<Message> {
    Err(ClientErrorKind::Io.into())
}
