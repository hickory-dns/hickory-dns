use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use futures::{future, Future};

use trust_dns::op::{Message, Query};
use trust_dns::rr::{Name, RData, Record, RecordType};
use trust_dns_proto::DnsHandle;
use trust_dns_proto::error::FromProtoError;

#[derive(Clone)]
pub struct MockClientHandle<E: FromProtoError> {
    messages: Arc<Mutex<Vec<Result<Message, E>>>>,
}

impl<E: FromProtoError> MockClientHandle<E> {
    /// constructs a new MockClient which returns each Message one after the other
    pub fn mock(messages: Vec<Result<Message, E>>) -> Self {
        MockClientHandle {
            messages: Arc::new(Mutex::new(messages)),
        }
    }
}

impl<E: FromProtoError + 'static> DnsHandle for MockClientHandle<E> {
    type Error = E;

    fn send(&mut self, _: Message) -> Box<Future<Item = Message, Error = Self::Error>> {
        Box::new(future::result(
            self.messages.lock().unwrap().pop().unwrap_or(empty::<E>()),
        ))
    }
}

pub fn cname_record(name: Name, cname: Name) -> Record {
    Record::from_rdata(name, 86400, RecordType::CNAME, RData::CNAME(cname))
}

pub fn v4_record(name: Name, ip: Ipv4Addr) -> Record {
    Record::from_rdata(name, 86400, RecordType::A, RData::A(ip))
}

pub fn message<E: FromProtoError>(
    query: Query,
    answers: Vec<Record>,
    name_servers: Vec<Record>,
    additionals: Vec<Record>,
) -> Result<Message, E> {
    let mut message = Message::new();
    message.add_query(query);
    message.insert_answers(answers);
    message.insert_name_servers(name_servers);
    message.insert_additionals(additionals);
    Ok(message)
}

pub fn empty<E: FromProtoError>() -> Result<Message, E> {
    Ok(Message::new())
}

pub fn error<E: FromProtoError>(error: E) -> Result<Message, E> {
    Err(error)
}
