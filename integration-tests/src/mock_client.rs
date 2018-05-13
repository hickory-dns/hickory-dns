use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use futures::{future, Future};

use trust_dns::op::{Message, Query};
use trust_dns::rr::{Name, RData, Record, RecordType};
use trust_dns_proto::error::FromProtoError;
use trust_dns_proto::xfer::{DnsHandle, DnsRequest, DnsResponse};

#[derive(Clone)]
pub struct MockClientHandle<E: FromProtoError> {
    messages: Arc<Mutex<Vec<Result<DnsResponse, E>>>>,
}

impl<E: FromProtoError> MockClientHandle<E> {
    /// constructs a new MockClient which returns each Message one after the other
    pub fn mock(messages: Vec<Result<DnsResponse, E>>) -> Self {
        MockClientHandle {
            messages: Arc::new(Mutex::new(messages)),
        }
    }
}

impl<E: FromProtoError + 'static> DnsHandle for MockClientHandle<E> {
    type Error = E;

    fn send<R: Into<DnsRequest>>(
        &mut self,
        _: R,
    ) -> Box<Future<Item = DnsResponse, Error = Self::Error> + Send> {
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

pub fn empty<E: FromProtoError>() -> Result<DnsResponse, E> {
    Ok(Message::new().into())
}

pub fn error<E: FromProtoError>(error: E) -> Result<DnsResponse, E> {
    Err(error)
}
