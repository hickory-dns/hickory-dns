use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use futures::{future, Future};

use trust_dns::op::{Message, Query};
use trust_dns::rr::{Name, RData, Record, RecordType};
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::xfer::{DnsHandle, DnsRequest, DnsResponse};

#[derive(Clone)]
pub struct MockClientHandle {
    messages: Arc<Mutex<Vec<Result<DnsResponse, ProtoError>>>>,
}

impl MockClientHandle {
    /// constructs a new MockClient which returns each Message one after the other
    pub fn mock(messages: Vec<Result<DnsResponse, ProtoError>>) -> Self {
        MockClientHandle {
            messages: Arc::new(Mutex::new(messages)),
        }
    }
}

impl DnsHandle for MockClientHandle {
    type Response = Box<Future<Item = DnsResponse, Error = ProtoError> + Send>;

    fn send<R: Into<DnsRequest>>(&mut self, _: R) -> Self::Response {
        Box::new(future::result(
            self.messages.lock().unwrap().pop().unwrap_or_else(empty),
        ))
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
