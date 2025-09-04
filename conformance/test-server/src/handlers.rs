use crate::Transport;
use anyhow::{Context, Result};
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{RData, Record, RecordType, domain::Name, rdata},
};
use std::sync::atomic::{AtomicU8, Ordering};

/// This handler generates a valid A-record response to any query
pub(crate) fn base_handler(bytes: &[u8], _transport: Transport) -> Result<Option<Vec<u8>>> {
    let mut msg = Message::from_vec(bytes)?.to_response();
    let name = msg.queries()[0].name().clone();

    msg.set_recursion_desired(false)
        .add_answer(Record::from_rdata(
            name,
            1,
            RData::A(rdata::A([192, 0, 2, 1].into())),
        ))
        .to_vec()
        .map(Some)
        .with_context(|| "base handler: could not serialize Message")
}

/// This handler responds to any messages with an incorrect transaction (query) id.
pub(crate) fn bad_txid_handler(bytes: &[u8], _transport: Transport) -> Result<Option<Vec<u8>>> {
    let mut msg = Message::from_vec(bytes)?.to_response();
    let name = msg.queries()[0].name().clone();

    msg.set_id(if msg.id() == 65535 { 0 } else { msg.id() + 1 })
        .set_recursion_desired(false)
        .set_authoritative(true)
        .add_answer(Record::from_rdata(
            name,
            1,
            RData::A(rdata::A([192, 0, 2, 1].into())),
        ))
        .to_vec()
        .map(Some)
        .with_context(|| "bad txid handler: could not serialize Message")
}

/// This handler responds to any messages with an empty message (no response records)
pub(crate) fn empty_response_handler(
    bytes: &[u8],
    _transport: Transport,
) -> Result<Option<Vec<u8>>> {
    Message::from_vec(bytes)?
        .to_response()
        .to_vec()
        .map(Some)
        .with_context(|| "empty response handler: could not serialize Message")
}

/// This handler responds to UDP requests with the truncation bit set.  If the test server is
/// configured to listen via TCP and a request is received over a TCP channel, the truncation bit
/// is not set.
pub(crate) fn truncated_response_handler(
    bytes: &[u8],
    transport: Transport,
) -> Result<Option<Vec<u8>>> {
    let mut msg = Message::from_vec(bytes)?.to_response();
    let name = msg.queries()[0].name().clone();

    if name != Name::from_ascii("example.testing.").unwrap()
        && msg.queries()[0].query_type() != RecordType::TXT
    {
        msg.set_response_code(ResponseCode::NXDomain);
        return msg
            .to_vec()
            .map(Some)
            .with_context(|| "truncated response handler: could not serialize Message");
    }

    let (protocol_str, counter_str) = match transport {
        Transport::Tcp => (
            String::from("protocol=TCP"),
            format!(
                "counter={}",
                TRUNCATED_TCP_COUNTER.fetch_add(1, Ordering::Relaxed)
            ),
        ),
        Transport::Udp => (
            String::from("protocol=UDP"),
            format!(
                "counter={}",
                TRUNCATED_UDP_COUNTER.fetch_add(1, Ordering::Relaxed)
            ),
        ),
    };

    msg.set_authoritative(true)
        .set_recursion_desired(false)
        .set_truncated(match transport {
            Transport::Udp => true,
            Transport::Tcp => false,
        })
        .add_answer(Record::from_rdata(
            name,
            86400,
            RData::TXT(rdata::TXT::new(vec![protocol_str, counter_str])),
        ))
        .to_vec()
        .map(Some)
        .with_context(|| "truncated response handler: could not serialize Message")
}

static TRUNCATED_TCP_COUNTER: AtomicU8 = AtomicU8::new(0);
static TRUNCATED_UDP_COUNTER: AtomicU8 = AtomicU8::new(0);
