use crate::Transport;
use hickory_proto::{
    ProtoError,
    op::Message,
    rr::{RData, Record, rdata},
};

/// This handler generates a valid A-record response to any query
pub(crate) fn base_handler(
    bytes: &[u8],
    _transport: Transport,
) -> Result<Option<Vec<u8>>, ProtoError> {
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
}

/// This handler responds to any messages with an incorrect transaction (query) id.
pub(crate) fn bad_txid_handler(
    bytes: &[u8],
    _transport: Transport,
) -> Result<Option<Vec<u8>>, ProtoError> {
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
}

/// This handler responds to any messages with an empty message (no response records)
pub(crate) fn empty_response_handler(
    bytes: &[u8],
    _transport: Transport,
) -> Result<Option<Vec<u8>>, ProtoError> {
    Message::from_vec(bytes)?.to_response().to_vec().map(Some)
}
