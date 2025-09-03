use crate::Transport;
use anyhow::{Context, Result};
use hickory_proto::{
    op::Message,
    rr::{RData, Record, rdata},
};

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
