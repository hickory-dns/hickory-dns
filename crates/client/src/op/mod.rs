// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Operations to send with a `Client` or server, e.g. `Query`, `Message`, or `UpdateMessage` can
//! be used together to either query or update resource records sets.

mod lower_query;
pub mod update_message;

pub use self::lower_query::LowerQuery;
pub use self::update_message::UpdateMessage;
pub use crate::proto::{
    op::{
        Edns, Header, Message, MessageFinalizer, MessageType, MessageVerifier, OpCode, Query,
        ResponseCode,
    },
    xfer::DnsResponse,
};
