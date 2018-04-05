// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `DnsResponse` wraps a `Message` and any associated connection details

use std::ops::{Deref, DerefMut};

use smallvec::SmallVec;

use op::Message;

/// A DNS reqeust object
///
/// Most DnsRequests only ever expect one response, the exception is a multicast request.
#[derive(Clone, Debug)]
pub struct DnsResponse(SmallVec<[Message; 1]>);

impl DnsResponse {
    /// Get all the messages in the Response
    pub fn messages(&self) -> &[Message] {
        self.0.as_slice()
    }

    /// Get all the messages in the Response
    pub fn messages_mut(&mut self) -> &mut [Message] {
        self.0.as_mut_slice()
    }

    /// returns the number of messages in the response
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Deref for DnsResponse {
    type Target = Message;

    fn deref(&self) -> &Self::Target {
        debug_assert!(self.len() == 1, "There is more than one message in the response, this code path needs to deal with that");
        &self.0[0]
    }
}

impl DerefMut for DnsResponse {
    fn deref_mut(&mut self) -> &mut Self::Target {
        debug_assert!(self.len() == 1, "There is more than one message in the response, this code path needs to deal with that");
        &mut self.0[0]
    }
}

impl From<DnsResponse> for Message {
    fn from(mut response: DnsResponse) -> Message {
        // there should be no way to create an empty smallvec
        debug_assert!(response.len() == 1, "There is more than one message in the response, this code path needs to deal with that");
        response.0.remove(0)
    }
}

impl From<Message> for DnsResponse {
    fn from(message: Message) -> DnsResponse {
        DnsResponse(SmallVec::from([message]))
    }
}

impl From<SmallVec<[Message; 1]>> for DnsResponse {
    fn from(messages: SmallVec<[Message; 1]>) -> DnsResponse {
        debug_assert!(!messages.is_empty(), "There should be at least one message in any DnsResponse");
        DnsResponse(messages)
    }
}
