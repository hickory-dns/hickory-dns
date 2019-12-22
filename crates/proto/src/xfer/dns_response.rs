// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `DnsResponse` wraps a `Message` and any associated connection details

use std::ops::{Deref, DerefMut};
use std::slice::{Iter, IterMut};

use smallvec::SmallVec;

use crate::op::Message;

// TODO: this needs to have the IP addr of the remote system...
// TODO: see https://github.com/bluejekyll/trust-dns/issues/383 for removing vec of messages and instead returning a Stream
/// A DNS response object
///
/// For Most DNS requests, only one response is expected, the exception is a multicast request.
#[derive(Clone, Debug)]
pub struct DnsResponse(SmallVec<[Message; 1]>);

// TODO: when `impl Trait` lands in stable, remove this, and expose FlatMap over answers, et al.
impl DnsResponse {
    /// Get all the messages in the Response
    pub fn messages(&self) -> Iter<Message> {
        self.0.as_slice().iter()
    }

    /// Get all the messages in the Response
    pub fn messages_mut(&mut self) -> IterMut<Message> {
        self.0.as_mut_slice().iter_mut()
    }

    /// returns the number of messages in the response
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// returns the number of messages in the response
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Deref for DnsResponse {
    type Target = Message;

    fn deref(&self) -> &Self::Target {
        &self.0[0]
    }
}

impl DerefMut for DnsResponse {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0[0]
    }
}

impl From<DnsResponse> for Message {
    fn from(mut response: DnsResponse) -> Message {
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
        debug_assert!(
            !messages.is_empty(),
            "There should be at least one message in any DnsResponse"
        );
        DnsResponse(messages)
    }
}
