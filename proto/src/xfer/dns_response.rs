// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `DnsResponse` wraps a `Message` and any associated connection details

use std::ops::{Deref, DerefMut};

use op::Message;

/// A DNS reqeust object
#[derive(Clone, Debug)]
pub struct DnsResponse(Message);

impl DnsResponse {
    /// Returns a new DnsRequest object
    pub fn new(message: Message) -> Self {
        DnsResponse(message)
    }
}

impl Deref for DnsResponse {
    type Target = Message;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DnsResponse {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Into<Message> for DnsResponse {
    fn into(self) -> Message {
        self.0
    }
}

impl Into<DnsResponse> for Message {
    fn into(self) -> DnsResponse {
        DnsResponse(self)
    }
}
