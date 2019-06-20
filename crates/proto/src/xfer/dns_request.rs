// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `DnsRequest` wraps a `Message` and associates a set of `DnsRequestOptions` for specifying different transfer options.

use std::ops::{Deref, DerefMut};

use crate::op::Message;

/// A set of options for expressing options to how requests should be treated
#[derive(Clone, Default)]
pub struct DnsRequestOptions {
    /// When true, the underlying DNS protocols will not return on the first response received.
    ///
    /// Setting this option will cause the underlying protocol to await the timeout, and then return all Responses.
    pub expects_multiple_responses: bool,
    // /// If set, then the request will terminate early if all types have been received
    // pub expected_record_types: Option<SmallVec<[RecordType; 2]>>,
    // TODO: add EDNS options here?
}

/// A DNS request object
///
/// This wraps a DNS Message for requests. It also has request options associated for controlling certain features of the DNS protocol handlers.
#[derive(Clone)]
pub struct DnsRequest {
    message: Message,
    options: DnsRequestOptions,
}

impl DnsRequest {
    /// Returns a new DnsRequest object
    pub fn new(message: Message, options: DnsRequestOptions) -> Self {
        DnsRequest { message, options }
    }

    /// Get the set of request options associated with this request
    pub fn options(&self) -> &DnsRequestOptions {
        &self.options
    }

    /// Unwraps the raw message
    pub fn unwrap(self) -> (Message, DnsRequestOptions) {
        (self.message, self.options)
    }
}

impl Deref for DnsRequest {
    type Target = Message;
    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

impl DerefMut for DnsRequest {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.message
    }
}

impl Into<DnsRequest> for Message {
    fn into(self) -> DnsRequest {
        DnsRequest::new(self, DnsRequestOptions::default())
    }
}
