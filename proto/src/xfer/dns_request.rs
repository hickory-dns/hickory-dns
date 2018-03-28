// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::ops::Deref;

use smallvec::SmallVec;

use op::Message;
use rr::RecordType;

/// A set of options for expressing options to how requests should be treated
#[derive(Default)]
pub struct DnsRequestOptions {
    /// If true, then the request will block until all reqeusts have been received
    pub expects_multiple_responses: bool,
    /// If set, then the request will terminate early if all types have been received
    pub expected_record_types: Option<SmallVec<[RecordType; 2]>>,
}

/// A DNS reqeust object
pub struct DnsRequest {
    message: Message,
    options: DnsRequestOptions,
}

impl DnsRequest {
    /// Returns a new DnsRequest object
    pub fn new(message: Message, options: DnsRequestOptions) -> Self {
        DnsRequest { message, options }
    }

    pub fn options(&self) -> &DnsRequestOptions {
        &self.options
    }
}

impl Deref for DnsRequest {
    type Target = Message;
    fn deref(&self) -> &Self::Target {
        &self.message
    }
}
