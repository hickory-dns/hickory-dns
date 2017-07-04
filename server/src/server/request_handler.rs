// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Request Handler for incoming requests

use server::Request;
use trust_dns::op::Message;

/// Trait for handling incoming requests, and providing a message response.
pub trait RequestHandler {
    /// Determine's what needs to happen given the type of request, i.e. Query or Update.
    ///
    /// # Arguments
    ///
    /// * `request` - the requested action to perform.
    ///
    /// # Returns
    ///
    /// The derived response to the the request
    fn handle_request(&self, request: &Request) -> Message;
}
