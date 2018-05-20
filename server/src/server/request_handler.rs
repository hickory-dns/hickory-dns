// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Request Handler for incoming requests

use std::io;
use std::net::SocketAddr;

use authority::MessageRequest;
use server::ResponseHandler;

/// An incoming request to the DNS catalog
pub struct Request<'r> {
    /// Message with the associated query or update data
    pub message: MessageRequest<'r>,
    /// Source address of the Client
    pub src: SocketAddr,
}

/// Trait for handling incoming requests, and providing a message response.
pub trait RequestHandler: Send + 'static {
    // TODO: allow associated error type
    // type Error;

    /// Determine's what needs to happen given the type of request, i.e. Query or Update.
    ///
    /// # Arguments
    ///
    /// * `request` - the requested action to perform.
    /// * `response_handle` - handle to which a return message should be sent
    fn handle_request<'q, 'a, R: ResponseHandler>(
        &'a self,
        request: &'q Request,
        response_handle: R,
    ) -> io::Result<()>;
}
