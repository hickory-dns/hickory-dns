// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Request Handler for incoming requests

use std::net::SocketAddr;

use futures::Future;

use authority::MessageRequest;
use server::ResponseHandler;

/// An incoming request to the DNS catalog
pub struct Request {
    /// Message with the associated query or update data
    pub message: MessageRequest,
    /// Source address of the Client
    pub src: SocketAddr,
}

/// Trait for handling incoming requests, and providing a message response.
pub trait RequestHandler: Send + 'static {
    /// A future for execution of the request
    type ResponseFuture: Future<Output = Result<(), ()>> + Send + 'static;

    /// Determines what needs to happen given the type of request, i.e. Query or Update.
    ///
    /// # Arguments
    ///
    /// * `request` - the requested action to perform.
    /// * `response_handle` - handle to which a return message should be sent
    fn handle_request<R: ResponseHandler>(
        &self,
        request: Request,
        response_handle: R,
    ) -> Self::ResponseFuture;
}
