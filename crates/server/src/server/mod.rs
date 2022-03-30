// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `Server` component for hosting a domain name servers operations.

#[cfg(feature = "dns-over-https")]
mod https_handler;
mod protocol;
#[cfg(feature = "dns-over-quic")]
mod quic_handler;
mod request_handler;
mod response_handler;
mod server_future;
mod timeout_stream;

pub use self::protocol::Protocol;
pub use self::request_handler::{Request, RequestHandler, RequestInfo, ResponseInfo};
pub use self::response_handler::{ResponseHandle, ResponseHandler};
pub use self::server_future::ServerFuture;
pub use self::timeout_stream::TimeoutStream;
