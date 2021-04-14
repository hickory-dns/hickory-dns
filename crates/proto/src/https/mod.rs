// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TLS protocol related components for DNS over HTTPS (DoH)

const MIME_APPLICATION_DNS: &str = "application/dns-message";
const DNS_QUERY_PATH: &str = "/dns-query";

mod error;
mod https_client_stream;
pub mod https_server;
pub mod request;
pub mod response;

pub use self::error::{Error as HttpsError, Result as HttpsResult};

pub use self::https_client_stream::{
    HttpsClientConnect, HttpsClientResponse, HttpsClientStream, HttpsClientStreamBuilder,
};
