// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TLS protocol related components for DNS over HTTPS (DoH)

mod h2_client_stream;
pub mod h2_server;

pub use crate::http::error::{Error as HttpsError, Result as HttpsResult};

pub use self::h2_client_stream::{
    HttpsClientConnect, HttpsClientResponse, HttpsClientStream, HttpsClientStreamBuilder,
};
