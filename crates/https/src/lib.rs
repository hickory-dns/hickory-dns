// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TLS protocol related components for DNS over TLS
#![warn(missing_docs)]

extern crate bytes;
extern crate data_encoding;
#[macro_use]
extern crate futures;
extern crate h2;
extern crate http;
#[macro_use]
extern crate log;
extern crate failure;
extern crate rustls;
extern crate tokio_executor;
extern crate tokio_rustls;
extern crate tokio_net;
extern crate trust_dns_proto;
extern crate trust_dns_rustls;
extern crate typed_headers;
extern crate webpki;
extern crate webpki_roots;

const MIME_APPLICATION: &str = "application";
const MIME_DNS_BINARY: &str = "dns-message";
const MIME_APPLICATION_DNS: &str = "application/dns-message";
const DNS_QUERY_PATH: &str = "/dns-query";
const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

//pub mod https_client_connection;
mod error;
mod https_client_stream;
pub mod https_server;
pub mod request;
pub mod response;
//pub mod https_stream;

pub use self::error::{Error as HttpsError, Result as HttpsResult};

//pub use self::https_client_connection::{HttpsClientConnection, HttpsClientConnectionBuilder};
pub use self::https_client_stream::{
    HttpsClientConnect, HttpsClientStream, HttpsClientStreamBuilder
};
//pub use self::https_stream::{HttpsStream, HttpsStreamBuilder};
