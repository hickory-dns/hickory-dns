// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TLS protocol related components for DNS over TLS

extern crate bytes;
extern crate data_encoding;
#[macro_use]
extern crate futures;
extern crate h2;
extern crate http;
#[macro_use]
extern crate log;
extern crate rustls;
extern crate tokio_executor;
extern crate tokio_reactor;
extern crate tokio_rustls;
extern crate tokio_tcp;
extern crate trust_dns_proto;
extern crate trust_dns_rustls;
extern crate webpki_roots;

const ACCEPTS_DNS_BINARY: &str = "application/dns-message";

//pub mod https_client_connection;
pub mod https_client_stream;
//pub mod https_stream;

//pub use self::https_client_connection::{HttpsClientConnection, HttpsClientConnectionBuilder};
pub use self::https_client_stream::{
    HttpsClientStream, HttpsClientStreamBuilder, HttpsSerialResponse,
};
//pub use self::https_stream::{HttpsStream, HttpsStreamBuilder};
