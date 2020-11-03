// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TLS protocol related components for DNS over TLS

pub mod tls_client_stream;
pub mod tls_server;
pub mod tls_stream;

pub use self::tls_client_stream::{
    tls_client_connect, tls_client_connect_with_bind_addr, TlsClientStream,
};
pub use self::tls_stream::{tls_connect, tls_connect_with_bind_addr, tls_from_stream, TlsStream};

#[cfg(test)]
pub(crate) mod tests;
