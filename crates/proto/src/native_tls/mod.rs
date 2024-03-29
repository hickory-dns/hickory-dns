// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TLS protocol related components for DNS over TLS

pub mod tls_client_stream;
pub mod tls_stream;

pub use self::tls_client_stream::{TlsClientStream, TlsClientStreamBuilder};
pub use self::tls_stream::{TlsStream, TlsStreamBuilder};

#[cfg(test)]
mod tests;
