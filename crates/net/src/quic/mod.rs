// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! QUIC protocol related components for DNS over QUIC (DoQ)

mod quic_client_stream;
mod quic_config;
mod quic_server;
mod quic_stream;

#[cfg(feature = "__h3")]
pub(crate) use self::quic_client_stream::connect_quic;
pub use self::quic_client_stream::{
    QuicClientConnect, QuicClientResponse, QuicClientStream, QuicClientStreamBuilder,
};
pub use self::quic_server::{QuicServer, QuicStreams};
pub use self::quic_stream::{DoqErrorCode, QuicStream};

#[cfg(test)]
mod tests;
