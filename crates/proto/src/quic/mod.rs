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
pub(crate) mod quic_socket;
mod quic_stream;

pub use self::quic_client_stream::{
    client_config_tls13, QuicClientConnect, QuicClientResponse, QuicClientStream,
    QuicClientStreamBuilder,
};
pub use self::quic_server::{QuicServer, QuicStreams};
pub use self::quic_stream::{DoqErrorCode, QuicStream};
pub use crate::udp::QuicLocalAddr;

#[cfg(test)]
mod tests;
