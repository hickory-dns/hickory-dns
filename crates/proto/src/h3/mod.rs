// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TLS protocol related components for DNS over HTTP/3 (DoH3)

mod h3_client_stream;
pub mod h3_server;

use quinn::{TransportConfig, VarInt};

pub use crate::http::error::{Error as H3Error, Result as H3Result};

pub use self::h3_client_stream::{
    H3ClientConnect, H3ClientResponse, H3ClientStream, H3ClientStreamBuilder,
};

const ALPN_H3: &[u8] = b"h3";

/// Returns a default endpoint configuration for DNS-over-QUIC
fn transport() -> TransportConfig {
    let mut transport_config = TransportConfig::default();

    transport_config.datagram_receive_buffer_size(None);
    transport_config.datagram_send_buffer_size(0);
    // clients never accept new bidirectional streams
    transport_config.max_concurrent_bidi_streams(VarInt::from_u32(3));
    // - SETTINGS
    // - QPACK encoder
    // - QPACK decoder
    // - RESERVED (GREASE)
    transport_config.max_concurrent_uni_streams(VarInt::from_u32(4));

    transport_config
}
