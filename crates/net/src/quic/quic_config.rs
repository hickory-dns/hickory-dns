// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::sync::Arc;

use quinn::{EndpointConfig, TransportConfig, VarInt, crypto::rustls::QuicServerConfig};
use rustls::{
    ServerConfig,
    quic::{ServerConnection, Version},
};

use crate::error::NetError;

/// Returns a default endpoint configuration for DNS-over-QUIC
pub(crate) fn endpoint() -> EndpointConfig {
    // set some better EndpointConfig defaults for DoQ
    let mut endpoint_config = EndpointConfig::default();

    // all DNS packets have a maximum size of u16 due to DoQ and 1035 rfc
    // TODO: the RFC claims max == u16::max, but this matches the max in some test servers.
    endpoint_config
        .max_udp_payload_size(0x45ac)
        .expect("max udp payload size exceeded");

    endpoint_config
}

/// Returns a default endpoint configuration for DNS-over-QUIC
pub(crate) fn transport() -> TransportConfig {
    let mut transport_config = TransportConfig::default();

    transport_config.max_concurrent_uni_streams(VarInt::from_u32(0));
    transport_config.datagram_receive_buffer_size(None);
    transport_config.datagram_send_buffer_size(0);

    transport_config
}

/// Converts a TLS configuration for use by a QUIC server endpoint.
///
/// Fails if rustls would reject `tls_config` for QUIC connections, for example without TLS 1.3.
pub(crate) fn server_crypto(tls_config: Arc<ServerConfig>) -> Result<QuicServerConfig, NetError> {
    let crypto = QuicServerConfig::try_from(tls_config.clone())?;
    // quinn only checks the cipher suites here; rustls checks its other QUIC requirements when
    // each connection starts, and quinn panics if that fails.
    ServerConnection::new(tls_config, Version::V1, Vec::new())?;
    Ok(crypto)
}
