use quinn::{EndpointConfig, TransportConfig, VarInt};

/// Returns a default endpoint configuration for DNS-over-HTTP/3
pub(super) fn endpoint() -> EndpointConfig {
    EndpointConfig::default()
}

/// Returns a default transport configuration for DNS-over-HTTP/3
pub(super) fn transport() -> TransportConfig {
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
