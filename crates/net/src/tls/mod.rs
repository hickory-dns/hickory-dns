//! TLS protocol related components for DNS over TLS

mod tls_client_stream;
/// Default TLS configurations and cryptographic provider selection.
pub mod tls_config;
mod tls_listener;

pub use self::tls_client_stream::{
    TlsClientStream, tls_client_connect, tls_client_connect_with_bind_addr, tls_exchange,
};
pub use self::tls_listener::{TlsListener, TlsServerStream};

/// [TLS Application-Layer Protocol Negotiation (ALPN) Protocol IDs](https://www.iana.org/assignments/tls-extensiontype-values#alpn-protocol-ids)
#[allow(missing_docs)]
pub mod alpn {
    pub const H2: &[u8] = b"h2";
    pub const H3: &[u8] = b"h3";
    pub const DOT: &[u8] = b"dot";
    pub const DOQ: &[u8] = b"doq";
}
