//! TLS protocol related components for DNS over TLS

mod tls_client_stream;
/// Default TLS configurations and cryptographic provider selection.
pub mod tls_config;
mod tls_listener;

pub use self::tls_client_stream::{
    TlsClientStream, tls_client_connect, tls_client_connect_with_bind_addr, tls_exchange,
};
pub use self::tls_listener::{TlsListener, TlsServerStream};
