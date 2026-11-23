// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! QUIC protocol related components for DNS over QUIC (DoQ)

use std::{io, sync::Arc};

use quinn::Runtime;

mod quic_client_stream;
mod quic_config;
mod quic_server;
mod quic_stream;

#[cfg(feature = "__h3")]
pub(crate) use self::quic_client_stream::connect_quic;
pub use self::quic_client_stream::{QuicClientStream, QuicClientStreamBuilder};
pub use self::quic_server::{QuicServer, QuicStreams};
pub use self::quic_stream::{DoqErrorCode, QuicStream};
pub use quinn::AsyncUdpSocket;

/// Adapts an input socket into the abstract socket that the QUIC based server endpoints require.
///
/// [`tokio::net::UdpSocket`] and [`std::net::UdpSocket`] inputs are adapted automatically, as are
/// sockets that implement Quinn's [`AsyncUdpSocket`] and are already shared through an [`Arc`].
/// Inputs that need additional preparation can implement this trait for their own type and adapt
/// the input themselves.
pub trait IntoQuicSocket {
    /// Convert this input into an abstract QUIC socket.
    fn into_quic_socket(self) -> io::Result<Arc<dyn AsyncUdpSocket>>;
}

impl IntoQuicSocket for tokio::net::UdpSocket {
    fn into_quic_socket(self) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        quinn::TokioRuntime.wrap_udp_socket(self.into_std()?)
    }
}

impl IntoQuicSocket for std::net::UdpSocket {
    fn into_quic_socket(self) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        quinn::TokioRuntime.wrap_udp_socket(self)
    }
}

impl<T: AsyncUdpSocket> IntoQuicSocket for Arc<T> {
    fn into_quic_socket(self) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        Ok(self)
    }
}

impl IntoQuicSocket for Arc<dyn AsyncUdpSocket> {
    fn into_quic_socket(self) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        Ok(self)
    }
}

#[cfg(test)]
mod tests;
