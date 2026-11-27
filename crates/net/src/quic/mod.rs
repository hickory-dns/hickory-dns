// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! QUIC protocol related components for DNS over QUIC (DoQ)

use std::{io, sync::Arc};

use quinn::{AsyncUdpSocket, Runtime};

mod quic_client_stream;
mod quic_config;
mod quic_server;
mod quic_stream;

#[cfg(feature = "__h3")]
pub(crate) use self::quic_client_stream::connect_quic;
pub use self::quic_client_stream::{QuicClientStream, QuicClientStreamBuilder};
pub use self::quic_server::{QuicServer, QuicStreams};
pub use self::quic_stream::{DoqErrorCode, QuicStream};

/// An abstract UDP socket configured for QUIC endpoints.
///
/// Convert a bound [`tokio::net::UdpSocket`] or [`std::net::UdpSocket`] via [`TryFrom`]
/// (requires an active Tokio runtime), or wrap an `Arc` implementing [`quinn::AsyncUdpSocket`]
/// via [`From`].
#[derive(Clone, Debug)]
pub struct QuicSocket(Arc<dyn AsyncUdpSocket>);

impl TryFrom<tokio::net::UdpSocket> for QuicSocket {
    type Error = io::Error;

    fn try_from(socket: tokio::net::UdpSocket) -> Result<Self, Self::Error> {
        Self::try_from(socket.into_std()?)
    }
}

impl TryFrom<std::net::UdpSocket> for QuicSocket {
    type Error = io::Error;

    fn try_from(socket: std::net::UdpSocket) -> Result<Self, Self::Error> {
        Ok(Self(quinn::TokioRuntime.wrap_udp_socket(socket)?))
    }
}

impl<T: AsyncUdpSocket> From<Arc<T>> for QuicSocket {
    fn from(socket: Arc<T>) -> Self {
        Self(socket)
    }
}

impl From<Arc<dyn AsyncUdpSocket>> for QuicSocket {
    fn from(socket: Arc<dyn AsyncUdpSocket>) -> Self {
        Self(socket)
    }
}

impl From<QuicSocket> for Arc<dyn AsyncUdpSocket> {
    fn from(socket: QuicSocket) -> Self {
        socket.0
    }
}

#[cfg(test)]
mod tests;
