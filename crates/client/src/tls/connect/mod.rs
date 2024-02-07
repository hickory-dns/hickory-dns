use std::future::Future;
use std::io;
use std::pin::Pin;

use crate::proto::tcp::{Connect, DnsTcpStream};

#[cfg(feature = "dns-over-rustls")]
pub mod rustls;

pub trait TlsConnect<S: Connect> {
    type TlsStream: DnsTcpStream;

    fn tls_connect(
        &self,
        stream: S,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::TlsStream>> + Send + Unpin + 'static>>;
}
