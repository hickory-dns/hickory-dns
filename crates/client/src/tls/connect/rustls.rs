use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use crate::proto::iocompat::{AsyncIoStdAsTokio, AsyncIoTokioAsStd};
use crate::proto::tcp::Connect;

use rustls::{ClientConfig, ServerName};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use super::TlsConnect;

pub struct RustlsConnector {
    pub config: Arc<ClientConfig>,
    pub tls_name: ServerName,
}

impl<S: Connect> TlsConnect<S> for RustlsConnector {
    type TlsStream = AsyncIoTokioAsStd<TlsStream<AsyncIoStdAsTokio<S>>>;

    fn tls_connect(
        &self,
        stream: S,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::TlsStream>> + Send + Unpin + 'static>> {
        let connect = connect_tls(self.config.clone(), self.tls_name.clone(), stream);
        Box::pin(connect)
    }
}

async fn connect_tls<S: Connect>(
    config: Arc<ClientConfig>,
    tls_name: ServerName,
    stream: S,
) -> io::Result<AsyncIoTokioAsStd<TlsStream<AsyncIoStdAsTokio<S>>>> {
    let connector = TlsConnector::from(config);
    connector
        .connect(tls_name, AsyncIoStdAsTokio(stream))
        .await
        .map(|s| AsyncIoTokioAsStd(s))
}
