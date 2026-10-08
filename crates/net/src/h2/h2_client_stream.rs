// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::future::{Future, poll_fn};
use core::net::SocketAddr;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::io;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures_util::stream::Stream;
use h2::client::SendRequest;
use http::Request;
use http::response::Parts;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use super::ALPN_H2;
use crate::error::NetError;
use crate::http::{HttpSender, RequestContext, SetHeaders, Version, content_length, fetch_body};
use crate::proto::op::DnsRequest;
use crate::runtime::iocompat::AsyncIoStdAsTokio;
use crate::runtime::{DnsTcpStream, RuntimeProvider, Spawn};
use crate::xfer::{CONNECT_TIMEOUT, DnsExchange, DnsRequestSender, DnsResponseStream};

/// A DNS client connection for DNS-over-HTTPS
#[derive(Clone)]
#[must_use = "futures do nothing unless polled"]
pub struct HttpsClientStream {
    context: Arc<RequestContext>,
    h2: SendRequest<Bytes>,
    is_shutdown: bool,
}

impl HttpsClientStream {
    /// Constructs a new HttpsClientStreamBuilder with the associated ClientConfig
    pub fn builder<P: RuntimeProvider>(
        client_config: Arc<ClientConfig>,
        provider: P,
    ) -> HttpsClientStreamBuilder<P> {
        HttpsClientStreamBuilder {
            provider,
            client_config,
            bind_addr: None,
            set_headers: None,
            connect_timeout: CONNECT_TIMEOUT,
        }
    }
}

impl DnsRequestSender for HttpsClientStream {
    /// See `crate::http::send_message`
    fn send_message(&mut self, request: DnsRequest) -> DnsResponseStream {
        crate::http::send_message(self, self.is_shutdown, request)
    }

    fn shutdown(&mut self) {
        self.is_shutdown = true;
    }

    fn is_shutdown(&self) -> bool {
        self.is_shutdown
    }
}

impl Stream for HttpsClientStream {
    type Item = Result<(), NetError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.is_shutdown {
            return Poll::Ready(None);
        }

        // just checking if the connection is ok
        match self.h2.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Some(Ok(()))),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(NetError::from(format!(
                "h2 stream errored: {e}",
            ))))),
        }
    }
}

/// A HTTPS connection builder for DNS-over-HTTPS
#[derive(Clone)]
pub struct HttpsClientStreamBuilder<P> {
    provider: P,
    client_config: Arc<ClientConfig>,
    bind_addr: Option<SocketAddr>,
    set_headers: Option<Arc<dyn SetHeaders>>,
    connect_timeout: Duration,
}

impl<P: RuntimeProvider> HttpsClientStreamBuilder<P> {
    /// Sets the address to connect from.
    pub fn bind_addr(&mut self, bind_addr: SocketAddr) {
        self.bind_addr = Some(bind_addr);
    }

    /// Set the [`SetHeaders`] trait object used to inject dynamic headers into the DoH request
    pub fn set_headers(&mut self, headers: Arc<dyn SetHeaders>) {
        self.set_headers.replace(headers);
    }

    /// Override the connect timeout (default: 2 seconds).
    ///
    /// This controls both the TCP connect and the HTTP/2 handshake timeouts.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Creates a new [`DnsExchange`] wrapping the [`HttpsClientStream`] from this builder
    pub async fn exchange(
        self,
        name_server: SocketAddr,
        server_name: Arc<str>,
        path: Arc<str>,
    ) -> Result<DnsExchange<P>, NetError> {
        let mut handle = self.provider.create_handle();
        let stream = self.build(name_server, server_name, path).await?;
        let (exchange, bg) = DnsExchange::from_stream(stream);
        handle.spawn_bg(bg);
        Ok(exchange)
    }

    /// Creates a new HttpsStream to the specified name_server
    ///
    /// # Arguments
    ///
    /// * `name_server` - IP and Port for the remote DNS resolver
    /// * `dns_name` - The DNS name associated with a certificate
    /// * `http_endpoint` - The HTTP endpoint where the remote DNS resolver provides service, typically `/dns-query`
    pub fn build(
        self,
        name_server: SocketAddr,
        server_name: Arc<str>,
        path: Arc<str>,
    ) -> impl Future<Output = Result<HttpsClientStream, NetError>> + Send + 'static {
        connect(
            self.provider.connect_tcp(name_server, self.bind_addr, None),
            self.client_config,
            name_server,
            server_name,
            path,
            self.set_headers,
            self.connect_timeout,
        )
    }
}

/// Creates a new HttpsStream with existing connection
pub fn connect(
    tcp: impl Future<Output = Result<impl DnsTcpStream, io::Error>> + Send + 'static,
    mut client_config: Arc<ClientConfig>,
    name_server: SocketAddr,
    server_name: Arc<str>,
    query_path: Arc<str>,
    set_headers: Option<Arc<dyn SetHeaders>>,
    connect_timeout: Duration,
) -> impl Future<Output = Result<HttpsClientStream, NetError>> + Send + 'static {
    // ensure the ALPN protocol is set correctly
    if client_config.alpn_protocols.is_empty() {
        let mut client_cfg = (*client_config).clone();
        client_cfg.alpn_protocols = vec![ALPN_H2.to_vec()];

        client_config = Arc::new(client_cfg);
    }

    let context = Arc::new(RequestContext {
        version: Version::Http2,
        server_name,
        query_path,
        set_headers,
    });

    async move {
        let tls_server_name = match ServerName::try_from(&*context.server_name) {
            Ok(dns_name) => dns_name.to_owned(),
            Err(err) => {
                return Err(NetError::from(format!(
                    "bad server name {:?}: {err}",
                    context.server_name
                )));
            }
        };

        let (h2, driver) = timeout(connect_timeout, async {
            let tcp = tcp.await?;
            let tls = TlsConnector::from(client_config)
                .connect(tls_server_name, AsyncIoStdAsTokio(tcp))
                .await
                .map_err(NetError::from)?;

            let mut handshake = h2::client::Builder::new();
            handshake.enable_push(false);
            handshake.handshake(tls).await.map_err(NetError::from)
        })
        .await
        .map_err(|_| NetError::Timeout)??;

        debug!("h2 connection established to: {name_server}");
        tokio::spawn(async {
            if let Err(e) = driver.await {
                warn!("h2 connection failed: {e}");
            }
        });

        Ok(HttpsClientStream {
            h2,
            context,
            is_shutdown: false,
        })
    }
}

impl HttpSender for HttpsClientStream {
    async fn send_http_request(
        &mut self,
        request: Request<()>,
        message: Bytes,
    ) -> Result<(Parts, BytesMut), NetError> {
        poll_fn(|cx| self.h2.poll_ready(cx)).await?;

        // Send the request
        let (response_future, mut send_stream) = self.h2.send_request(request, false)?;
        send_stream.send_data(message, true)?;

        let (parts, body) = response_future.await?.into_parts();

        // get the length of packet
        let content_length = content_length(&parts.headers)?;

        // read the response body
        Ok((parts, fetch_body(body, content_length).await?))
    }

    fn context(&self) -> &RequestContext {
        &self.context
    }
}
