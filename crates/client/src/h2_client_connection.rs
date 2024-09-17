// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! UDP based DNS client connection for Client impls

use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;

use hickory_proto::h2::{HttpsClientConnect, HttpsClientStream, HttpsClientStreamBuilder};
use hickory_proto::tcp::Connect;
use rustls::ClientConfig;

use crate::client::{ClientConnection, Signer};

/// UDP based DNS Client connection
///
/// Use with `hickory_client::client::Client` impls
#[derive(Clone)]
pub struct HttpsClientConnection<T> {
    name_server: SocketAddr,
    bind_addr: Option<SocketAddr>,
    dns_name: String,
    client_config: Arc<ClientConfig>,
    marker: PhantomData<T>,
}

/// ## Querying DNS over HTTPS (DoH)
///
/// The example code below demonstrates how to use the Client to
/// issue DNS queries over HTTPS.
///
/// ```rust
/// use hickory_client::client::SyncClient;
/// use hickory_client::client::Client;
/// use hickory_client::h2::HttpsClientConnection;
/// use hickory_client::proto::rr::{DNSClass, Name, RecordType};
/// use hickory_client::proto::runtime::iocompat::AsyncIoTokioAsStd;
/// use rustls::{ClientConfig, RootCertStore};
/// use std::net::{IpAddr, Ipv4Addr, SocketAddr};
/// use std::sync::Arc;
/// use webpki_roots;
///
/// let name_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443);
/// let host_to_lookup = "example.com".to_string();
///
/// let mut root_store = RootCertStore::empty();
/// root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
///
/// let client_config = ClientConfig::builder()
///     .with_root_certificates(root_store)
///     .with_no_client_auth();
///
/// let shared_client_config = Arc::new(client_config);
/// let conn: HttpsClientConnection<AsyncIoTokioAsStd<tokio::net::TcpStream>> =
///     HttpsClientConnection::new(name_server, "dns.google".to_string(), shared_client_config);
///
/// let client = SyncClient::new(conn);
/// let name = Name::from_ascii(host_to_lookup).unwrap();
/// let dns_class = DNSClass::IN;
/// let record_type = RecordType::A;
///
/// let response = client.query(&name, dns_class, record_type);
/// match response {
///     Ok(answer) => {
///         println!("ok={:?}", answer);
///     }
///     Err(e) => {
///         println!("err Resp={:?}", e);
///     }
/// }
/// ```

impl<T> HttpsClientConnection<T> {
    /// Creates a new client connection.
    ///
    /// *Note* this has side affects of starting the listening event_loop. Expect this to change in
    /// the future.
    ///
    /// # Arguments
    ///
    /// * `name_server` - IP and Port for the remote DNS resolver
    /// * `dns_name` - The DNS name, Subject Public Key Info (SPKI) name, as associated to a certificate
    /// * `client_config` - The TLS config
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        name_server: SocketAddr,
        dns_name: String,
        client_config: Arc<ClientConfig>,
    ) -> Self {
        Self::new_with_bind_addr(name_server, None, dns_name, client_config)
    }

    /// Creates a new client connection with a specified source address.
    ///
    /// *Note* this has side affects of starting the listening event_loop. Expect this to change in
    /// the future.
    ///
    /// # Arguments
    ///
    /// * `name_server` - IP and Port for the remote DNS resolver
    /// * `bind_addr` - IP and port to connect from
    /// * `dns_name` - The DNS name, Subject Public Key Info (SPKI) name, as associated to a certificate
    /// * `client_config` - The TLS config
    #[allow(clippy::new_ret_no_self)]
    pub fn new_with_bind_addr(
        name_server: SocketAddr,
        bind_addr: Option<SocketAddr>,
        dns_name: String,
        client_config: Arc<ClientConfig>,
    ) -> Self {
        Self {
            name_server,
            bind_addr,
            dns_name,
            client_config,
            marker: PhantomData,
        }
    }
}

impl<T> ClientConnection for HttpsClientConnection<T>
where
    T: Connect,
{
    type Sender = HttpsClientStream;
    type SenderFuture = HttpsClientConnect<T>;

    fn new_stream(
        &self,
        // TODO: maybe signer needs to be applied in https...
        _signer: Option<Arc<Signer>>,
    ) -> Self::SenderFuture {
        // TODO: maybe signer needs to be applied in https...
        let mut https_builder =
            HttpsClientStreamBuilder::with_client_config(Arc::clone(&self.client_config));
        if let Some(bind_addr) = self.bind_addr {
            https_builder.bind_addr(bind_addr);
        }
        https_builder.build(self.name_server, self.dns_name.clone())
    }
}
