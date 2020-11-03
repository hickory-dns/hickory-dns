// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! UDP based DNS client connection for Client impls

use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;

use rustls::ClientConfig;
use trust_dns_proto::https::{HttpsClientConnect, HttpsClientStream, HttpsClientStreamBuilder};
use trust_dns_proto::tcp::Connect;

use crate::client::{ClientConnection, Signer};

/// UDP based DNS Client connection
///
/// Use with `trust_dns_client::client::Client` impls
#[derive(Clone)]
pub struct HttpsClientConnection<T> {
    name_server: SocketAddr,
    bind_addr: Option<SocketAddr>,
    dns_name: String,
    client_config: Arc<ClientConfig>,
    marker: PhantomData<T>,
}

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
