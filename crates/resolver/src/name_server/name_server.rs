// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt::{self, Debug, Formatter};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use futures_util::lock::Mutex;
use futures_util::stream::{Stream, once};
use tracing::debug;

use crate::config::{NameServerConfig, ResolverOpts};
use crate::name_server::connection_provider::{ConnectionProvider, GenericConnector};
use crate::name_server::{NameServerState, NameServerStats};
use crate::proto::{
    ProtoError,
    xfer::{DnsHandle, DnsRequest, DnsResponse, FirstAnswer},
};

/// This struct is used to create `DnsHandle` with the help of `P`.
#[derive(Clone)]
pub struct NameServer<P: ConnectionProvider> {
    config: NameServerConfig,
    options: ResolverOpts,
    client: Arc<Mutex<Option<P::Conn>>>,
    state: Arc<NameServerState>,
    pub(crate) stats: Arc<NameServerStats>,
    connection_provider: P,
}

/// Specifies the details of a remote NameServer used for lookups
pub type GenericNameServer<R> = NameServer<GenericConnector<R>>;

impl<P> Debug for NameServer<P>
where
    P: ConnectionProvider + Send,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "config: {:?}, options: {:?}", self.config, self.options)
    }
}

impl<P> NameServer<P>
where
    P: ConnectionProvider + Send,
{
    /// Construct a new Nameserver with the configuration and options. The connection provider will create UDP and TCP sockets
    pub fn new(config: NameServerConfig, options: ResolverOpts, connection_provider: P) -> Self {
        Self {
            config,
            options,
            client: Arc::new(Mutex::new(None)),
            state: Arc::new(NameServerState::init(None)),
            stats: Arc::new(NameServerStats::default()),
            connection_provider,
        }
    }

    #[doc(hidden)]
    pub fn from_conn(
        config: NameServerConfig,
        options: ResolverOpts,
        client: P::Conn,
        connection_provider: P,
    ) -> Self {
        Self {
            config,
            options,
            client: Arc::new(Mutex::new(Some(client))),
            state: Arc::new(NameServerState::init(None)),
            stats: Arc::new(NameServerStats::default()),
            connection_provider,
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn is_connected(&self) -> bool {
        !self.state.is_failed()
            && if let Some(client) = self.client.try_lock() {
                client.is_some()
            } else {
                // assuming that if someone has it locked it will be or is connected
                true
            }
    }

    /// This will return a mutable client to allows for sending messages.
    ///
    /// If the connection is in a failed state, then this will establish a new connection
    async fn connected_mut_client(&mut self) -> Result<P::Conn, ProtoError> {
        let mut client = self.client.lock().await;

        // if this is in a failure state
        if self.state.is_failed() || client.is_none() {
            debug!("reconnecting: {:?}", self.config);

            // TODO: we need the local EDNS options
            self.state.reinit(None);

            let new_client = Box::pin(
                self.connection_provider
                    .new_connection(&self.config, &self.options)?,
            )
            .await?;

            // establish a new connection
            *client = Some(new_client);
        } else {
            debug!("existing connection: {:?}", self.config);
        }

        Ok((*client)
            .clone()
            .expect("bad state, client should be connected"))
    }

    async fn inner_send<R: Into<DnsRequest> + Unpin + Send + 'static>(
        mut self,
        request: R,
    ) -> Result<DnsResponse, ProtoError> {
        let client = self.connected_mut_client().await?;
        let now = Instant::now();
        let response = client.send(request).first_answer().await;
        let rtt = now.elapsed();

        match response {
            Ok(response) => {
                // Record the measured latency.
                self.stats.record_rtt(rtt);

                // First evaluate if the message succeeded.
                let response =
                    ProtoError::from_response(response, self.config.trust_negative_responses)?;

                // TODO: consider making message::take_edns...
                let remote_edns = response.extensions().clone();

                // take the remote edns options and store them
                self.state.establish(remote_edns);

                Ok(response)
            }
            Err(error) => {
                debug!(config = ?self.config, "name_server connection failure: {}", error);

                // this transitions the state to failure
                self.state.fail(Instant::now());

                // record the failure
                self.stats.record_connection_failure();

                // These are connection failures, not lookup failures, that is handled in the resolver layer
                Err(error)
            }
        }
    }

    /// Specifies that this NameServer will treat negative responses as permanent failures and will not retry
    pub fn trust_nx_responses(&self) -> bool {
        self.config.trust_negative_responses
    }
}

impl<P> DnsHandle for NameServer<P>
where
    P: ConnectionProvider + Clone,
{
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send>>;

    fn is_verifying_dnssec(&self) -> bool {
        self.options.validate
    }

    // TODO: there needs to be some way of customizing the connection based on EDNS options from the server side...
    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&self, request: R) -> Self::Response {
        let this = self.clone();
        // if state is failed, return future::err(), unless retry delay expired..
        Box::pin(once(this.inner_send(request)))
    }
}

#[cfg(test)]
#[cfg(feature = "tokio")]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use std::time::Duration;

    use hickory_proto::op::Message;
    use hickory_proto::rr::rdata::NULL;
    use hickory_proto::rr::{RData, Record};
    use test_support::subscribe;
    use tokio::net::UdpSocket;
    use tokio::spawn;

    use crate::proto::op::{Query, ResponseCode};
    use crate::proto::rr::{Name, RecordType};
    use crate::proto::xfer::{DnsHandle, DnsRequestOptions, FirstAnswer, Protocol};

    use super::*;
    use crate::name_server::connection_provider::TokioConnectionProvider;

    #[tokio::test]
    async fn test_name_server() {
        subscribe();

        let config = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            http_endpoint: None,
            trust_negative_responses: false,
            bind_addr: None,
        };
        let name_server = GenericNameServer::new(
            config,
            ResolverOpts::default(),
            TokioConnectionProvider::default(),
        );

        let name = Name::parse("www.example.com.", None).unwrap();
        let response = name_server
            .lookup(
                Query::query(name.clone(), RecordType::A),
                DnsRequestOptions::default(),
            )
            .first_answer()
            .await
            .expect("query failed");
        assert_eq!(response.response_code(), ResponseCode::NoError);
    }

    #[tokio::test]
    async fn test_failed_name_server() {
        subscribe();

        let options = ResolverOpts {
            timeout: Duration::from_millis(1), // this is going to fail, make it fail fast...
            ..ResolverOpts::default()
        };
        let config = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 252)), 252),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            http_endpoint: None,
            trust_negative_responses: false,
            bind_addr: None,
        };
        let name_server =
            GenericNameServer::new(config, options, TokioConnectionProvider::default());

        let name = Name::parse("www.example.com.", None).unwrap();
        assert!(
            name_server
                .lookup(
                    Query::query(name.clone(), RecordType::A),
                    DnsRequestOptions::default(),
                )
                .first_answer()
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn case_randomization_query_preserved() {
        subscribe();

        let provider = TokioConnectionProvider::default();
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let name = Name::from_str("dead.beef.").unwrap();
        let data = b"DEADBEEF";

        spawn({
            let name = name.clone();
            async move {
                let mut buffer = [0_u8; 512];
                let (len, addr) = server.recv_from(&mut buffer).await.unwrap();
                let request = Message::from_vec(&buffer[0..len]).unwrap();
                let mut response = Message::new();
                response.set_id(request.id());
                response.add_queries(request.queries().to_vec());
                response.add_answer(Record::from_rdata(
                    name,
                    0,
                    RData::NULL(NULL::with(data.to_vec())),
                ));
                let response_buffer = response.to_vec().unwrap();
                server.send_to(&response_buffer, addr).await.unwrap();
            }
        });

        let config = NameServerConfig::new(server_addr, Protocol::Udp);
        let resolver_opts = ResolverOpts {
            case_randomization: true,
            ..Default::default()
        };
        let mut request_options = DnsRequestOptions::default();
        request_options.case_randomization = true;
        let ns = NameServer::new(config, resolver_opts, provider);

        let stream = ns.lookup(
            Query::query(name.clone(), RecordType::NULL),
            request_options,
        );
        let response = stream.first_answer().await.unwrap();

        let response_query_name = response.query().unwrap().name();
        assert!(response_query_name.eq_case(&name));
    }
}
