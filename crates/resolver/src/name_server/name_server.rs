// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::cmp::Ordering;
use std::fmt::{self, Debug, Formatter};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use futures_util::lock::Mutex;
use futures_util::stream::{once, Stream};

#[cfg(feature = "mdns")]
use proto::multicast::MDNS_IPV4;
use proto::xfer::{DnsHandle, DnsRequest, DnsResponse, FirstAnswer};
use tracing::debug;

use crate::config::{NameServerConfig, ResolverOpts};
use crate::error::ResolveError;
use crate::name_server::connection_provider::{ConnectionProvider, GenericConnector};
use crate::name_server::{NameServerState, NameServerStats};
#[cfg(feature = "mdns")]
use proto::multicast::{MdnsClientConnect, MdnsClientStream, MdnsQueryType};

/// This struct is used to create `DnsHandle` with the help of `P`.
#[derive(Clone)]
pub struct NameServer<P: ConnectionProvider> {
    config: NameServerConfig,
    options: ResolverOpts,
    client: Arc<Mutex<Option<P::Conn>>>,
    state: Arc<NameServerState>,
    stats: Arc<NameServerStats>,
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
    async fn connected_mut_client(&mut self) -> Result<P::Conn, ResolveError> {
        let mut client = self.client.lock().await;

        // if this is in a failure state
        if self.state.is_failed() || client.is_none() {
            debug!("reconnecting: {:?}", self.config);

            // TODO: we need the local EDNS options
            self.state.reinit(None);

            let new_client = Box::pin(
                self.connection_provider
                    .new_connection(&self.config, &self.options),
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
    ) -> Result<DnsResponse, ResolveError> {
        let mut client = self.connected_mut_client().await?;
        let now = Instant::now();
        let response = client.send(request).first_answer().await;
        let rtt = now.elapsed();

        match response {
            Ok(response) => {
                // Record the measured latency.
                self.stats.record_rtt(rtt);

                // First evaluate if the message succeeded.
                let response =
                    ResolveError::from_response(response, self.config.trust_negative_responses)?;

                // TODO: consider making message::take_edns...
                let remote_edns = response.extensions().clone();

                // take the remote edns options and store them
                self.state.establish(remote_edns);

                Ok(response)
            }
            Err(error) => {
                debug!("name_server connection failure: {}", error);

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
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ResolveError>> + Send>>;
    type Error = ResolveError;

    fn is_verifying_dnssec(&self) -> bool {
        self.options.validate
    }

    // TODO: there needs to be some way of customizing the connection based on EDNS options from the server side...
    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&mut self, request: R) -> Self::Response {
        let this = self.clone();
        // if state is failed, return future::err(), unless retry delay expired..
        Box::pin(once(this.inner_send(request)))
    }
}

impl<P> Ord for NameServer<P>
where
    P: ConnectionProvider + Send,
{
    /// Custom implementation of Ord for NameServer which incorporates the performance of the connection into it's ranking
    fn cmp(&self, other: &Self) -> Ordering {
        // if they are literally equal, just return
        if self == other {
            return Ordering::Equal;
        }

        self.stats.cmp(&other.stats)
    }
}

impl<P> PartialOrd for NameServer<P>
where
    P: ConnectionProvider + Send,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<P> PartialEq for NameServer<P>
where
    P: ConnectionProvider + Send,
{
    /// NameServers are equal if the config (connection information) are equal
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config
    }
}

impl<P> Eq for NameServer<P> where P: ConnectionProvider + Send {}

// TODO: once IPv6 is better understood, also make this a binary keep.
#[cfg(feature = "mdns")]
pub(crate) fn mdns_nameserver<P>(
    options: ResolverOpts,
    conn_provider: P,
    trust_negative_responses: bool,
) -> GenericNameServer<P>
where
    P: ConnectionProvider,
{
    let config = NameServerConfig {
        socket_addr: *MDNS_IPV4,
        protocol: Protocol::Mdns,
        tls_dns_name: None,
        trust_negative_responses,
        #[cfg(feature = "dns-over-rustls")]
        tls_config: None,
        bind_addr: None,
    };
    GenericNameServer::new_with_provider(config, options, conn_provider)
}

#[cfg(test)]
#[cfg(feature = "tokio-runtime")]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use futures_util::{future, FutureExt};
    use tokio::runtime::Runtime;

    use proto::op::{Query, ResponseCode};
    use proto::rr::{Name, RecordType};
    use proto::xfer::{DnsHandle, DnsRequestOptions, FirstAnswer};

    use super::*;
    use crate::config::Protocol;
    use crate::name_server::TokioConnectionProvider;

    #[test]
    fn test_name_server() {
        //env_logger::try_init().ok();

        let config = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
            bind_addr: None,
        };
        let io_loop = Runtime::new().unwrap();
        let name_server = future::lazy(|_| {
            GenericNameServer::new(
                config,
                ResolverOpts::default(),
                TokioConnectionProvider::default(),
            )
        });

        let name = Name::parse("www.example.com.", None).unwrap();
        let response = io_loop
            .block_on(name_server.then(|mut name_server| {
                name_server
                    .lookup(
                        Query::query(name.clone(), RecordType::A),
                        DnsRequestOptions::default(),
                    )
                    .first_answer()
            }))
            .expect("query failed");
        assert_eq!(response.response_code(), ResponseCode::NoError);
    }

    #[test]
    fn test_failed_name_server() {
        let options = ResolverOpts {
            timeout: Duration::from_millis(1), // this is going to fail, make it fail fast...
            ..ResolverOpts::default()
        };
        let config = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 252)), 252),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
            bind_addr: None,
        };
        let io_loop = Runtime::new().unwrap();
        let name_server = future::lazy(|_| {
            GenericNameServer::new(config, options, TokioConnectionProvider::default())
        });

        let name = Name::parse("www.example.com.", None).unwrap();
        assert!(io_loop
            .block_on(name_server.then(|mut name_server| {
                name_server
                    .lookup(
                        Query::query(name.clone(), RecordType::A),
                        DnsRequestOptions::default(),
                    )
                    .first_answer()
            }))
            .is_err());
    }
}
