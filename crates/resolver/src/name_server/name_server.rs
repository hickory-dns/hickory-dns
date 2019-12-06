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

use futures::{Future, FutureExt};
use tokio::spawn;

use proto::error::{ProtoError, ProtoResult};
#[cfg(feature = "mdns")]
use proto::multicast::MDNS_IPV4;
use proto::op::ResponseCode;
use proto::xfer::{DnsHandle, DnsRequest, DnsResponse};

#[cfg(feature = "mdns")]
use crate::config::Protocol;
use crate::config::{NameServerConfig, ResolverOpts};
use crate::name_server::NameServerState;
use crate::name_server::NameServerStats;
use crate::name_server::{Connection, ConnectionProvider, StandardConnection};
use crate::{SpawnBg, TokioSpawnBg};

/// Specifies the details of a remote NameServer used for lookups
#[derive(Clone)]
pub struct NameServer<C: DnsHandle + Send, P: ConnectionProvider<Conn = C> + Send, S: SpawnBg> {
    config: NameServerConfig,
    options: ResolverOpts,
    client: Option<C>,
    join_bg: S::JoinHandle,
    state: Arc<NameServerState>,
    stats: Arc<NameServerStats>,
    conn_provider: P,
    spawn_bg: S,
}

impl<C: DnsHandle, P: ConnectionProvider<Conn = C>, S: SpawnBg> Debug for NameServer<C, P, S> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "config: {:?}, options: {:?}", self.config, self.options)
    }
}

impl NameServer<Connection, StandardConnection, TokioSpawnBg> {
    pub fn new(config: NameServerConfig, options: ResolverOpts) -> Self {
        Self::new_with_provider(config, options, StandardConnection)
    }
}

impl<C: DnsHandle, P: ConnectionProvider<Conn = C>, S: SpawnBg> NameServer<C, P, S> {
    pub fn new_with_provider(
        config: NameServerConfig,
        options: ResolverOpts,
        conn_provider: P,
        spawn_bg: S,
    ) -> NameServer<C, P, S> {
        NameServer {
            config,
            options,
            client: None,
            join_bg: None,
            state: Arc::new(NameServerState::init(None)),
            stats: Arc::new(NameServerStats::default()),
            conn_provider,
            spawn_bg,
        }
    }

    #[doc(hidden)]
    pub fn from_conn(
        config: NameServerConfig,
        options: ResolverOpts,
        client: C,
        join_bg: S::JoinHandle,
        conn_provider: P,
        spawn_bg: S,
    ) -> NameServer<C, P, S> {
        NameServer {
            config,
            options,
            client: Some(client),
            join_bg: Some(join_bg),
            state: Arc::new(NameServerState::init(None)),
            stats: Arc::new(NameServerStats::default()),
            conn_provider,
            spawn_bg,
        }
    }

    /// This will return a mutable client to allows for sending messages.
    ///
    /// If the connection is in a failed state, then this will establish a new connection
    async fn connected_mut_client(&mut self) -> ProtoResult<&mut C> {
        // if this is in a failure state
        if self.state.is_failed() || self.client.is_none() {
            debug!("reconnecting: {:?}", self.config);

            // TODO: we need the local EDNS options
            self.state = Arc::new(NameServerState::init(None));

            let (client, bg) = self
                .conn_provider
                .new_connection(&self.config, &self.options)
                .await?;

            // TODO: We mignt need to extract a future here, to verify the BG hasn't exited
            let join_bg = self.spawn_bg.spawn_bg(bg);
            self.join_bg = Some(join_bg);
            
            // establish a new connection
            self.client = Some(client);

        }

        Ok(self
            .client
            .as_mut()
            .expect("bad state, client should be connected"))
    }

    async fn inner_send<R: Into<DnsRequest> + Unpin + Send + 'static>(
        mut self,
        request: R,
    ) -> Result<DnsResponse, ProtoError> {
        let client = self.connected_mut_client().await?;
        let response = client.send(request).await;

        match response {
            Ok(response) => {
                // first we'll evaluate if the message succeeded
                //   see https://github.com/bluejekyll/trust-dns/issues/606
                //   TODO: there are probably other return codes from the server we may want to
                //    retry on. We may also want to evaluate NoError responses that lack records as errors as well
                if self.options.distrust_nx_responses {
                    if let ResponseCode::ServFail = response.response_code() {
                        let note = "Nameserver responded with SERVFAIL";
                        debug!("{}", note);
                        return Err(ProtoError::from(note));
                    }
                }

                // TODO: consider making message::take_edns...
                let remote_edns = response.edns().cloned();

                // take the remote edns options and store them
                self.state.establish(remote_edns);

                // record the success
                self.stats.next_success();
                Ok(response)
            }
            Err(error) => {
                debug!("name_server connection failure: {}", error);

                // this transitions the state to failure
                self.state.fail(Instant::now());

                // record the failure
                self.stats.next_failure();

                // These are connection failures, not lookup failures, that is handled in the resolver layer
                Err(error)
            }
        }
    }
}

impl<C, P, S> DnsHandle for NameServer<C, P, S>
where
    C: DnsHandle,
    P: ConnectionProvider<Conn = C>,
    S: SpawnBg,
{
    type Response = Pin<Box<dyn Future<Output = Result<DnsResponse, ProtoError>> + Send>>;

    fn is_verifying_dnssec(&self) -> bool {
        self.options.validate
    }

    // TODO: there needs to be some way of customizing the connection based on EDNS options from the server side...
    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&mut self, request: R) -> Self::Response {
        let this = self.clone();
        // if state is failed, return future::err(), unless retry delay expired..
        Box::pin(this.inner_send(request))
    }
}

impl<C: DnsHandle, P: ConnectionProvider<Conn = C>, S: SpawnBg> Ord for NameServer<C, P, S> {
    /// Custom implementation of Ord for NameServer which incorporates the performance of the connection into it's ranking
    fn cmp(&self, other: &Self) -> Ordering {
        // if they are literally equal, just return
        if self == other {
            return Ordering::Equal;
        }

        // otherwise, run our evaluation to determine the next to be returned from the Heap
        //   this will prefer established connections, we should try other connections after
        //   some number to make sure that all are used. This is more important for when
        //   latency is started to be used.
        match self.state.cmp(&other.state) {
            Ordering::Equal => (),
            o => {
                return o;
            }
        }

        self.stats.cmp(&other.stats)
    }
}

impl<C: DnsHandle, P: ConnectionProvider<Conn = C>, S: SpawnBg> PartialOrd for NameServer<C, P, S> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<C: DnsHandle, P: ConnectionProvider<Conn = C>, S: SpawnBg> PartialEq for NameServer<C, P, S> {
    /// NameServers are equal if the config (connection information) are equal
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config
    }
}

impl<C: DnsHandle, P: ConnectionProvider<Conn = C>, S: SpawnBg> Eq for NameServer<C, P, S> {}

// TODO: once IPv6 is better understood, also make this a binary keep.
#[cfg(feature = "mdns")]
pub(crate) fn mdns_nameserver<C, P, S>(options: ResolverOpts, conn_provider: P) -> NameServer<C, P, S>
where
    C: DnsHandle,
    P: ConnectionProvider<Conn = C>,
    S: SpawnBg,
{
    let config = NameServerConfig {
        socket_addr: *MDNS_IPV4,
        protocol: Protocol::Mdns,
        tls_dns_name: None,
        #[cfg(feature = "dns-over-rustls")]
        tls_config: None,
    };
    NameServer::new_with_provider(config, options, conn_provider)
}

#[cfg(test)]
mod tests {
    extern crate env_logger;

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use futures::{future, FutureExt};
    use tokio::runtime::Runtime;

    use proto::op::{Query, ResponseCode};
    use proto::rr::{Name, RecordType};
    use proto::xfer::{DnsHandle, DnsRequestOptions};

    use super::*;
    use crate::config::Protocol;

    #[test]
    fn test_name_server() {
        //env_logger::try_init().ok();

        let config = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
        };
        let mut io_loop = Runtime::new().unwrap();
        let name_server = future::lazy(|_| {
            NameServer::<_, StandardConnection>::new(config, ResolverOpts::default())
        });

        let name = Name::parse("www.example.com.", None).unwrap();
        let response = io_loop
            .block_on(name_server.then(|mut name_server| {
                name_server.lookup(
                    Query::query(name.clone(), RecordType::A),
                    DnsRequestOptions::default(),
                )
            }))
            .expect("query failed");
        assert_eq!(response.response_code(), ResponseCode::NoError);
    }

    #[test]
    fn test_failed_name_server() {
        let mut options = ResolverOpts::default();
        options.timeout = Duration::from_millis(1); // this is going to fail, make it fail fast...
        let config = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 252)), 252),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
        };
        let mut io_loop = Runtime::new().unwrap();
        let name_server =
            future::lazy(|_| NameServer::<_, StandardConnection>::new(config, options));

        let name = Name::parse("www.example.com.", None).unwrap();
        assert!(io_loop
            .block_on(name_server.then(|mut name_server| name_server.lookup(
                Query::query(name.clone(), RecordType::A),
                DnsRequestOptions::default()
            )))
            .is_err());
    }
}
