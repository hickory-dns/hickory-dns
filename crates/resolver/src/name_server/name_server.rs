// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::cmp::Ordering;
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;
use std::time::Instant;
use std::pin::Pin;

use futures::{future, Future, TryFutureExt};

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
use crate::name_server::{ConnectionHandle, ConnectionProvider, StandardConnection};

/// Specifies the details of a remote NameServer used for lookups
#[derive(Clone)]
pub struct NameServer<C: DnsHandle, P: ConnectionProvider<ConnHandle = C>> {
    config: NameServerConfig,
    options: ResolverOpts,
    client: Option<C>,
    state: Arc<NameServerState>,
    stats: Arc<NameServerStats>,
    conn_provider: P,
}

impl<C: DnsHandle, P: ConnectionProvider<ConnHandle = C>> Debug for NameServer<C, P> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "config: {:?}, options: {:?}", self.config, self.options)
    }
}

impl NameServer<ConnectionHandle, StandardConnection> {
    pub fn new(config: NameServerConfig, options: ResolverOpts) -> Self {
        Self::new_with_provider(config, options, StandardConnection)
    }
}

impl<C: DnsHandle, P: ConnectionProvider<ConnHandle = C>> NameServer<C, P> {
    pub fn new_with_provider(
        config: NameServerConfig,
        options: ResolverOpts,
        conn_provider: P,
    ) -> NameServer<C, P> {
        NameServer {
            config,
            options,
            client: None,
            state: Arc::new(NameServerState::init(None)),
            stats: Arc::new(NameServerStats::default()),
            conn_provider,
        }
    }

    #[doc(hidden)]
    pub fn from_conn(
        config: NameServerConfig,
        options: ResolverOpts,
        client: C,
        conn_provider: P,
    ) -> NameServer<C, P> {
        NameServer {
            config,
            options,
            client: Some(client),
            state: Arc::new(NameServerState::init(None)),
            stats: Arc::new(NameServerStats::default()),
            conn_provider,
        }
    }

    /// This will return a mutable client to allows for sending messages.
    ///
    /// If the connection is in a failed state, then this will establish a new connection
    fn connected_mut_client(&mut self) -> ProtoResult<&mut C> {
        // if this is in a failure state
        if self.state.is_failed() || self.client.is_none() {
            debug!("reconnecting: {:?}", self.config);

            // reinitialize the mutex (in case it was poisoned before)
            // TODO: we need the local EDNS options
            self.state = Arc::new(NameServerState::init(None));

            // establish a new connection
            self.client = Some(
                self.conn_provider
                    .new_connection(&self.config, &self.options),
            );
        }

        Ok(self
            .client
            .as_mut()
            .expect("bad state, client should be connected"))
    }
}

impl<C, P> DnsHandle for NameServer<C, P>
where
    C: DnsHandle,
    P: ConnectionProvider<ConnHandle = C>,
{
    type Response = Pin<Box<dyn Future<Output = Result<DnsResponse, ProtoError>> + Send + Unpin>>;

    fn is_verifying_dnssec(&self) -> bool {
        self.options.validate
    }

    // TODO: there needs to be some way of customizing the connection based on EDNS options from the server side...
    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> Self::Response {
        let distrust_nx_responses = self.options.distrust_nx_responses;

        // grab a reference to the stats for this NameServer
        let stats1 = self.stats.clone();
        let stats2 = self.stats.clone();
        let state1 = self.state.clone();
        let state2 = self.state.clone();

        // if state is failed, return future::err(), unless retry delay expired...
        let client = match self.connected_mut_client() {
            Ok(client) => client,
            Err(e) => return Box::pin(future::err(e)) as Self::Response,
        };

        // Because a Poisoned lock error could have occurred, make sure to create a new Mutex...
        Box::pin(client
                .send(request)
                .and_then(move |response| {
                    // first we'll evaluate if the message succeeded
                    //   see https://github.com/bluejekyll/trust-dns/issues/606
                    //   TODO: there are probably other return codes from the server we may want to
                    //    retry on. We may also want to evaluate NoError responses that lack records as errors as well
                    if distrust_nx_responses {
                        if let ResponseCode::ServFail = response.response_code() {
                            let note = "Nameserver responded with SERVFAIL";
                            debug!("{}", note);
                            return future::err(ProtoError::from(note));
                        }
                    }

                    future::ok(response)
                })
                .and_then(move |response| {
                    // TODO: consider making message::take_edns...
                    let remote_edns = response.edns().cloned();

                    // take the remote edns options and store them
                    state1.establish(remote_edns);

                    // record the success
                    stats1.next_success();

                    future::ok(response)
                })
                .or_else(move |error| {
                    debug!("name_server connection failure: {}", error);

                    // this transitions the state to failure
                    state2.fail(Instant::now());

                    // record the failure
                    stats2.next_failure();

                    // These are connection failures, not lookup failures, that is handled in the resolver layer
                    future::err(error)
                })
        )
        
    }
}

impl<C: DnsHandle, P: ConnectionProvider<ConnHandle = C>> Ord for NameServer<C, P> {
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
        match self
            .state
            .cmp(&other.state)
        {
            Ordering::Equal => (),
            o => {
                return o;
            }
        }

        self.stats.cmp(&other.stats)
    }
}

impl<C: DnsHandle, P: ConnectionProvider<ConnHandle = C>> PartialOrd for NameServer<C, P> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<C: DnsHandle, P: ConnectionProvider<ConnHandle = C>> PartialEq for NameServer<C, P> {
    /// NameServers are equal if the config (connection information) are equal
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config
    }
}

impl<C: DnsHandle, P: ConnectionProvider<ConnHandle = C>> Eq for NameServer<C, P> {}

// TODO: once IPv6 is better understood, also make this a binary keep.
#[cfg(feature = "mdns")]
pub(crate) fn mdns_nameserver<C, P>(options: ResolverOpts, conn_provider: P) -> NameServer<C, P>
where
    C: DnsHandle,
    P: ConnectionProvider<ConnHandle = C>,
{
    let config = NameServerConfig {
        socket_addr: *MDNS_IPV4,
        protocol: Protocol::Mdns,
        tls_dns_name: None,
    };
    NameServer::new_with_provider(config, options, conn_provider)
}

#[cfg(test)]
mod tests {
    extern crate env_logger;

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use futures::{future, FutureExt};
    use tokio::runtime::current_thread::Runtime;

    use proto::op::{Query, ResponseCode};
    use proto::rr::{Name, RecordType};
    use proto::xfer::{DnsHandle, DnsRequestOptions};

    use super::*;
    use crate::config::Protocol;

    #[test]
    fn test_name_server() {
        env_logger::try_init().ok();

        let config = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            protocol: Protocol::Udp,
            tls_dns_name: None,
        };
        let mut io_loop = Runtime::new().unwrap();
        let name_server = future::lazy(|_| {
            NameServer::<_, StandardConnection>::new(
                config,
                ResolverOpts::default(),
            )
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
