// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::mem;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::{future, Future};
use tokio_core::reactor::Handle;

use trust_dns::error::*;
use trust_dns::client::{BasicClientHandle, ClientFuture, ClientHandle};
use trust_dns::op::{Edns, Message};
use trust_dns::udp::UdpClientStream;
use trust_dns::tcp::TcpClientStream;
// use trust_dns::tls::TlsClientStream;

use config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};

const MIN_RETRY_DELAY_MS: u64 = 500;
const MAX_RETRY_DELAY_S: u64 = 360;

/// State of a connection with a remote NameServer.
#[derive(Clone, Debug)]
enum NameServerState {
    /// Initial state, if Edns is not none, then Edns will be requested
    Init { send_edns: Option<Edns> },
    /// There has been successful communication with the remote.
    ///  if no Edns is associated, then the remote does not support Edns
    Established { remote_edns: Option<Edns> },
    /// For some reason the connection failed. For UDP this would only be a timeout
    ///  for TCP this could be either Connection could never be established, or it
    ///  failed at some point after. The Failed state should not be entered due to the
    ///  error contained in a Message recieved from the server. In All cases to reestablish
    ///  a new connection will need to be created.
    Failed { error: ClientError, when: Instant }, // TODO: make error Arc...
}

impl NameServerState {
    fn to_usize(&self) -> usize {
        match *self {
            NameServerState::Init { .. } => 3, // Should we instead prefer already established connections?
            NameServerState::Established { .. } => 2,
            NameServerState::Failed { .. } => 1,
        }
    }
}

impl Ord for NameServerState {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_usize().cmp(&other.to_usize())
    }
}

impl PartialOrd for NameServerState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for NameServerState {
    fn eq(&self, other: &Self) -> bool {
        self.to_usize() == other.to_usize()
    }
}

impl Eq for NameServerState {}

#[derive(Clone, PartialEq, Eq)]
struct NameServerStats {
    state: NameServerState,
    successes: usize,
    failures: usize,
}

impl Default for NameServerStats {
    fn default() -> Self {
        Self::init(None, 0, 0)
    }
}

impl NameServerStats {
    fn init(send_edns: Option<Edns>, successes: usize, failures: usize) -> Self {
        NameServerStats {
            state: NameServerState::Init { send_edns },
            successes,
            failures,
            // TODO: incorporate latency
        }
    }

    fn next_success(&mut self, remote_edns: Option<Edns>) {
        self.successes += 1;

        // update current state

        if remote_edns.is_some() {
            mem::replace(&mut self.state,
                         NameServerState::Established { remote_edns });
        } else {
            // preserve existing EDNS if it exists
            let remote_edns = if let NameServerState::Established { ref remote_edns } =
                self.state {
                remote_edns.clone()
            } else {
                None
            };

            mem::replace(&mut self.state,
                         NameServerState::Established { remote_edns });
        };
    }

    fn next_failure(&mut self, error: ClientError, when: Instant) {
        self.failures += 1;

        // update current state
        mem::replace(&mut self.state, NameServerState::Failed { error, when });
    }
}

impl Ord for NameServerStats {
    /// Custom implementation of Ord for NameServer which incorporates the performance of the connection into it's ranking
    fn cmp(&self, other: &Self) -> Ordering {
        // if they are literally equal, just return
        if self == other {
            return Ordering::Equal;
        }

        // otherwise, run our evaluation to determine the next to be returned from the Heap
        match self.state.cmp(&other.state) {
            Ordering::Equal => (),
            o @ _ => {
                return o;
            }
        }

        // TODO: track latency and use lowest latency connection...

        // invert failure comparison
        if self.failures <= other.failures {
            return Ordering::Greater;
        }

        // at this point we'll go with the lesser of successes to make sure there is ballance
        self.successes.cmp(&other.successes)
    }
}

impl PartialOrd for NameServerStats {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone)]
pub(crate) struct NameServer {
    config: NameServerConfig,
    options: ResolverOpts,
    client: BasicClientHandle,
    stats: Arc<Mutex<NameServerStats>>,
    reactor: Handle,
}

impl NameServer {
    fn new_connection(config: &NameServerConfig, options: &ResolverOpts, reactor: Handle) -> BasicClientHandle {
        match config.protocol {
            Protocol::Udp => {
                let (stream, handle) = UdpClientStream::new(config.socket_addr, reactor.clone());
                // TODO: need config for Signer...
                ClientFuture::with_timeout(stream, handle, reactor, options.timeout, None)
            }
            Protocol::Tcp => {
                let (stream, handle) = TcpClientStream::with_timeout(config.socket_addr, reactor.clone(), options.timeout);
                // TODO: need config for Signer...
                ClientFuture::with_timeout(stream, handle, reactor, options.timeout, None)
            }
            // TODO: Protocol::Tls => TlsClientStream::new(config.socket_addr, reactor),
            _ => unimplemented!(),
        }
    }

    pub fn new(config: NameServerConfig, options: ResolverOpts, reactor: Handle) -> Self {
        let client = Self::new_connection(&config, &options, reactor.clone());

        // FIXME: setup EDNS
        NameServer {
            config,
            options,
            client,
            stats: Arc::new(Mutex::new(NameServerStats::default())),
            reactor,
        }
    }

    /// checks if the connection is failed, if so, then it
    ///  will check the last falure time, and if the retry period is acceptable,
    ///  then reconnect.
    #[allow(unused_must_use)] // TODO: remove must use from BasicClientHandle
    fn try_reconnect(&mut self) -> ClientResult<()> {
        let error_opt: Option<(ClientError, Instant, usize, usize)> = self.stats
            .lock()
            .map(|stats| if let NameServerState::Failed { ref error, when } = stats.state {
                     Some((error.clone(), when, stats.successes, stats.failures))
                 } else {
                     None
                 })
            .map_err(|e| {
                         ClientErrorKind::Msg(format!("Error acquiring NameServerStats lock: {}",
                                                      e)
                                                      .into())
                     })?;

        // if this is in a failure state
        if let Some((error, when, successes, failures)) = error_opt {
            // Backoff is based on successes vs. failures...
            let max_delay = Duration::from_secs(MAX_RETRY_DELAY_S);
            let min_delay = Duration::from_millis(MIN_RETRY_DELAY_MS);
            let failures = failures.saturating_sub(successes);
            let retry_delay = Duration::from_millis(failures.saturating_mul(10) as u64); // 10 ms backoff

            // TODO: switch to min|max when they stabalize
            let retry_delay = if retry_delay < max_delay {
                if retry_delay > min_delay {
                    retry_delay
                } else {
                    min_delay
                }
            } else {
                max_delay
            };

            if Instant::now().duration_since(when) > retry_delay {
                println!("reconnecting: {:?}", self.config);
                // establish a new connection
                let client = Self::new_connection(&self.config, &self.options, self.reactor.clone());
                mem::replace(&mut self.client, client);

                // reinitialize the mutex (in case it was poisoned before)
                mem::replace(&mut self.stats,
                             Arc::new(Mutex::new(NameServerStats::init(None,
                                                                       successes,
                                                                       failures))));
                Ok(())
            } else {
                Err(error)
            }
        } else {
            Ok(())
        }
    }
}

// TODO: there needs to be some way of customizing the connection based on EDNS options from the server side...
impl ClientHandle for NameServer {
    fn send(&mut self, message: Message) -> Box<Future<Item = Message, Error = ClientError>> {
        // if state is failed, return future::err(), unless retry delay expired...
        if let Err(error) = self.try_reconnect() {
            return Box::new(future::err(error));
        }

        // Becuase a Poisoned lock error could have occured, make sure to create a new Mutex...

        // grab a reference to the stats for this NameServer
        let mutex1 = self.stats.clone();
        let mutex2 = self.stats.clone();
        Box::new(self.client.send(message).and_then(move |response| {
            // TODO: consider making message::take_edns...
            let remote_edns = response.edns().cloned();

            // this transitions the state to success
            let response = 
                mutex1
                    .lock()
                    .and_then(|mut stats| { stats.next_success(remote_edns); Ok(response) })
                    .map_err(|e| format!("Error acquiring NameServerStats lock: {}", e).into());

            future::result(response)
        }).or_else(move |error| {
            // this transitions the state to failure
            mutex2
                .lock()
                .and_then(|mut stats| {
                    stats.next_failure(error.clone(), Instant::now());
                    Ok(())
                })
                .or_else(|e| {
                    warn!("Error acquiring NameServerStats lock (already in error state, ignoring): {}", e);
                    Err(()) 
                })
                .is_ok(); // ignoring error, as this connection is already marked in error...

            // These are connection failures, not lookup failures, that is handled in the resolver layer
            future::err(error)
        }))
    }
}

impl Ord for NameServer {
    /// Custom implementation of Ord for NameServer which incorporates the performance of the connection into it's ranking
    fn cmp(&self, other: &Self) -> Ordering {
        // if they are literally equal, just return
        if self == other {
            return Ordering::Equal;
        }

        self.stats
            .lock()
            .expect("poisoned lock in NameServer::cmp")
            .cmp(&other
                      .stats
                      .lock() // TODO: hmm... deadlock potential? switch to try_lock?
                      .expect("poisoned lock in NameServer::cmp"))
    }
}

impl PartialOrd for NameServer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for NameServer {
    /// NameServers are equal if the config (connection information) are equal
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config
    }
}

impl Eq for NameServer {}

#[derive(Clone)]
pub(crate) struct NameServerPool {
    conns: BinaryHeap<NameServer>,
    options: ResolverOpts,
}

impl NameServerPool {
    pub fn from_config(config: &ResolverConfig,
                       options: &ResolverOpts,
                       reactor: Handle)
                       -> NameServerPool {
        let conns: BinaryHeap<NameServer> = config
            .name_servers()
            .iter()
            .map(|ns_config| NameServer::new(ns_config.clone(), options.clone(), reactor.clone()))
            .collect();

        NameServerPool {
            conns,
            options: options.clone(),
        }
    }
}

impl ClientHandle for NameServerPool {
    fn send(&mut self, message: Message) -> Box<Future<Item = Message, Error = ClientError>> {
        // select the highest priority connection
        let conn = self.conns.peek_mut(); // TODO: how to support parallel connections?

        if conn.is_none() {
            return Box::new(future::err(ClientErrorKind::Message("No connections available")
                                            .into()));
        }

        let mut conn = conn.unwrap();
        conn.send(message)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{SocketAddr, IpAddr, Ipv4Addr};

    use tokio_core::reactor::Core;

    use trust_dns::client::ClientHandle;
    use trust_dns::op::ResponseCode;
    use trust_dns::rr::{DNSClass, Name, RecordType};

    use config::Protocol;
    use super::*;

    #[test]
    fn test_state_cmp() {
        let init = NameServerStats {
            state: NameServerState::Init { send_edns: None },
            successes: 0,
            failures: 0,
        };

        let established = NameServerStats {
            state: NameServerState::Established { remote_edns: None },
            successes: 0,
            failures: 0,
        };

        let failed = NameServerStats {
            state: NameServerState::Failed {
                error: ClientErrorKind::Msg("test".to_string()).into(),
                when: Instant::now(),
            },
            successes: 0,
            failures: 0,
        };

        let established_successes = NameServerStats {
            state: NameServerState::Established { remote_edns: None },
            successes: 1,
            failures: 0,
        };

        let established_failed = NameServerStats {
            state: NameServerState::Established { remote_edns: None },
            successes: 0,
            failures: 1,
        };


        assert_eq!(init.cmp(&init), Ordering::Equal);
        assert_eq!(init.cmp(&established), Ordering::Greater);
        assert_eq!(established.cmp(&failed), Ordering::Greater);
        assert_eq!(established.cmp(&established_successes), Ordering::Greater);
        assert_eq!(established.cmp(&established_failed), Ordering::Greater);
    }

    #[test]
    fn test_name_server() {
        let config = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            protocol: Protocol::Udp,
        };
        let mut io_loop = Core::new().unwrap();
        let mut name_server = NameServer::new(config, ResolverOpts::default(), io_loop.handle());

        let name = Name::parse("www.example.com.", None).unwrap();
        let response = io_loop
            .run(name_server.query(name.clone(), DNSClass::IN, RecordType::A))
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
        };
        let mut io_loop = Core::new().unwrap();
        let mut name_server = NameServer::new(config, options, io_loop.handle());

        let name = Name::parse("www.example.com.", None).unwrap();
        assert!(io_loop
                    .run(name_server.query(name.clone(), DNSClass::IN, RecordType::A))
                    .is_err());
    }

    #[ignore] // because of there is a real connection that needs a reasonable timeout
    #[test]
    fn test_failed_then_success_pool() {
        let config1 = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 252)), 253),
            protocol: Protocol::Udp,
        };

        let config2 = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            protocol: Protocol::Udp,
        };

        let mut resolver_config = ResolverConfig::new();
        resolver_config.add_name_server(config1);
        resolver_config.add_name_server(config2);

        let mut io_loop = Core::new().unwrap();
        let mut pool = NameServerPool::from_config(&resolver_config,
                                                   &ResolverOpts::default(),
                                                   io_loop.handle());

        let name = Name::parse("www.example.com.", None).unwrap();

        // TODO: it's not clear why there are two failures before the
        for i in 0..2 {
            assert!(io_loop
                        .run(pool.query(name.clone(), DNSClass::IN, RecordType::A))
                        .is_err(),
                    "iter: {}",
                    i);
        }

        for i in 0..10 {
            assert!(io_loop
                        .run(pool.query(name.clone(), DNSClass::IN, RecordType::A))
                        .is_ok(),
                    "iter: {}",
                    i);
        }
    }
}