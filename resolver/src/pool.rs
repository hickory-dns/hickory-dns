// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::BinaryHeap;
use std::io;
use std::time::Duration;

use futures::{Future, Sink};

use trust_dns::error::*;
use trust_dns::client::{BasicClientHandle, ClientHandle};
use trust_dns::op::{Edns, Message};

use config::{NameServerConfig, ResolverConfig, ResolverOpts};

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
    ///  failed at somepoint after. The Failed state should not be entered due to the
    ///  error contained in a Message recieved from the server.
    Failed { error: ClientError, chrono: Duration },
}

#[derive(Clone)]
pub(crate) struct NameServer {
    config: NameServerConfig,
    client: BasicClientHandle,
    state: NameServerState,
    successes: usize,
    failures: usize,
}

impl NameServer {
    pub fn new(config: NameServerConfig) -> Self {
        unimplemented!()
    }
}

impl ClientHandle for NameServer {
    fn send(&mut self, message: Message) -> Box<Future<Item = Message, Error = ClientError>> {
        self.client.send(message)
    }
}

#[derive(Clone)]
pub(crate) struct NameServerPool {
    conns: BinaryHeap<NameServer>,
}

impl NameServerPool {
    pub fn from_config(config: &ResolverConfig, opts: &ResolverOpts) -> NameServerPool {
        for ns_config in config.name_servers() {}

        unimplemented!()
    }
}

impl ClientHandle for NameServerPool {
    fn send(&mut self, message: Message) -> Box<Future<Item = Message, Error = ClientError>> {
        // select the highest priority connection

        unimplemented!()
    }
}