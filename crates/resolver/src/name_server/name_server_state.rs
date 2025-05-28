// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::proto::op::Edns;
use futures_util::lock::Mutex;

pub(crate) struct NameServerState {
    conn_state: AtomicU8,
    remote_edns: Mutex<Arc<Option<Edns>>>,
}

impl NameServerState {
    fn store(&self, conn_state: ConnectionState) {
        self.conn_state.store(conn_state.into(), Ordering::Release);
    }

    fn load(&self) -> ConnectionState {
        ConnectionState::from(self.conn_state.load(Ordering::Acquire))
    }

    /// Set at the new Init state
    ///
    /// If send_dns is some, this will be sent on the first request when it is established
    pub(crate) fn reinit(&self, _send_edns: Option<Edns>) {
        // eventually do this
        // self.send_edns.lock() = send_edns;

        self.store(ConnectionState::Init);
    }

    /// Transition to the Established state
    ///
    /// If remote_edns is Some, then it will be used to effect things like buffer sizes based on
    ///   the remote's support.
    pub(crate) fn establish(&self, remote_edns: Option<Edns>) {
        if remote_edns.is_some() {
            // best effort locking, we'll assume a different user of this connection is storing the same thing...
            if let Some(mut current_edns) = self.remote_edns.try_lock() {
                *current_edns = Arc::new(remote_edns)
            }
        }

        self.store(ConnectionState::Established);
    }

    /// transition to the Failed state
    ///
    /// when is the time of the failure
    pub(crate) fn fail(&self) {
        self.store(ConnectionState::Failed);
    }

    /// True if this is in the Failed state
    pub(crate) fn is_failed(&self) -> bool {
        ConnectionState::Failed == self.load()
    }
}

impl Default for NameServerState {
    fn default() -> Self {
        Self {
            conn_state: AtomicU8::new(ConnectionState::Init.into()),
            remote_edns: Mutex::new(Arc::new(None)),
        }
    }
}

/// State of a connection with a remote NameServer.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[repr(u8)]
enum ConnectionState {
    /// For some reason the connection failed. For UDP this would generally be a timeout
    ///  for TCP this could be either Connection could never be established, or it
    ///  failed at some point after. The Failed state should *not* be entered due to an
    ///  error contained in a Message received from the server. In All cases to reestablish
    ///  a new connection will need to be created.
    Failed = 0,
    /// Initial state, if Edns is not none, then Edns will be requested
    Init = 1,
    /// There has been successful communication with the remote.
    ///  if no Edns is associated, then the remote does not support Edns
    Established = 2,
}

impl From<ConnectionState> for u8 {
    /// used for ordering purposes. The highest priority is placed on open connections
    fn from(val: ConnectionState) -> Self {
        val as Self
    }
}

impl From<u8> for ConnectionState {
    fn from(val: u8) -> Self {
        match val {
            2 => Self::Established,
            1 => Self::Init,
            _ => Self::Failed,
        }
    }
}
