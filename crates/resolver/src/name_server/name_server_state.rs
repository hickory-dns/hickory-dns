// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::cmp::Ordering;
use std::sync::atomic::{self, AtomicU8};
use std::sync::Arc;
use std::time::Instant;

use futures_util::lock::Mutex;
use proto::op::Edns;

pub(crate) struct NameServerState {
    conn_state: AtomicU8,
    remote_edns: Mutex<Arc<Option<Edns>>>,
}

/// State of a connection with a remote NameServer.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[repr(u8)]
enum NameServerStateInner {
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

impl From<NameServerStateInner> for u8 {
    /// used for ordering purposes. The highest priority is placed on open connections
    fn from(val: NameServerStateInner) -> Self {
        val as Self
    }
}

impl From<u8> for NameServerStateInner {
    fn from(val: u8) -> Self {
        match val {
            2 => Self::Established,
            1 => Self::Init,
            _ => Self::Failed,
        }
    }
}

impl NameServerState {
    fn store(&self, conn_state: NameServerStateInner) {
        self.conn_state
            .store(conn_state.into(), atomic::Ordering::Release);
    }

    fn load(&self) -> NameServerStateInner {
        NameServerStateInner::from(self.conn_state.load(atomic::Ordering::Acquire))
    }

    /// Set at the new Init state
    ///
    /// If send_dns is some, this will be sent on the first request when it is established
    pub(crate) fn init(_send_edns: Option<Edns>) -> Self {
        // TODO: need to track send_edns
        Self {
            conn_state: AtomicU8::new(NameServerStateInner::Init.into()),
            remote_edns: Mutex::new(Arc::new(None)),
        }
    }

    /// Set at the new Init state
    ///
    /// If send_dns is some, this will be sent on the first request when it is established
    pub(crate) fn reinit(&self, _send_edns: Option<Edns>) {
        // eventually do this
        // self.send_edns.lock() = send_edns;

        self.store(NameServerStateInner::Init);
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

        self.store(NameServerStateInner::Established);
    }

    /// transition to the Failed state
    ///
    /// when is the time of the failure
    ///
    /// * when - deprecated
    pub(crate) fn fail(&self, _when: /* FIXME: remove in 0.20 */ Instant) {
        self.store(NameServerStateInner::Failed);
    }

    /// True if this is in the Failed state
    pub(crate) fn is_failed(&self) -> bool {
        NameServerStateInner::Failed == self.load()
    }
}

impl Ord for NameServerStateInner {
    fn cmp(&self, other: &Self) -> Ordering {
        let (self_num, other_num) = (u8::from(*self), u8::from(*other));
        self_num.cmp(&other_num)
    }
}

impl PartialOrd for NameServerStateInner {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NameServerState {
    fn cmp(&self, other: &Self) -> Ordering {
        let other = other.load();
        self.load().cmp(&other)
    }
}

impl PartialOrd for NameServerState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for NameServerState {
    fn eq(&self, other: &Self) -> bool {
        self.load() == other.load()
    }
}

impl Eq for NameServerState {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name_server::NameServerState;

    #[test]
    fn test_state_cmp() {
        let init = NameServerState::init(None);

        let established = NameServerState::init(None);
        established.establish(None);

        let failed = NameServerState::init(None);
        failed.fail(Instant::now());

        assert_eq!(init.cmp(&init), Ordering::Equal);
        assert_eq!(init.cmp(&established), Ordering::Less);
        assert_eq!(init.cmp(&failed), Ordering::Greater);
        assert_eq!(established.cmp(&established), Ordering::Equal);
        assert_eq!(established.cmp(&failed), Ordering::Greater);
        assert_eq!(failed.cmp(&failed), Ordering::Equal);
    }
}
