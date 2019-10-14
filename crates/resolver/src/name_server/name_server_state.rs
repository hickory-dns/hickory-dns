// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::cmp::Ordering;
use std::sync::RwLock;
use std::time::Instant;

use proto::op::Edns;

pub struct NameServerState(RwLock<NameServerStateInner>);

/// State of a connection with a remote NameServer.
#[derive(Debug)]
enum NameServerStateInner {
    /// Initial state, if Edns is not none, then Edns will be requested
    Init { send_edns: Option<Edns> },
    /// There has been successful communication with the remote.
    ///  if no Edns is associated, then the remote does not support Edns
    Established { remote_edns: Option<Edns> },
    /// For some reason the connection failed. For UDP this would generally be a timeout
    ///  for TCP this could be either Connection could never be established, or it
    ///  failed at some point after. The Failed state should *not* be entered due to an
    ///  error contained in a Message received from the server. In All cases to reestablish
    ///  a new connection will need to be created.
    Failed { when: Instant },
}

impl NameServerStateInner {
    /// used for ordering purposes. The highest priority is placed on open connections
    fn to_usize(&self) -> usize {
        match *self {
            NameServerStateInner::Init { .. } => 2,
            NameServerStateInner::Established { .. } => 3,
            NameServerStateInner::Failed { .. } => 1,
        }
    }
}

impl NameServerState {
    /// Set at the new Init state
    ///
    /// If send_dns is some, this will be sent on the first request when it is established
    pub fn init(send_edns: Option<Edns>) -> Self {
        NameServerState(RwLock::new(NameServerStateInner::Init { send_edns }))
    }

    /// Transition to the Established state
    ///
    /// If remote_edns is Some, then it will be used to effect things like buffer sizes based on
    ///   the remote's support.
    pub fn establish(&self, remote_edns: Option<Edns>) {
        let mut state = self.0.write().expect("poisoned lock");
        *state = NameServerStateInner::Established { remote_edns };
    }

    /// transition to the Failed state
    ///
    /// when is the time of the failure
    pub fn fail(&self, when: Instant) {
        let mut state = self.0.write().expect("poisoned lock");
        *state = NameServerStateInner::Failed { when };
    }

    /// True if this is in the Failed state
    pub(crate) fn is_failed(&self) -> bool {
        if let NameServerStateInner::Failed { .. } = *self.0.read().expect("poisoned lock") {
            true
        } else {
            false
        }
    }
}

impl Ord for NameServerStateInner {
    fn cmp(&self, other: &Self) -> Ordering {
        let (self_num, other_num) = (self.to_usize(), other.to_usize());
        match self_num.cmp(&other_num) {
            Ordering::Equal => match (self, other) {
                (
                    NameServerStateInner::Failed {
                        when: ref self_when,
                    },
                    NameServerStateInner::Failed {
                        when: ref other_when,
                    },
                ) => {
                    // We reverse, because we want the "older" failures to be tried first...
                    self_when.cmp(other_when).reverse()
                }
                _ => Ordering::Equal,
            },
            cmp => cmp,
        }
    }
}

impl PartialOrd for NameServerStateInner {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for NameServerStateInner {
    fn eq(&self, other: &Self) -> bool {
        self.to_usize() == other.to_usize()
    }
}

impl Eq for NameServerStateInner {}

impl Ord for NameServerState {
    fn cmp(&self, other: &Self) -> Ordering {
        let other = other.0.read().expect("other poisoned");
        self.0.read().expect("self poisoned").cmp(&*other)
    }
}

impl PartialOrd for NameServerState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for NameServerState {
    fn eq(&self, other: &Self) -> bool {
        self.0.read().expect("self poisoned").to_usize()
            == other.0.read().expect("self poisoned").to_usize()
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

        let established = NameServerState(RwLock::new(NameServerStateInner::Established {
            remote_edns: None,
        }));

        let failed = NameServerState(RwLock::new(NameServerStateInner::Failed {
            when: Instant::now(),
        }));

        assert_eq!(init.cmp(&init), Ordering::Equal);
        assert_eq!(init.cmp(&established), Ordering::Less);
        assert_eq!(init.cmp(&failed), Ordering::Greater);
        assert_eq!(established.cmp(&established), Ordering::Equal);
        assert_eq!(established.cmp(&failed), Ordering::Greater);
        assert_eq!(failed.cmp(&failed), Ordering::Equal);
    }
}
