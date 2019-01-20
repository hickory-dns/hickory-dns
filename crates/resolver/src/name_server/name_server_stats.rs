// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::cmp::Ordering;
use std::time::Instant;

use proto::error::ProtoError;
use proto::op::Edns;

/// State of a connection with a remote NameServer.
#[derive(Clone, Debug)]
pub(crate) enum NameServerState {
    /// Initial state, if Edns is not none, then Edns will be requested
    Init { send_edns: Option<Edns> },
    /// There has been successful communication with the remote.
    ///  if no Edns is associated, then the remote does not support Edns
    Established { remote_edns: Option<Edns> },
    /// For some reason the connection failed. For UDP this would generally be a timeout
    ///  for TCP this could be either Connection could never be established, or it
    ///  failed at some point after. The Failed state should *not* be entered due to an
    ///  error contained in a Message recieved from the server. In All cases to reestablish
    ///  a new connection will need to be created.
    Failed { when: Instant },
}

impl NameServerState {
    /// used for ordering purposes. The highest priority is placed on open connections
    fn to_usize(&self) -> usize {
        match *self {
            NameServerState::Init { .. } => 2,
            NameServerState::Established { .. } => 3,
            NameServerState::Failed { .. } => 1,
        }
    }
}

impl Ord for NameServerState {
    fn cmp(&self, other: &Self) -> Ordering {
        let (self_num, other_num) = (self.to_usize(), other.to_usize());
        match self_num.cmp(&other_num) {
            Ordering::Equal => match (self, other) {
                (
                    NameServerState::Failed {
                        when: ref self_when,
                    },
                    NameServerState::Failed {
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
pub(crate) struct NameServerStats {
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
    pub fn init(send_edns: Option<Edns>, successes: usize, failures: usize) -> Self {
        NameServerStats {
            state: NameServerState::Init { send_edns },
            successes,
            failures,
            // TODO: incorporate latency
        }
    }

    pub fn state(&self) -> &NameServerState {
        &self.state
    }

    pub fn successes(&self) -> usize {
        self.successes
    }

    pub fn failures(&self) -> usize {
        self.failures
    }

    pub fn next_success(&mut self, remote_edns: Option<Edns>) {
        self.successes += 1;

        // update current state

        if remote_edns.is_some() {
            self.state = NameServerState::Established { remote_edns };;
        } else {
            // preserve existing EDNS if it exists
            let remote_edns = if let NameServerState::Established { ref remote_edns } = self.state {
                remote_edns.clone()
            } else {
                None
            };

            self.state = NameServerState::Established { remote_edns };
        };
    }

    pub fn next_failure(&mut self, error: ProtoError, when: Instant) {
        self.failures += 1;
        debug!("name_server connection failure: {}", error);

        // update current state
        self.state = NameServerState::Failed { when };
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
        //   this will prefer established connections, we should try other connections after
        //   some number to make sure that all are used. This is more important for when
        //   letency is started to be used.
        match self.state.cmp(&other.state) {
            Ordering::Equal => (),
            o => {
                return o;
            }
        }

        // TODO: track latency and use lowest latency connection...

        // invert failure comparison, i.e. the one with the least failures, wins
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

#[cfg(test)]
mod tests {
    extern crate env_logger;

    use super::*;
    use name_server::NameServerState;

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
        assert_eq!(init.cmp(&established), Ordering::Less);
        assert_eq!(established.cmp(&failed), Ordering::Greater);
        assert_eq!(established.cmp(&established_successes), Ordering::Greater);
        assert_eq!(established.cmp(&established_failed), Ordering::Greater);
    }
}
