// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::cmp::Ordering;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct NameServerStats {
    successes: usize,
    failures: usize,
}

impl Default for NameServerStats {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

impl NameServerStats {
    pub fn new(successes: usize, failures: usize) -> Self {
        NameServerStats {
            successes,
            failures,
            // TODO: incorporate latency
        }
    }

    pub fn next_success(&mut self) {
        self.successes += 1;
   }

    pub fn next_failure(&mut self) {
        self.failures += 1;
    }
}

impl Ord for NameServerStats {
    /// Custom implementation of Ord for NameServer which incorporates the performance of the connection into it's ranking
    fn cmp(&self, other: &Self) -> Ordering {
        // if they are literally equal, just return
        if self == other {
            return Ordering::Equal;
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

    #[test]
    fn test_state_cmp() {
        let nil = NameServerStats {
            successes: 0,
            failures: 0,
        };

        let successes = NameServerStats {
            successes: 1,
            failures: 0,
        };

        let failures = NameServerStats {
            successes: 0,
            failures: 1,
        };

        assert_eq!(nil.cmp(&nil), Ordering::Equal);
        assert_eq!(nil.cmp(&successes), Ordering::Greater);
        assert_eq!(successes.cmp(&failures), Ordering::Greater);
    }
}
