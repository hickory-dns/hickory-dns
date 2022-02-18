// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::cmp::Ordering;

use std::sync::atomic::{self, AtomicUsize};

pub(crate) struct NameServerStats {
    successes: AtomicUsize,
    failures: AtomicUsize,
    // TODO: incorporate latency
}

impl Default for NameServerStats {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

impl NameServerStats {
    pub(crate) fn new(successes: usize, failures: usize) -> Self {
        Self {
            successes: AtomicUsize::new(successes),
            failures: AtomicUsize::new(failures),
        }
    }

    pub(crate) fn next_success(&self) {
        self.successes.fetch_add(1, atomic::Ordering::Release);
    }

    pub(crate) fn next_failure(&self) {
        self.failures.fetch_add(1, atomic::Ordering::Release);
    }

    fn noload_eq(
        self_successes: usize,
        other_successes: usize,
        self_failures: usize,
        other_failures: usize,
    ) -> bool {
        self_successes == other_successes && self_failures == other_failures
    }
}

impl PartialEq for NameServerStats {
    fn eq(&self, other: &Self) -> bool {
        let self_successes = self.successes.load(atomic::Ordering::Acquire);
        let other_successes = other.successes.load(atomic::Ordering::Acquire);

        let self_failures = self.failures.load(atomic::Ordering::Acquire);
        let other_failures = other.failures.load(atomic::Ordering::Acquire);

        // if they are literally equal, just return
        Self::noload_eq(
            self_successes,
            other_successes,
            self_failures,
            other_failures,
        )
    }
}

impl Eq for NameServerStats {}

impl Ord for NameServerStats {
    /// Custom implementation of Ord for NameServer which incorporates the performance of the connection into it's ranking
    fn cmp(&self, other: &Self) -> Ordering {
        let self_successes = self.successes.load(atomic::Ordering::Acquire);
        let other_successes = other.successes.load(atomic::Ordering::Acquire);

        let self_failures = self.failures.load(atomic::Ordering::Acquire);
        let other_failures = other.failures.load(atomic::Ordering::Acquire);

        // if they are literally equal, just return
        if Self::noload_eq(
            self_successes,
            other_successes,
            self_failures,
            other_failures,
        ) {
            return Ordering::Equal;
        }

        // TODO: track latency and use lowest latency connection...

        // invert failure comparison, i.e. the one with the least failures, wins
        if self_failures <= other_failures {
            return Ordering::Greater;
        }

        // at this point we'll go with the lesser of successes to make sure there is balance
        self_successes.cmp(&other_successes)
    }
}

impl PartialOrd for NameServerStats {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_send_sync<S: Sync + Send>() -> bool {
        true
    }

    #[test]
    fn stats_are_sync() {
        assert!(is_send_sync::<NameServerStats>());
    }

    #[test]
    fn test_state_cmp() {
        let nil = NameServerStats::new(0, 0);
        let successes = NameServerStats::new(1, 0);
        let failures = NameServerStats::new(0, 1);

        assert_eq!(nil.cmp(&nil), Ordering::Equal);
        assert_eq!(nil.cmp(&successes), Ordering::Greater);
        assert_eq!(successes.cmp(&failures), Ordering::Greater);
    }
}
