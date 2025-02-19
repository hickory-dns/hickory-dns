// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::cmp::Ordering;

use crate::rr::{LowerName, RecordType};

/// Accessor key for RRSets in the Authority.
#[derive(Eq, PartialEq, Debug, Hash, Clone)]
pub struct RrKey {
    /// Matches the name in the Record of this key
    pub name: LowerName,
    /// Matches the type of the Record of this key
    pub record_type: RecordType,
}

impl RrKey {
    /// Creates a new key to access the Authority.
    ///
    /// # Arguments
    ///
    /// * `name` - domain name to lookup.
    /// * `record_type` - the `RecordType` to lookup.
    ///
    /// # Return value
    ///
    /// A new key to access the Authorities.
    /// TODO: make all cloned params pass by value.
    pub fn new(name: LowerName, record_type: RecordType) -> Self {
        Self { name, record_type }
    }

    /// Returns the name of the key
    pub fn name(&self) -> &LowerName {
        &self.name
    }
}

impl PartialOrd for RrKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RrKey {
    fn cmp(&self, other: &Self) -> Ordering {
        let order = self.name.cmp(&other.name);
        if order == Ordering::Equal {
            self.record_type.cmp(&other.record_type)
        } else {
            order
        }
    }
}
