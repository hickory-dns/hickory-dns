use std::cmp::Ordering;

use rr::{Name, RecordType};

/// Accessor key for RRSets in the Authority.
#[derive(Eq, PartialEq, Debug, Hash, Clone)]
pub struct RrKey {
    pub name: Name,
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
    pub fn new(name: &Name, record_type: RecordType) -> RrKey {
        RrKey {
            name: name.clone(),
            record_type: record_type,
        }
    }
}

impl PartialOrd for RrKey {
    fn partial_cmp(&self, other: &RrKey) -> Option<Ordering> {
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
