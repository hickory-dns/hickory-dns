use std::collections::BTreeMap;

use crate::{record::NSEC3, zone_file::ZoneFile};

pub struct NSEC3Records {
    records: BTreeMap<String, NSEC3>,
}

impl NSEC3Records {
    /// Extract the NSEC3 RRs from the signed zonefile and sort them by the hash embedded in the
    /// last label of each record's owner.
    pub fn new(signed_zf: &ZoneFile) -> Self {
        Self {
            records: signed_zf
                .records
                .iter()
                .cloned()
                .filter_map(|rr| {
                    let mut nsec3_rr = rr.try_into_nsec3().ok()?;
                    nsec3_rr.next_hashed_owner_name =
                        nsec3_rr.next_hashed_owner_name.to_uppercase();
                    Some((nsec3_rr.fqdn.last_label().to_uppercase(), nsec3_rr))
                })
                .collect(),
        }
    }

    ///  An NSEC3 RR is said to "match" a name if the owner name of the NSEC3 RR is the same as the
    ///  hashed owner name of that name.
    pub fn find_match<'a>(&'a self, name_hash: &str) -> Option<&'a NSEC3> {
        self.records.get(name_hash)
    }

    /// An NSEC3 RR is said to cover a name if the hash of the name or "next closer" name falls between
    /// the owner name and the next hashed owner name of the NSEC3.  In other words, if it proves the
    /// nonexistence of the name, either directly or by proving the nonexistence of an ancestor of the
    /// name.
    pub fn find_cover<'a>(&'a self, name_hash: &str) -> Option<&'a NSEC3> {
        let (hash, candidate) = self
            .records
            // Find the greater hash that is less or equal than the name's hash.
            .range(..=name_hash.to_owned())
            .last()
            // If no value is less or equal than the name's hash, it means that the name's hash is out
            // of range and the last record covers it.
            .or_else(|| self.records.last_key_value())?;

        // If the found hash is exactly the name's hash, return None as it wouldn't be proving its
        // nonexistence. Otherwise return the RR with that hash.
        (hash != name_hash).then_some(candidate)
    }

    /// This proof consists of (up to) two different NSEC3 RRs:
    /// - An NSEC3 RR that matches the closest (provable) encloser.
    /// - An NSEC3 RR that covers the "next closer" name to the closest encloser.
    pub fn closest_encloser_proof<'a>(
        &'a self,
        closest_encloser_hash: &str,
        next_closer_name_hash: &str,
    ) -> Option<(&'a NSEC3, &'a NSEC3)> {
        Some((
            self.find_match(closest_encloser_hash)?,
            self.find_cover(next_closer_name_hash)?,
        ))
    }
}
