use core::{
    clone::Clone,
    hash::{Hash, Hasher},
};
use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    ops::{Deref, DerefMut},
};

use tracing::{debug, warn};

use crate::{
    dnssec::{
        MAX_KEY_TAG_COLLISIONS, ProofError, ProofErrorKind, ValidationCacheKey,
        nsec::ZoneNsecRecords, nsec3::ZoneNsec3Records,
    },
    proto::{
        dnssec::{
            Proof, Verifier,
            rdata::{DNSKEY, DNSSECRData, RRSIG},
        },
        op::{DnsRequestOptions, DnsResponse, Query},
        rr::{
            DNSClass, Label, LowerName, Name, RData, Record, RecordRef, RecordType, RrKey,
            SerialNumber,
        },
    },
};

pub(super) struct RrsetVerificationContext<'a> {
    pub(super) query: &'a Query,
    pub(super) key: &'a RrKey,
    pub(super) rrset: &'a Rrset<'a>,
    pub(super) options: DnsRequestOptions,
    pub(super) current_time: u32,
}

impl<'a> RrsetVerificationContext<'a> {
    pub(super) fn verify_rrsig_with_keys(
        &self,
        dnskey_message: DnsResponse,
        rrsig: &RecordRef<'_, RRSIG>,
    ) -> Option<(Proof, Option<u32>)> {
        let mut tag_count = HashMap::<u16, usize>::new();

        if (self.key.record_type == RecordType::NSEC || self.key.record_type == RecordType::NSEC3)
            && self.key.name.num_labels() != rrsig.data().input().num_labels
        {
            warn!(
                rrset_name = ?self.key.name,
                rrset_type = ?self.key.record_type,
                "record signature claims to be expanded from a wildcard",
            );
            return None;
        }
        if self.key.record_type == RecordType::NSEC3
            && self.key.name.base_name().deref() != &rrsig.data().input().signer_name
        {
            warn!(
                name = %self.key.name,
                signer_name = %rrsig.data().input().signer_name,
                "NSEC3 record name is malformed"
            );
            return None;
        }

        // DNSKEYs were already validated by the inner query in the above lookup
        let dnskeys = dnskey_message.answers.iter().filter_map(|r| {
            let dnskey = r.try_borrow::<DNSKEY>()?;

            let tag = match dnskey.data().calculate_key_tag() {
                Ok(tag) => tag,
                Err(e) => {
                    warn!("unable to calculate key tag: {e:?}; skipping key");
                    return None;
                }
            };

            match tag_count.get_mut(&tag) {
                Some(n_keys) => {
                    *n_keys += 1;
                    if *n_keys > MAX_KEY_TAG_COLLISIONS {
                        warn!("too many ({n_keys}) DNSKEYs with key tag {tag}; skipping");
                        return None;
                    }
                }
                None => _ = tag_count.insert(tag, 1),
            }

            Some(dnskey)
        });

        let mut all_insecure = None;
        for dnskey in dnskeys {
            match dnskey.proof() {
                Proof::Secure => {
                    all_insecure = Some(false);
                    if let Ok(proof) = self.verify_with_dnskey(dnskey, dnskey.proof(), rrsig) {
                        return Some((proof.0, proof.1));
                    }
                }
                Proof::Insecure => {
                    all_insecure.get_or_insert(true);
                }
                _ => all_insecure = Some(false),
            }
        }

        if all_insecure.unwrap_or(false) {
            // inherit Insecure state
            Some((Proof::Insecure, None))
        } else {
            None
        }
    }

    /// Verifies the given signature over the RRset with the given DNSKEY.
    pub(super) fn verify_with_dnskey(
        &self,
        dnskey: RecordRef<'_, DNSKEY>,
        dnskey_proof: Proof,
        rrsig: &RecordRef<'_, RRSIG>,
    ) -> Result<(Proof, Option<u32>), ProofError> {
        match dnskey_proof {
            Proof::Secure => (),
            proof => {
                debug!("insecure dnskey {} {}", dnskey.name(), dnskey.data());
                return Err(ProofError::new(
                    proof,
                    ProofErrorKind::InsecureDnsKey {
                        name: dnskey.name().clone(),
                        key_tag: rrsig.data().input().key_tag,
                    },
                ));
            }
        }

        if dnskey.data().revoke() {
            debug!("revoked dnskey {} {}", dnskey.name(), dnskey.data());
            return Err(ProofError::new(
                Proof::Bogus,
                ProofErrorKind::DnsKeyRevoked {
                    name: dnskey.name().clone(),
                    key_tag: rrsig.data().input().key_tag,
                },
            ));
        } // TODO: does this need to be validated? RFC 5011
        if !dnskey.data().zone_key() {
            return Err(ProofError::new(
                Proof::Bogus,
                ProofErrorKind::NotZoneDnsKey {
                    name: dnskey.name().clone(),
                    key_tag: rrsig.data().input().key_tag,
                },
            ));
        }
        if dnskey.data().algorithm() != rrsig.data().input().algorithm {
            return Err(ProofError::new(
                Proof::Bogus,
                ProofErrorKind::AlgorithmMismatch {
                    rrsig: rrsig.data().input().algorithm,
                    dnskey: dnskey.data().algorithm(),
                },
            ));
        }

        let validity = self.validity(*rrsig, dnskey);
        if !matches!(validity, RrsigValidity::ValidRrsig) {
            // TODO better error handling when the error payload is not immediately discarded by
            // the caller
            return Err(ProofError::new(
                Proof::Bogus,
                ProofErrorKind::Msg(format!("{validity:?}")),
            ));
        }

        let Some(first_record) = self.rrset.records.first() else {
            debug!(
                rrset_name = ?self.key.name,
                rrset_type = ?self.key.record_type,
                "unable to validate record: no record in rrset",
            );
            return Ok((Proof::Bogus, None));
        };

        if rrsig.dns_class() != DNSClass::IN {
            debug!(
                rrset_name = ?self.key.name,
                rrset_type = ?self.key.record_type,
                class = ?rrsig.dns_class(),
                "ignoring RRSIG with class other than IN"
            );
            return Err(ProofError::new(
                Proof::Bogus,
                ProofErrorKind::Msg("RRSIG record has unsupported class".to_string()),
            ));
        }
        let result = dnskey.data().verify_rrsig(
            &self.key.name,
            DNSClass::IN,
            rrsig.data(),
            self.rrset.records.iter().map(|record| &**record),
        );
        match result {
            Ok(_) => {
                debug!(
                    rrset_name = ?self.key.name,
                    rrset_type = ?self.key.record_type,
                    dnskey_name = ?dnskey.name(),
                    dnskey_data = ?dnskey.data(),
                    "validated rrset with dnskey",
                );
                Ok((
                    Proof::Secure,
                    Some(
                        rrsig
                            .data()
                            .authenticated_ttl(first_record, self.current_time),
                    ),
                ))
            }
            Err(e) => {
                debug!(
                    rrset_name = ?self.key.name,
                    rrset_type = ?self.key.record_type,
                    dnskey_name = ?dnskey.name(),
                    dnskey_data = ?dnskey.data(),
                    "failed rrset validation",
                );
                Err(ProofError::new(
                    Proof::Bogus,
                    ProofErrorKind::DnsKeyVerifyRrsig {
                        name: dnskey.name().clone(),
                        key_tag: rrsig.data().input().key_tag,
                        error: e,
                    },
                ))
            }
        }
    }

    // see section 5.3.1 of RFC4035 "Checking the RRSIG RR Validity"
    fn validity(
        &self,
        rrsig: RecordRef<'_, RRSIG>,
        dnskey: RecordRef<'_, DNSKEY>,
    ) -> RrsigValidity {
        let Ok(dnskey_key_tag) = dnskey.data().calculate_key_tag() else {
            return RrsigValidity::WrongDnskey;
        };

        // "The RRSIG RR and the RRset MUST have the same owner name and the same class"
        for record in self.rrset.records.iter() {
            if record.dns_class != DNSClass::IN {
                return RrsigValidity::WrongRrsig;
            }
        }

        let current_time = SerialNumber::new(self.current_time);
        let sig_input = rrsig.data().input();
        if !(
            // "The RRSIG RR and the RRset MUST have the same owner name and the same class"
            *rrsig.name() == **self.key.name() &&

            // "The RRSIG RR's Signer's Name field MUST be the name of the zone that contains the
            // RRset"
            sig_input.signer_name.zone_of(self.key.name()) &&

            // "The RRSIG RR's Type Covered field MUST equal the RRset's type"
            sig_input.type_covered == self.key.record_type &&

            // "The number of labels in the RRset owner name MUST be greater than or equal to the
            // value in the RRSIG RR's Labels field"
            self.key.name.num_labels() >= sig_input.num_labels
        ) {
            return RrsigValidity::WrongRrsig;
        }

        // Section 3.1.5 of RFC4034 states that 'all comparisons involving these fields MUST use
        // "Serial number arithmetic", as defined in RFC1982'
        if !(
            // "The validator's notion of the current time MUST be less than or equal to the time
            // listed in the RRSIG RR's Expiration field"
            current_time <= sig_input.sig_expiration &&

            // "The validator's notion of the current time MUST be greater than or equal to the
            // time listed in the RRSIG RR's Inception field"
            current_time >= sig_input.sig_inception
        ) {
            return RrsigValidity::ExpiredRrsig;
        }

        if !(
            // "The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST match the owner name,
            // algorithm, and key tag for some DNSKEY RR in the zone's apex DNSKEY RRset"
            &sig_input.signer_name == dnskey.name() &&
            sig_input.algorithm == dnskey.data().algorithm() &&
            sig_input.key_tag == dnskey_key_tag &&
            // "The matching DNSKEY RR MUST be present in the zone's apex DNSKEY RRset, and MUST have the
            // Zone Flag bit (DNSKEY RDATA Flag bit 7) set"
            dnskey.data().zone_key()
        ) {
            return RrsigValidity::WrongDnskey;
        }

        if !(sig_input.num_labels >= dnskey.name().num_labels()) {
            // If the RRSIG claims to be over a wildcard name, it must still be within the zone.
            //
            // See https://indico.dns-oarc.net/event/58/contributions/1255/, slide 25 onward.
            return RrsigValidity::WrongDnskey;
        }

        RrsigValidity::ValidRrsig
    }

    // Build a cache lookup key based on the query, rrset, and rrsigs contents, minus the TTLs
    // for each, since the recursor cache will return an adjusted TTL for each request and
    // cause cache misses.
    pub(super) fn key(&self) -> ValidationCacheKey {
        let mut hasher = DefaultHasher::new();
        self.query.name.hash(&mut hasher);
        self.query.query_class.hash(&mut hasher);
        self.query.query_type.hash(&mut hasher);
        self.key.name.hash(&mut hasher);
        self.key.record_type.hash(&mut hasher);

        for rec in self.rrset.records.iter() {
            rec.name.hash(&mut hasher);
            rec.dns_class.hash(&mut hasher);
            rec.data.hash(&mut hasher);
        }
        for rec in self.rrset.signatures.iter() {
            rec.name.hash(&mut hasher);
            rec.dns_class.hash(&mut hasher);
            rec.data.hash(&mut hasher);
        }

        ValidationCacheKey(hasher.finish(), self.query.clone())
    }
}

/// A collection of RRsets that have had their signatures verified.
#[derive(Default)]
pub(super) struct VerifiedRrsetMap<'a>(pub(super) HashMap<RrKey, VerifiedRrset<'a>>);

impl<'a> VerifiedRrsetMap<'a> {
    /// Make a copy of all NSEC record sets, organized by zone.
    pub(super) fn gather_nsec_records(&self) -> HashMap<Name, ZoneNsecRecords> {
        let mut zones: HashMap<Name, ZoneNsecRecords> = HashMap::new();
        for (key, rrset) in self.iter() {
            if key.record_type != RecordType::NSEC {
                continue;
            }
            let RrsigVerificationOutcome::Secure { rrsig } = &rrset.outcome else {
                continue;
            };
            if !rrsig.input().signer_name.zone_of(&key.name) {
                warn!(
                    nsec_name = %key.name,
                    signer_name = %rrsig.input().signer_name,
                    "ignoring NSEC record outside of signer's zone"
                );
                continue;
            }
            if key.name.num_labels() != rrsig.input().num_labels {
                warn!(
                    nsec_name = %key.name,
                    num_labels = rrsig.input().num_labels,
                    "ignoring NSEC record with name expanded from wildcard"
                );
                continue;
            }
            let zone_name = rrsig.input().signer_name.clone();
            let zone = zones
                .entry(zone_name.clone())
                .or_insert_with(|| ZoneNsecRecords::new(zone_name));
            for record in rrset.records.iter() {
                let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = &record.data else {
                    continue;
                };
                zone.push(key.name.clone(), nsec.clone());
            }
        }
        zones
    }

    /// Make a copy of all NSEC3 record sets, organized by zone.
    pub(super) fn gather_nsec3_records(&self) -> HashMap<Name, ZoneNsec3Records> {
        let mut zones: HashMap<Name, ZoneNsec3Records> = HashMap::new();
        for (key, rrset) in self.iter() {
            if key.record_type != RecordType::NSEC3 {
                continue;
            }
            let RrsigVerificationOutcome::Secure { rrsig } = &rrset.outcome else {
                continue;
            };
            // Ignore NSEC3 records from outside the RRSIG signer's zone, and ignore NSEC3 records
            // with names that have extra labels.
            if !rrsig.input().signer_name.zone_of(&key.name)
                || key.name.num_labels() != rrsig.input().signer_name.num_labels() + 1
            {
                warn!(
                    nsec3_name = %key.name,
                    signer_name = %rrsig.input().signer_name,
                    "ignoring NSEC3 record with invalid name"
                );
                continue;
            }
            let zone_name = rrsig.input().signer_name.clone();
            let zone = zones
                .entry(zone_name.clone())
                .or_insert_with(|| ZoneNsec3Records::new(zone_name));
            for record in rrset.records.iter() {
                let RData::DNSSEC(DNSSECRData::NSEC3(nsec3)) = &record.data else {
                    continue;
                };
                let Some(first_label) = key.name.iter().next() else {
                    continue;
                };
                // Unwrap safety: this label came from a `Name`, so it must be valid.
                let label = Label::from_raw_bytes(first_label).unwrap();
                zone.push(label, nsec3.clone());
            }
        }
        zones
    }

    /// Check if wildcard expansion was performed correctly on each RRset.
    ///
    /// For each RRset that was expanded from an RRset with a wildcard name, this determines if the
    /// correct wildcard was used to produce the response, by confirming that the next closer name
    /// does not exist. If wildcard expansion cannot be validated, the RRset will be marked as
    /// bogus.
    ///
    /// Returns true if all RRsets pass verification.
    pub(super) fn verify_wildcard_expansion(
        &mut self,
        nsec_records: &HashMap<Name, ZoneNsecRecords>,
        nsec3_records: &HashMap<Name, ZoneNsec3Records>,
    ) -> bool {
        let mut all_valid = true;
        for (key, rrset) in self.iter_mut() {
            let RrsigVerificationOutcome::Secure { rrsig } = &rrset.outcome else {
                continue;
            };
            if rrsig.input().num_labels == key.name.num_labels() {
                // No wildcard expansion performed.
                continue;
            }
            if rrsig.input().num_labels > key.name.num_labels() {
                return false;
            }

            // Check for a nonexistence proof of the next closer name. We are looking for a name
            // that's a sibling to the wildcard name.
            let num_labels = rrsig.input().num_labels as usize;
            let next_closer = LowerName::from(key.name.trim_to(num_labels + 1));
            let zone = &rrsig.input().signer_name;

            let nsec_proof_valid = nsec_records
                .get(zone)
                .and_then(|nsec_records| nsec_records.find_covering_record(&next_closer))
                .is_some_and(|covering_nsec| {
                    if &*covering_nsec.name < covering_nsec.rdata.next_domain_name() {
                        // Check if the next closer name is an empty non-terminal name.
                        !next_closer
                            .deref()
                            .zone_of(covering_nsec.rdata.next_domain_name())
                    } else {
                        // This is a wraparound NSEC record, so the next closer name is definitely
                        // not an empty non-terminal name.
                        true
                    }
                });

            let nsec3_proof_valid = nsec3_records.get(zone).is_some_and(|nsec3_records| {
                nsec3_records
                    .compute_all_nsec3_hashes(&next_closer)
                    .iter()
                    .any(|hashed_name| nsec3_records.covers(hashed_name))
            });

            if !nsec_proof_valid && !nsec3_proof_valid {
                warn!(
                    name = %key.name,
                    wildcard_name = key
                        .name
                        .trim_to(num_labels)
                        .prepend_label("*")
                        .map(|name| name.to_string())
                        .unwrap_or_else(|_| "could not construct wildcard name".to_string()),
                    "no valid next closer name nonexistence proof accompanying wildcard record"
                );
                rrset.outcome = RrsigVerificationOutcome::Bogus;
                for record in rrset.records.iter_mut() {
                    record.proof = Proof::Bogus;
                }
                all_valid = false;
            }
        }
        all_valid
    }
}

impl<'a> Deref for VerifiedRrsetMap<'a> {
    type Target = HashMap<RrKey, VerifiedRrset<'a>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> DerefMut for VerifiedRrsetMap<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// A collection of RRsets, with mutable access to the underlying records.
pub(super) struct RrsetMap<'a>(pub(super) HashMap<RrKey, Rrset<'a>>);

impl<'a> RrsetMap<'a> {
    /// Splits records into RRsets.
    pub(super) fn new(records: &'a mut [Record]) -> Self {
        let mut map = HashMap::<RrKey, Rrset<'_>>::new();
        for record in records.iter_mut() {
            let (is_rrsig, record_type) = match &record.data {
                RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => (true, rrsig.input().type_covered),
                _ => (false, record.record_type()),
            };

            let rrset = map
                .entry(RrKey::new(LowerName::new(&record.name), record_type))
                .or_default();
            match is_rrsig {
                true => &mut rrset.signatures,
                false => &mut rrset.records,
            }
            .push(record);
        }
        Self(map)
    }
}

impl<'a> Deref for RrsetMap<'a> {
    type Target = HashMap<RrKey, Rrset<'a>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> DerefMut for RrsetMap<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Represents an RRset as a collection of mutable references to [`Record`]s.
#[derive(Default)]
pub(super) struct Rrset<'a> {
    pub(super) records: Vec<&'a mut Record>,
    pub(super) signatures: Vec<&'a mut Record>,
}

impl<'a> Rrset<'a> {
    /// Updates the RRset with verification results and produces a `VerifiedRrset`.
    pub(super) fn verified(
        mut self,
        result: Result<RrsetProof, ProofError>,
        name: &LowerName,
        record_type: RecordType,
    ) -> VerifiedRrset<'a> {
        let proof = match result {
            Ok(proof) => {
                debug!("verified: {name} record_type: {record_type}");
                proof
            }
            Err(err) => {
                match err.kind() {
                    ProofErrorKind::DsResponseInsecure { .. } => {
                        debug!("verified insecure {name}/{record_type}")
                    }
                    kind => {
                        debug!("failed to verify: {name} record_type: {record_type}: {kind}")
                    }
                }
                RrsetProof {
                    proof: err.proof,
                    adjusted_ttl: None,
                    rrsig_index: None,
                }
            }
        };

        let RrsetProof {
            proof,
            adjusted_ttl,
            rrsig_index: rrsig_idx,
        } = proof;

        for record in self.records.iter_mut() {
            record.proof = proof;
            if let (Proof::Secure, Some(ttl)) = (proof, adjusted_ttl) {
                record.ttl = ttl;
            }
        }

        // only mark the RRSIG used for the proof
        if let Some(rrsig_idx) = rrsig_idx {
            if let Some(rrsig) = self.signatures.get_mut(rrsig_idx) {
                rrsig.proof = proof;
                if let (Proof::Secure, Some(ttl)) = (proof, adjusted_ttl) {
                    rrsig.ttl = ttl;
                }
            } else {
                warn!(
                    "bad rrsig index {rrsig_idx} rrsigs.len = {}",
                    self.signatures.len()
                );
            }
        }

        // Change from mutable references to immutable references. (This should be cheap due to
        // specialization and optimization)
        let signatures = self
            .signatures
            .into_iter()
            .map(|record| &*record)
            .collect::<Vec<_>>();

        // Combine the `Proof` from the signature verification with the RRSIG record, if it was
        // successful.
        let outcome = match (proof, rrsig_idx.and_then(|i| signatures.get(i))) {
            (
                Proof::Secure,
                Some(Record {
                    data: RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
                    ..
                }),
            ) => RrsigVerificationOutcome::Secure { rrsig },
            (Proof::Insecure, _) => RrsigVerificationOutcome::Insecure,
            (Proof::Bogus, _) | (Proof::Indeterminate, _) | (Proof::Secure, _) => {
                RrsigVerificationOutcome::Bogus
            }
        };

        VerifiedRrset {
            records: self.records,
            signatures,
            outcome,
        }
    }
}

/// An RRset, along with the results of signature verification.
pub(super) struct VerifiedRrset<'a> {
    pub(super) records: Vec<&'a mut Record>,
    pub(super) signatures: Vec<&'a Record>,
    pub(super) outcome: RrsigVerificationOutcome<'a>,
}

/// Signature verification result for an RRset.
pub(super) enum RrsigVerificationOutcome<'a> {
    Secure { rrsig: &'a RRSIG },
    Insecure,
    Bogus,
}

#[derive(Clone)]
pub(super) struct RrsetProof {
    pub(super) proof: Proof,
    pub(super) adjusted_ttl: Option<u32>,
    pub(super) rrsig_index: Option<usize>,
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
enum RrsigValidity {
    /// RRSIG has already expired
    ExpiredRrsig,
    /// RRSIG is valid
    ValidRrsig,
    /// DNSKEY does not match RRSIG
    WrongDnskey,
    /// RRSIG does not match RRset
    WrongRrsig,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::proto::{
        dnssec::{
            Algorithm, PublicKeyBuf,
            rdata::{DNSKEY as rdataDNSKEY, DNSSECRData, RRSIG as rdataRRSIG, SigInput},
        },
        op::Query,
        rr::{Name, RData, Record, RecordType::A, RrKey, SerialNumber},
    };

    use test_support::subscribe;

    #[test]
    fn rrsig_off_tree_signer_rejected() {
        subscribe();
        let (key, rrset, rrsig_rec, dnskey_rec) =
            make_rrsig_check_inputs("www.victim.hack.", "evil.hack.");
        let rrsig_ref = rrsig_rec.try_borrow::<rdataRRSIG>().unwrap();
        let dnskey_ref = dnskey_rec.try_borrow::<rdataDNSKEY>().unwrap();

        let query = Query::root();
        let context = validity_context(&query, &key, &rrset);
        assert_eq!(
            context.validity(rrsig_ref, dnskey_ref),
            RrsigValidity::WrongRrsig
        );
    }

    #[test]
    fn rrsig_zone_signer_accepted() {
        subscribe();
        let (key, rrset, rrsig_rec, dnskey_rec) =
            make_rrsig_check_inputs("www.victim.hack.", "victim.hack.");
        let rrsig_ref = rrsig_rec.try_borrow::<rdataRRSIG>().unwrap();
        let dnskey_ref = dnskey_rec.try_borrow::<rdataDNSKEY>().unwrap();

        let query = Query::root();
        let context = validity_context(&query, &key, &rrset);
        assert_eq!(
            context.validity(rrsig_ref, dnskey_ref),
            RrsigValidity::ValidRrsig
        );
    }

    #[test]
    fn rrsig_apex_self_signed_accepted() {
        subscribe();
        let (key, rrset, rrsig_rec, dnskey_rec) =
            make_rrsig_check_inputs("victim.hack.", "victim.hack.");
        let rrsig_ref = rrsig_rec.try_borrow::<rdataRRSIG>().unwrap();
        let dnskey_ref = dnskey_rec.try_borrow::<rdataDNSKEY>().unwrap();

        let query = Query::root();
        let context = validity_context(&query, &key, &rrset);
        assert_eq!(
            context.validity(rrsig_ref, dnskey_ref),
            RrsigValidity::ValidRrsig
        );
    }

    #[test]
    fn rrsig_parent_signer_accepted() {
        subscribe();
        let (key, rrset, rrsig_rec, dnskey_rec) = make_rrsig_check_inputs("victim.hack.", "hack.");
        let rrsig_ref = rrsig_rec.try_borrow::<rdataRRSIG>().unwrap();
        let dnskey_ref = dnskey_rec.try_borrow::<rdataDNSKEY>().unwrap();

        let query = Query::root();
        let context = validity_context(&query, &key, &rrset);
        assert_eq!(
            context.validity(rrsig_ref, dnskey_ref),
            RrsigValidity::ValidRrsig
        );
    }

    #[test]
    fn rrsig_child_cannot_sign_parent() {
        subscribe();
        let (key, rrset, rrsig_rec, dnskey_rec) = make_rrsig_check_inputs("hack.", "victim.hack.");
        let rrsig_ref = rrsig_rec.try_borrow::<rdataRRSIG>().unwrap();
        let dnskey_ref = dnskey_rec.try_borrow::<rdataDNSKEY>().unwrap();

        let query = Query::root();
        let context = validity_context(&query, &key, &rrset);
        assert_eq!(
            context.validity(rrsig_ref, dnskey_ref),
            RrsigValidity::WrongRrsig
        );
    }

    #[test]
    fn rrsig_parent_wildcard_rejected() {
        subscribe();

        let wildcard_rrset_name = Name::from_ascii("*.example.").unwrap();
        let expanded_rrset_name = Name::from_ascii("attacker.example.").unwrap();
        let signer_name = Name::from_ascii("attacker.example.").unwrap();

        let dnskey = rdataDNSKEY::new(
            true,  // zone_key
            true,  // secure_entry_point
            false, // revoke
            PublicKeyBuf::new(vec![0u8; 32], Algorithm::ED25519),
        );
        let key_tag = dnskey.calculate_key_tag().unwrap();

        let sig_input = SigInput {
            type_covered: A,
            algorithm: Algorithm::ED25519,
            num_labels: wildcard_rrset_name.num_labels(),
            original_ttl: 300,
            sig_expiration: SerialNumber::new(1_000_000),
            sig_inception: SerialNumber::new(0),
            key_tag,
            signer_name: signer_name.clone(),
        };
        assert_eq!(sig_input.num_labels, 1);
        let rrsig = rdataRRSIG::from_sig(sig_input, vec![0u8; 64]);

        let key = RrKey::new((&expanded_rrset_name).into(), A);
        let rrset = Rrset {
            records: Vec::new(),
            signatures: Vec::new(),
        };
        let rrsig_rec = Record::from_rdata(
            expanded_rrset_name,
            300,
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
        );
        let dnskey_rec =
            Record::from_rdata(signer_name, 300, RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)));

        let rrsig_ref = rrsig_rec.try_borrow::<rdataRRSIG>().unwrap();
        let dnskey_ref = dnskey_rec.try_borrow::<rdataDNSKEY>().unwrap();

        let query = Query::root();
        let context = validity_context(&query, &key, &rrset);
        assert_eq!(
            context.validity(rrsig_ref, dnskey_ref),
            RrsigValidity::WrongDnskey
        );
    }

    fn validity_context<'a>(
        query: &'a Query,
        key: &'a RrKey,
        rrset: &'a Rrset<'static>,
    ) -> RrsetVerificationContext<'a> {
        RrsetVerificationContext {
            query,
            key,
            rrset,
            options: DnsRequestOptions::default(),
            current_time: 1000,
        }
    }

    /// Build inputs for testing `RrsigValidity::check()`. The RRSIG and DNSKEY have consistent key
    /// tags, algorithms, and time windows so that only the signer-name/zone relationship determines
    /// the outcome.
    fn make_rrsig_check_inputs(
        rrset_name: &str,
        signer_name: &str,
    ) -> (RrKey, Rrset<'static>, Record, Record) {
        let rrset_name = Name::from_ascii(rrset_name).unwrap();
        let signer_name = Name::from_ascii(signer_name).unwrap();

        let dnskey = rdataDNSKEY::new(
            true,  // zone_key
            true,  // secure_entry_point
            false, // revoke
            PublicKeyBuf::new(vec![0u8; 32], Algorithm::ED25519),
        );
        let key_tag = dnskey.calculate_key_tag().unwrap();

        let sig_input = SigInput {
            type_covered: A,
            algorithm: Algorithm::ED25519,
            num_labels: rrset_name.num_labels(),
            original_ttl: 300,
            sig_expiration: SerialNumber::new(1_000_000),
            sig_inception: SerialNumber::new(0),
            key_tag,
            signer_name: signer_name.clone(),
        };
        let rrsig = rdataRRSIG::from_sig(sig_input, vec![0u8; 64]);

        let rrkey = RrKey::new((&rrset_name).into(), A);
        let rrset = Rrset {
            records: Vec::new(),
            signatures: Vec::new(),
        };
        let rrsig_record =
            Record::from_rdata(rrset_name, 300, RData::DNSSEC(DNSSECRData::RRSIG(rrsig)));
        let dnskey_record =
            Record::from_rdata(signer_name, 300, RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)));

        (rrkey, rrset, rrsig_record, dnskey_record)
    }
}
