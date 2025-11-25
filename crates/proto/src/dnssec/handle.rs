// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The `DnssecDnsHandle` is used to validate all DNS responses for correct DNSSEC signatures.

use alloc::{borrow::ToOwned, boxed::Box, sync::Arc, vec::Vec};
use core::{
    clone::Clone,
    fmt::Display,
    hash::{Hash, Hasher},
    ops::RangeInclusive,
    pin::Pin,
    time::Duration,
};
use std::{
    collections::{HashMap, HashSet, hash_map::DefaultHasher},
    time::Instant,
};

use futures_util::{
    future::{self, FutureExt},
    stream::{self, Stream, StreamExt},
};
use lru_cache::LruCache;
use parking_lot::Mutex;
use tracing::{debug, error, trace, warn};

use crate::{
    dnssec::{
        Proof, ProofError, ProofErrorKind, TrustAnchors, Verifier,
        nsec3::verify_nsec3,
        rdata::{DNSKEY, DNSSECRData, DS, NSEC, RRSIG},
    },
    error::{DnsError, NoRecords, ProtoError, ProtoErrorKind},
    op::{DnsRequest, DnsRequestOptions, DnsResponse, Edns, Message, OpCode, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType, SerialNumber, resource::RecordRef},
    runtime::{RuntimeProvider, Time},
    xfer::{FirstAnswer, dns_handle::DnsHandle},
};

use self::rrset::Rrset;

/// Performs DNSSEC validation of all DNS responses from the wrapped DnsHandle
///
/// This wraps a DnsHandle, changing the implementation `send()` to validate all
///  message responses for Query operations. Update operation responses are not validated by
///  this process.
#[derive(Clone)]
#[must_use = "queries can only be sent through a DnsHandle"]
pub struct DnssecDnsHandle<H> {
    handle: H,
    trust_anchor: Arc<TrustAnchors>,
    request_depth: usize,
    nsec3_soft_iteration_limit: u16,
    nsec3_hard_iteration_limit: u16,
    validation_cache: ValidationCache,
    validation_negative_ttl: Option<RangeInclusive<Duration>>,
    validation_positive_ttl: Option<RangeInclusive<Duration>>,
}

impl<H: DnsHandle> DnssecDnsHandle<H> {
    /// Create a new DnssecDnsHandle wrapping the specified handle.
    ///
    /// This uses the compiled in TrustAnchor default trusted keys.
    ///
    /// # Arguments
    /// * `handle` - handle to use for all connections to a remote server.
    pub fn new(handle: H) -> Self {
        Self::with_trust_anchor(handle, Arc::new(TrustAnchors::default()))
    }

    /// Create a new DnssecDnsHandle wrapping the specified handle.
    ///
    /// This allows a custom TrustAnchor to be define.
    ///
    /// # Arguments
    /// * `handle` - handle to use for all connections to a remote server.
    /// * `trust_anchor` - custom DNSKEYs that will be trusted, can be used to pin trusted keys.
    pub fn with_trust_anchor(handle: H, trust_anchor: Arc<TrustAnchors>) -> Self {
        Self {
            handle,
            trust_anchor,
            request_depth: 0,
            // These default values are based on
            // [RFC 9276 Appendix A](https://www.rfc-editor.org/rfc/rfc9276.html#appendix-A)
            nsec3_soft_iteration_limit: 100,
            nsec3_hard_iteration_limit: 500,
            validation_cache: ValidationCache::new(DEFAULT_VALIDATION_CACHE_SIZE),
            validation_negative_ttl: None,
            validation_positive_ttl: None,
        }
    }

    /// Set custom NSEC3 iteration limits
    ///
    /// # Arguments
    /// * `soft_limit` - the soft limit for NSEC3 iterations. NSEC3 records with iteration counts
    ///   above this limit, but below the hard limit will evaluate to Proof::Insecure.
    /// * `hard_limit` - the hard limit for NSEC3 iterations. NSEC3 records with iteration counts
    ///   above this limit will evaluate to Proof::Bogus.
    pub fn nsec3_iteration_limits(
        mut self,
        soft_limit: Option<u16>,
        hard_limit: Option<u16>,
    ) -> Self {
        if let Some(soft) = soft_limit {
            self.nsec3_soft_iteration_limit = soft;
        }

        if let Some(hard) = hard_limit {
            self.nsec3_hard_iteration_limit = hard;
        }

        self
    }

    /// Set a custom validation cache size
    ///
    /// # Arguments
    /// * `capacity` - the desired capacity of the DNSSEC validation cache.
    pub fn validation_cache_size(mut self, capacity: usize) -> Self {
        self.validation_cache = ValidationCache::new(capacity);
        self
    }

    /// Set custom negative response validation cache TTL range
    ///
    /// # Arguments
    /// * `ttl` - A range of permissible TTL values for negative responses.
    ///
    /// Validation cache TTLs are based on the Rrset TTL value, but will be clamped to
    /// this value, if specified, for negative responses.
    pub fn negative_validation_ttl(mut self, ttl: RangeInclusive<Duration>) -> Self {
        self.validation_negative_ttl = Some(ttl);
        self
    }

    /// Set custom positive response validation cache TTL range
    ///
    /// # Arguments
    /// * `ttl` - A range of permissible TTL values for positive responses.
    ///
    /// Validation cache TTLs are based on the Rrset TTL value, but will be clamped to
    /// this value, if specified, for positive responses.
    pub fn positive_validation_ttl(mut self, ttl: RangeInclusive<Duration>) -> Self {
        self.validation_positive_ttl = Some(ttl);
        self
    }

    /// Get a reference to the underlying handle.
    pub fn inner(&self) -> &H {
        &self.handle
    }

    async fn verify_response(
        self,
        result: Result<DnsResponse, ProtoError>,
        query: Query,
        options: DnsRequestOptions,
    ) -> Result<DnsResponse, ProtoError> {
        let mut message = match result {
            Ok(response) => response,
            // Translate NoRecordsFound errors into a DnsResponse message so the rest of the
            // DNSSEC handler chain can validate negative responses.
            Err(err) => match err.kind {
                ProtoErrorKind::Dns(DnsError::NoRecordsFound(NoRecords {
                    query,
                    authorities,
                    response_code,
                    ..
                })) => {
                    debug!("translating NoRecordsFound to DnsResponse for {query}");
                    let mut msg = Message::query();
                    msg.add_query(*query);
                    msg.set_response_code(response_code);

                    if let Some(authorities) = authorities {
                        for record in authorities.iter() {
                            msg.add_authority(record.clone());
                        }
                    }

                    match DnsResponse::from_message(msg) {
                        Ok(response) => response,
                        Err(err) => {
                            return Err(ProtoError::from(format!(
                                "unable to construct DnsResponse: {err:?}"
                            )));
                        }
                    }
                }
                _ => return Err(err),
            },
        };

        debug!(
            "validating message_response: {}, with {} trust_anchors",
            message.id(),
            self.trust_anchor.len(),
        );

        // use the same current time value for all rrsig + rrset pairs.
        let current_time = <H::Runtime as RuntimeProvider>::Timer::current_time() as u32;

        // group the record sets by name and type
        //  each rrset type needs to validated independently
        let answers = message.take_answers();
        let authorities = message.take_authorities();
        let additionals = message.take_additionals();

        let answers = self
            .verify_rrsets(&query, answers, options, current_time)
            .await;
        let authorities = self
            .verify_rrsets(&query, authorities, options, current_time)
            .await;
        let additionals = self
            .verify_rrsets(&query, additionals, options, current_time)
            .await;

        // If we have any wildcard records, they must be validated with covering
        // NSEC/NSEC3 records.  RFC 4035 5.3.4, 5.4, and RFC 5155 7.2.6.
        let must_validate_nsec = answers.iter().any(|rr| {
            let Some(dnssec) = rr.data().as_dnssec() else {
                return false;
            };
            let Some(rrsig) = dnssec.as_rrsig() else {
                return false;
            };

            rrsig.input().num_labels < rr.name().num_labels()
        });

        message.insert_answers(answers);
        message.insert_authorities(authorities);
        message.insert_additionals(additionals);

        if !message.authorities().is_empty()
            && message
                .authorities()
                .iter()
                .all(|x| x.proof() == Proof::Insecure)
        {
            return Ok(message);
        }

        let nsec3s = message
            .authorities()
            .iter()
            .filter_map(|rr| {
                if message
                    .authorities()
                    .iter()
                    .any(|r| r.name() == rr.name() && r.proof() == Proof::Secure)
                {
                    rr.data()
                        .as_dnssec()?
                        .as_nsec3()
                        .map(|data| (rr.name(), data))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let nsecs = message
            .authorities()
            .iter()
            .filter_map(|rr| {
                if message
                    .authorities()
                    .iter()
                    .any(|r| r.name() == rr.name() && r.proof() == Proof::Secure)
                {
                    rr.data()
                        .as_dnssec()?
                        .as_nsec()
                        .map(|data| (rr.name(), data))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // Both NSEC and NSEC3 records cannot coexist during
        // transition periods, as per RFC 5515 10.4.3 and
        // 10.5.2
        let nsec_proof = match (!nsec3s.is_empty(), !nsecs.is_empty(), must_validate_nsec) {
            (true, false, _) => verify_nsec3(
                &query,
                find_soa_name(&message),
                message.response_code(),
                message.answers(),
                &nsec3s,
                self.nsec3_soft_iteration_limit,
                self.nsec3_hard_iteration_limit,
            ),
            (false, true, _) => verify_nsec(
                &query,
                find_soa_name(&message),
                message.response_code(),
                message.answers(),
                nsecs.as_slice(),
            ),
            (true, true, _) => {
                warn!(
                    "response contains both NSEC and NSEC3 records\nQuery:\n{query:?}\nResponse:\n{message:?}"
                );
                Proof::Bogus
            }
            (false, false, true) => {
                warn!("response contains wildcard RRSIGs, but no NSEC/NSEC3s are present.");
                Proof::Bogus
            }
            (false, false, false) => {
                // Return Ok if there were no NSEC/NSEC3 records and no wildcard RRSIGs.
                if !message.answers().is_empty() {
                    return Ok(message);
                }

                // Return Ok if the zone is insecure
                if let Err(err) = self.find_ds_records(query.name().clone(), options).await {
                    if err.proof == Proof::Insecure {
                        return Ok(message);
                    }
                }

                // If neither of the two conditions above are true, the response is Bogus - we should
                // have a covering NSEC/NSEC3 record for this scenario.
                warn!(
                    "response does not contain NSEC or NSEC3 records. Query: {query:?} response: {message:?}"
                );
                Proof::Bogus
            }
        };

        if !nsec_proof.is_secure() {
            debug!("returning Nsec error for {} {nsec_proof}", query.name());
            // TODO change this to remove the NSECs, like we do for the others?
            return Err(ProtoError::from(DnsError::Nsec {
                query: Box::new(query.clone()),
                response: Box::new(message),
                proof: nsec_proof,
            }));
        }

        Ok(message)
    }

    /// This pulls all answers returned in a Message response and returns a future which will
    ///  validate all of them.
    async fn verify_rrsets(
        &self,
        query: &Query,
        records: Vec<Record>,
        options: DnsRequestOptions,
        current_time: u32,
    ) -> Vec<Record> {
        let mut rrset_types: HashSet<(Name, RecordType)> = HashSet::new();

        for rrset in records
            .iter()
            .filter(|rr| {
                rr.record_type() != RecordType::RRSIG &&
                // if we are at a depth greater than 1, we are only interested in proving evaluation chains
                //   this means that only DNSKEY, DS, NSEC, and NSEC3 are interesting at that point.
                //   this protects against looping over things like NS records and DNSKEYs in responses.
                // TODO: is there a cleaner way to prevent cycles in the evaluations?
                (self.request_depth <= 1 || matches!(
                    rr.record_type(),
                    RecordType::DNSKEY | RecordType::DS | RecordType::NSEC | RecordType::NSEC3,
                ))
            })
            .map(|rr| (rr.name().clone(), rr.record_type()))
        {
            rrset_types.insert(rrset);
        }

        // there were no records to verify
        if rrset_types.is_empty() {
            return records;
        }

        // Records for return, eventually, all records will be returned in here
        let mut return_records = Vec::with_capacity(records.len());

        // Removing the RRSIGs from the original records, the rest of the records will be mutable to remove those evaluated
        //    and the remainder after all evalutions will be returned.
        let (mut rrsigs, mut records) = records
            .into_iter()
            .partition::<Vec<_>, _>(|r| r.record_type().is_rrsig());

        for (name, record_type) in rrset_types {
            // collect all the rrsets to verify
            let current_rrset;
            (current_rrset, records) = records
                .into_iter()
                .partition::<Vec<_>, _>(|rr| rr.record_type() == record_type && rr.name() == &name);

            let current_rrsigs;
            (current_rrsigs, rrsigs) = rrsigs.into_iter().partition::<Vec<_>, _>(|rr| {
                rr.try_borrow::<RRSIG>()
                    .map(|rr| rr.name() == &name && rr.data().input().type_covered == record_type)
                    .unwrap_or_default()
            });

            // TODO: we can do a better job here, no need for all the vec creation and clones in the Rrset.
            let mut rrs_to_verify = current_rrset.iter();
            let mut rrset = Rrset::new(rrs_to_verify.next().unwrap());
            rrs_to_verify.for_each(|rr| rrset.add(rr));

            // RRSIGS are never modified after this point
            let rrsigs: Vec<_> = current_rrsigs
                .iter()
                .filter_map(|rr| rr.try_borrow::<RRSIG>())
                .filter(|rr| rr.name() == &name)
                .filter(|rrsig| rrsig.data().input().type_covered == record_type)
                .collect();

            // if there is already an active validation going on, assume the other validation will
            //  complete properly or error if it is invalid

            // TODO: support non-IN classes?
            debug!(
                "verifying: {name} record_type: {record_type}, rrsigs: {rrsig_len}",
                rrsig_len = rrsigs.len()
            );

            // verify this rrset
            let proof = self
                .verify_rrset(RrsetVerificationContext {
                    query,
                    rrset: &rrset,
                    rrsigs,
                    options,
                    current_time,
                })
                .await;

            let proof = match proof {
                Ok(proof) => {
                    debug!("verified: {name} record_type: {record_type}",);
                    proof
                }
                Err(err) => {
                    match err.kind() {
                        ProofErrorKind::DsResponseNsec { .. } => {
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
            for mut record in current_rrset {
                record.set_proof(proof);
                if let (Proof::Secure, Some(ttl)) = (proof, adjusted_ttl) {
                    record.set_ttl(ttl);
                }

                return_records.push(record);
            }

            // only mark the RRSIG used for the proof
            let mut current_rrsigs = current_rrsigs;
            if let Some(rrsig_idx) = rrsig_idx {
                if let Some(rrsig) = current_rrsigs.get_mut(rrsig_idx) {
                    rrsig.set_proof(proof);
                    if let (Proof::Secure, Some(ttl)) = (proof, adjusted_ttl) {
                        rrsig.set_ttl(ttl);
                    }
                } else {
                    warn!(
                        "bad rrsig index {rrsig_idx} rrsigs.len = {}",
                        current_rrsigs.len()
                    );
                }
            }

            // push all the RRSIGs back to the return
            return_records.extend(current_rrsigs);
        }

        // Add back all the RRSIGs and any records that were not verified
        return_records.extend(rrsigs);
        return_records.extend(records);
        return_records
    }

    /// Generic entrypoint to verify any RRSET against the provided signatures.
    ///
    /// Generally, the RRSET will be validated by `verify_default_rrset()`. There are additional
    ///  checks that happen after the RRSET is successfully validated. In the case of DNSKEYs this
    ///  triggers `verify_dnskey_rrset()`. If it's an NSEC record, then the NSEC record will be
    ///  validated to prove it's correctness. There is a special case for DNSKEY, where if the RRSET
    ///  is unsigned, `rrsigs` is empty, then an immediate `verify_dnskey_rrset()` is triggered. In
    ///  this case, it's possible the DNSKEY is a trust_anchor and is not self-signed.
    ///
    /// # Returns
    ///
    /// If Ok, returns an RrsetProof containing the proof, adjusted TTL, and an index of the RRSIG used for
    /// validation of the rrset.
    async fn verify_rrset(
        &self,
        context: RrsetVerificationContext<'_>,
    ) -> Result<RrsetProof, ProofError> {
        let key = context.key();

        if let Some(cached) = self.validation_cache.get(&key, &context) {
            return cached;
        }

        // DNSKEYS have different logic for their verification
        let proof = match context.rrset.record_type {
            RecordType::DNSKEY => self.verify_dnskey_rrset(&context).await,
            _ => self.verify_default_rrset(&context).await,
        };

        match proof {
            // These could be transient errors that should be retried.
            Err(ref e) if matches!(e.kind(), ProofErrorKind::Proto { .. }) => {
                debug!("not caching DNSSEC validation with ProofErrorKind::Proto")
            }
            _ => {
                debug!(
                    name = ?context.rrset.name,
                    record_type = ?context.rrset.record_type,
                    "inserting DNSSEC validation cache entry",
                );

                let (mut min, mut max) = (Duration::from_secs(0), Duration::from_secs(u64::MAX));
                if proof.is_err() {
                    if let Some(negative_bounds) = self.validation_negative_ttl.clone() {
                        (min, max) = negative_bounds.into_inner();
                    }
                } else if let Some(positive_bounds) = self.validation_positive_ttl.clone() {
                    (min, max) = positive_bounds.into_inner();
                }

                self.validation_cache.insert(
                    key,
                    Instant::now()
                        + Duration::from_secs(context.rrset.record().ttl().into()).clamp(min, max),
                    proof.clone(),
                );
            }
        }

        proof
    }

    /// DNSKEY-specific verification
    ///
    /// A DNSKEY needs to be checked against a DS record provided by the parent zone.
    ///
    /// A DNSKEY that's part of the trust anchor does not need to have its DS record (which may
    /// not exist as it's the case of the root zone) nor its RRSIG validated. If an RRSIG is present
    /// it will be validated.
    ///
    /// # Return
    ///
    /// If Ok, returns an RrsetProof containing the proof, adjusted TTL, and an index of the RRSIG used for
    /// validation of the rrset.
    ///
    /// # Panics
    ///
    /// This method should only be called to validate DNSKEYs, see `verify_default_rrset` for other record types.
    ///  if a non-DNSKEY RRSET is passed into this method it will always panic.
    async fn verify_dnskey_rrset(
        &self,
        context: &RrsetVerificationContext<'_>,
    ) -> Result<RrsetProof, ProofError> {
        let RrsetVerificationContext {
            rrset,
            rrsigs,
            current_time,
            options,
            ..
        } = context;

        // Ensure that this method is not misused
        if RecordType::DNSKEY != rrset.record_type {
            panic!("All other RRSETs must use verify_default_rrset");
        }

        debug!(
            "dnskey validation {}, record_type: {:?}",
            rrset.name, rrset.record_type
        );

        let mut dnskey_proofs =
            Vec::<(Proof, Option<u32>, Option<usize>)>::with_capacity(rrset.records.len());
        dnskey_proofs.resize(rrset.records.len(), (Proof::Bogus, None, None));

        // check if the DNSKEYs are in the root store
        for (r, proof) in rrset.records.iter().zip(dnskey_proofs.iter_mut()) {
            let Some(dnskey) = r.try_borrow::<DNSKEY>() else {
                continue;
            };

            proof.0 = self.is_dnskey_in_root_store(&dnskey);
        }

        // if not all of the DNSKEYs are in the root store, then we need to look for DS records to verify
        let ds_records = if !dnskey_proofs.iter().all(|p| p.0.is_secure()) && !rrset.name.is_root()
        {
            // Need to get DS records for each DNSKEY.
            // Every DNSKEY other than the root zone's keys may have a corresponding DS record.
            self.fetch_ds_records(rrset.name.clone(), *options).await?
        } else {
            debug!("ignoring DS lookup for root zone or registered keys");
            Vec::default()
        };

        // if the DS records are not empty and they also have no supported algorithms, then this is INSECURE
        // for secure DS records the BOGUS check happens after DNSKEYs are evaluated against the DS
        if ds_records
            .iter()
            .filter(|ds| ds.proof().is_secure() || ds.proof().is_insecure())
            .all(|ds| {
                !ds.data().algorithm().is_supported() || !ds.data().digest_type().is_supported()
            })
            && !ds_records.is_empty()
        {
            debug!(
                "all dnskeys use unsupported algorithms and there are no supported DS records in the parent zone"
            );
            // cannot validate; mark as insecure
            return Err(ProofError::new(
                Proof::Insecure,
                ProofErrorKind::UnsupportedKeyAlgorithm,
            ));
        }

        // verify all dnskeys individually against the DS records
        for (r, proof) in rrset.records.iter().zip(dnskey_proofs.iter_mut()) {
            let Some(dnskey) = r.try_borrow() else {
                continue;
            };

            if proof.0.is_secure() {
                continue;
            }

            // need to track each proof on each dnskey to ensure they are all validated
            match verify_dnskey(&dnskey, &ds_records) {
                Ok(pf) => *proof = (pf, None, None),
                Err(err) => *proof = (err.proof, None, None),
            }
        }

        // There may have been a key-signing key for the zone,
        //   we need to verify all the other DNSKEYS in the zone against it (i.e. the rrset)
        for (i, rrsig) in rrsigs.iter().enumerate() {
            // These should all match, but double checking...
            let signer_name = &rrsig.data().input().signer_name;

            let rrset_proof = rrset
                .records
                .iter()
                .zip(dnskey_proofs.iter())
                .filter(|(_, (proof, ..))| proof.is_secure())
                .filter(|(r, _)| r.name() == signer_name)
                .filter_map(|(r, (proof, ..))| {
                    RecordRef::<'_, DNSKEY>::try_from(*r)
                        .ok()
                        .map(|r| (r, proof))
                })
                .find_map(|(dnskey, proof)| {
                    verify_rrset_with_dnskey(dnskey, *proof, rrsig, rrset, *current_time).ok()
                });

            if let Some(rrset_proof) = rrset_proof {
                return Ok(RrsetProof {
                    proof: rrset_proof.0,
                    adjusted_ttl: rrset_proof.1,
                    rrsig_index: Some(i),
                });
            }
        }

        // if it was just the root DNSKEYS with no RRSIG, we'll accept the entire set, or none
        if dnskey_proofs.iter().all(|(proof, ..)| proof.is_secure()) {
            let proof = dnskey_proofs.pop().unwrap(/* This can not happen due to above test */);
            return Ok(RrsetProof {
                proof: proof.0,
                adjusted_ttl: proof.1,
                rrsig_index: proof.2,
            });
        }

        if !ds_records.is_empty() {
            // there were DS records, but no DNSKEYs, we're in a bogus state
            trace!("bogus dnskey: {}", rrset.name);
            return Err(ProofError::new(
                Proof::Bogus,
                ProofErrorKind::DsRecordsButNoDnskey {
                    name: rrset.name.clone(),
                },
            ));
        }

        // There were DS records or RRSIGs, but none of the signatures could be validated, so we're in a
        // bogus state. If there was no DS record, it should have gotten an NSEC upstream, and returned
        // early above.
        trace!("no dnskey found: {}", rrset.name);
        Err(ProofError::new(
            Proof::Bogus,
            ProofErrorKind::DnskeyNotFound {
                name: rrset.name.clone(),
            },
        ))
    }

    /// Checks whether a DS RRset exists for the zone containing a name.
    ///
    /// Returns an error with an `Insecure` proof if the zone is proven to be insecure. Returns
    /// `Ok(())` if the zone is secure.
    ///
    /// This first finds the nearest zone cut at or above the given name, by making NS queries.
    /// Then, the DS RRset at the delegation point is requested. The DS response is validated to
    /// determine if any DS records exist or not, and thus whether the zone is secure, insecure, or
    /// bogus. See [RFC 6840 section 6.1](https://datatracker.ietf.org/doc/html/rfc6840#section-6.1)
    /// and [RFC 4035 section 4.2](https://datatracker.ietf.org/doc/html/rfc4035#section-4.2).
    async fn find_ds_records(
        &self,
        name: Name,
        options: DnsRequestOptions,
    ) -> Result<(), ProofError> {
        let mut ancestor = name.clone();
        let zone = loop {
            if ancestor.is_root() {
                return Err(ProofError::ds_should_exist(name));
            }

            // Make an un-verified request for the NS RRset at this ancestor name.
            let query = Query::query(ancestor.clone(), RecordType::NS);
            let result = self
                .handle
                .lookup(query.clone(), options)
                .first_answer()
                .await;
            match result {
                Ok(response) => {
                    if response.all_sections().any(|record| {
                        record.record_type() == RecordType::NS && record.name() == &ancestor
                    }) {
                        break ancestor;
                    }
                }
                Err(e) if e.is_no_records_found() || e.is_nx_domain() => {}
                Err(e) => {
                    return Err(ProofError::new(
                        Proof::Bogus,
                        ProofErrorKind::Proto { query, proto: e },
                    ));
                }
            }

            ancestor = ancestor.base_name();
        };

        self.fetch_ds_records(zone, options).await?;
        Ok(())
    }

    /// Retrieves DS records for the given zone.
    async fn fetch_ds_records(
        &self,
        zone: Name,
        options: DnsRequestOptions,
    ) -> Result<Vec<Record<DS>>, ProofError> {
        let ds_message = self
            .lookup(Query::query(zone.clone(), RecordType::DS), options)
            .first_answer()
            .await;

        let error_opt = match ds_message {
            Ok(mut ds_message)
                if ds_message
                    .answers()
                    .iter()
                    .filter(|r| r.record_type() == RecordType::DS)
                    .any(|r| r.proof().is_secure()) =>
            {
                // This is a secure DS RRset.

                let all_records = ds_message.take_answers().into_iter().filter_map(|r| {
                    r.map(|data| match data {
                        RData::DNSSEC(DNSSECRData::DS(ds)) => Some(ds),
                        _ => None,
                    })
                });

                let mut supported_records = vec![];
                let mut all_unknown = None;
                for record in all_records {
                    // A chain can be either SECURE or INSECURE, but we should not trust BOGUS or other
                    // records.
                    if (!record.data().algorithm().is_supported()
                        || !record.data().digest_type().is_supported())
                        && (record.proof().is_secure() || record.proof().is_insecure())
                    {
                        all_unknown.get_or_insert(true);
                        continue;
                    }
                    all_unknown = Some(false);

                    supported_records.push(record);
                }

                if all_unknown.unwrap_or(false) {
                    return Err(ProofError::new(
                        Proof::Insecure,
                        ProofErrorKind::UnknownKeyAlgorithm,
                    ));
                } else if !supported_records.is_empty() {
                    return Ok(supported_records);
                } else {
                    None
                }
            }
            Ok(response) => {
                let any_ds_rr = response
                    .answers()
                    .iter()
                    .any(|r| r.record_type() == RecordType::DS);
                if any_ds_rr {
                    None
                } else {
                    // If the response was an authenticated proof of nonexistence, then we have an
                    // insecure zone.
                    debug!("marking {zone} as insecure based on secure NSEC/NSEC3 proof");
                    return Err(ProofError::new(
                        Proof::Insecure,
                        ProofErrorKind::DsResponseNsec { name: zone },
                    ));
                }
            }
            Err(error) => Some(error),
        };

        // If the response was an empty DS RRset that was itself insecure, then we have another insecure zone.
        if let Some(ProtoErrorKind::Dns(DnsError::Nsec { query, proof, .. })) =
            error_opt.as_ref().map(|e| e.kind())
        {
            if proof.is_insecure() {
                debug!(
                    "marking {} as insecure based on insecure NSEC/NSEC3 proof",
                    query.name()
                );
                return Err(ProofError::new(
                    Proof::Insecure,
                    ProofErrorKind::DsResponseNsec {
                        name: query.name().to_owned(),
                    },
                ));
            }
        }

        Err(ProofError::ds_should_exist(zone))
    }

    /// Verifies that the key is a trust anchor.
    ///
    /// # Returns
    ///
    /// Proof::Secure if registered in the root store, Proof::Bogus if not
    fn is_dnskey_in_root_store(&self, rr: &RecordRef<'_, DNSKEY>) -> Proof {
        let dns_key = rr.data();
        let pub_key = dns_key.public_key();

        // Checks to see if the key is valid against the registered root certificates
        if self.trust_anchor.contains(pub_key) {
            debug!(
                "validated dnskey with trust_anchor: {}, {dns_key}",
                rr.name(),
            );

            Proof::Secure
        } else {
            Proof::Bogus
        }
    }

    /// Verifies that a given RRSET is validly signed by any of the specified RRSIGs.
    ///
    /// Invalid RRSIGs will be ignored. RRSIGs will only be validated against DNSKEYs which can
    ///  be validated through a chain back to the `trust_anchor`. As long as one RRSIG is valid,
    ///  then the RRSET will be valid.
    ///
    /// # Returns
    ///
    /// On Ok, the set of (Proof, AdjustedTTL, and IndexOfRRSIG) is returned, where the index is the one of the RRSIG that validated
    ///   the Rrset
    ///
    /// # Panics
    ///
    /// This method should never be called to validate DNSKEYs, see `verify_dnskey_rrset` instead.
    ///  if a DNSKEY RRSET is passed into this method it will always panic.
    async fn verify_default_rrset(
        &self,
        context: &RrsetVerificationContext<'_>,
    ) -> Result<RrsetProof, ProofError> {
        let RrsetVerificationContext {
            query: original_query,
            rrset,
            rrsigs,
            current_time,
            options,
        } = context;

        // Ensure that this method is not misused
        if RecordType::DNSKEY == rrset.record_type {
            panic!("DNSKEYs must be validated with verify_dnskey_rrset");
        }

        if rrsigs.is_empty() {
            // Decide if we're:
            //    1) "insecure", the zone has a valid NSEC for the DS record in the parent zone
            //    2) "bogus", the parent zone has a valid DS record, but the child zone didn't have the RRSIGs/DNSKEYs
            //       or the parent zone has a DS record without covering RRSIG records.
            if rrset.record_type != RecordType::DS {
                let mut search_name = rrset.name.clone();
                if rrset.record_type == RecordType::NSEC3 {
                    // No need to look for a zone cut at an NSEC3 owner name. Look at its parent
                    // instead, which ought to be a zone apex.
                    search_name = search_name.base_name();
                }

                self.find_ds_records(search_name, *options).await?; // insecure will return early here
            }

            return Err(ProofError::new(
                Proof::Bogus,
                ProofErrorKind::RrsigsNotPresent {
                    name: rrset.name.clone(),
                    record_type: rrset.record_type,
                },
            ));
        }

        // the record set is going to be shared across a bunch of futures, Arc for that.
        trace!(
            "default validation {}, record_type: {:?}",
            rrset.name, rrset.record_type
        );

        // we can validate with any of the rrsigs...
        //  i.e. the first that validates is good enough
        //  TODO: could there be a cert downgrade attack here with a MITM stripping stronger RRSIGs?
        //         we could check for the strongest RRSIG and only use that...
        //         though, since the entire package isn't signed any RRSIG could have been injected,
        //         right? meaning if there is an attack on any of the acceptable algorithms, we'd be
        //         susceptible until that algorithm is removed as an option.
        //        dns over TLS will mitigate this.
        //  TODO: strip RRSIGS to accepted algorithms and make algorithms configurable.
        let verifications = rrsigs
            .iter()
            .enumerate()
            .filter_map(|(i, rrsig)| {
                let query =
                    Query::query(rrsig.data().input().signer_name.clone(), RecordType::DNSKEY);

                if i > MAX_RRSIGS_PER_RRSET {
                    warn!("too many ({i}) RRSIGs for rrset {rrset:?}; skipping");
                    return None;
                }

                // TODO: Should this sig.signer_name should be confirmed to be in the same zone as the rrsigs and rrset?
                // Break verification cycle
                if query.name() == original_query.name()
                    && query.query_type() == original_query.query_type()
                {
                    warn!(
                        query_name = %query.name(),
                        query_type = %query.query_type(),
                        original_query_name = %original_query.name(),
                        original_query_type = %original_query.query_type(),
                        "stopping verification cycle in verify_default_rrset",
                    );
                    return None;
                }

                Some(
                    self.lookup(query.clone(), *options)
                        .first_answer()
                        .map(move |result| match result {
                            Ok(message) => {
                                Ok(verify_rrsig_with_keys(message, rrsig, rrset, *current_time)
                                    .map(|(proof, adjusted_ttl)| RrsetProof {
                                        proof,
                                        adjusted_ttl,
                                        rrsig_index: Some(i),
                                    }))
                            }
                            Err(proto) => Err(ProofError::new(
                                Proof::Bogus,
                                ProofErrorKind::Proto { query, proto },
                            )),
                        }),
                )
            })
            .collect::<Vec<_>>();

        // if there are no available verifications, then we are in a failed state.
        if verifications.is_empty() {
            return Err(ProofError::new(
                Proof::Bogus,
                ProofErrorKind::RrsigsNotPresent {
                    name: rrset.name.clone(),
                    record_type: rrset.record_type,
                },
            ));
        }

        // as long as any of the verifications is good, then the RRSET is valid.
        let select = future::select_ok(verifications);

        // this will return either a good result or the errors
        let (proof, rest) = select.await?;
        drop(rest);

        proof.ok_or_else(||
            // we are in a bogus state, DS records were available (see beginning of function), but RRSIGs couldn't be verified
            ProofError::new(Proof::Bogus, ProofErrorKind::RrsigsUnverified {
                name: rrset.name.clone(),
                record_type: rrset.record_type,
            }
        ))
    }

    /// An internal function used to clone the handle, but maintain some information back to the
    ///  original handle, such as the request_depth such that infinite recursion does
    ///  not occur.
    fn clone_with_context(&self) -> Self {
        Self {
            handle: self.handle.clone(),
            trust_anchor: Arc::clone(&self.trust_anchor),
            request_depth: self.request_depth + 1,
            nsec3_soft_iteration_limit: self.nsec3_soft_iteration_limit,
            nsec3_hard_iteration_limit: self.nsec3_hard_iteration_limit,
            validation_cache: self.validation_cache.clone(),
            validation_negative_ttl: self.validation_negative_ttl.clone(),
            validation_positive_ttl: self.validation_positive_ttl.clone(),
        }
    }
}

#[cfg(any(feature = "std", feature = "no-std-rand"))]
impl<H: DnsHandle> DnsHandle for DnssecDnsHandle<H> {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send>>;
    type Runtime = H::Runtime;

    fn is_verifying_dnssec(&self) -> bool {
        // This handler is always verifying...
        true
    }

    fn send(&self, mut request: DnsRequest) -> Self::Response {
        // backstop
        if self.request_depth > request.options().max_request_depth {
            error!("exceeded max validation depth");
            return Box::pin(stream::once(future::err(ProtoError::from(
                "exceeded max validation depth",
            ))));
        }

        // dnssec only matters on queries.
        match request.op_code() {
            OpCode::Query => {}
            _ => return Box::pin(self.handle.send(request)),
        }

        // This will fail on no queries, that is a very odd type of request, isn't it?
        // TODO: with mDNS there can be multiple queries
        let query = if let Some(query) = request.queries().first().cloned() {
            query
        } else {
            return Box::pin(stream::once(future::err(ProtoError::from(
                "no query in request",
            ))));
        };

        let handle = self.clone_with_context();
        request
            .extensions_mut()
            .get_or_insert_with(Edns::new)
            .enable_dnssec();

        request.set_authentic_data(true);
        request.set_checking_disabled(false);
        let options = *request.options();

        Box::pin(self.handle.send(request).then(move |result| {
            handle
                .clone()
                .verify_response(result, query.clone(), options)
        }))
    }
}

fn verify_rrsig_with_keys(
    dnskey_message: DnsResponse,
    rrsig: &RecordRef<'_, RRSIG>,
    rrset: &Rrset<'_>,
    current_time: u32,
) -> Option<(Proof, Option<u32>)> {
    let mut tag_count = HashMap::<u16, usize>::new();

    if (rrset.record_type == RecordType::NSEC || rrset.record_type == RecordType::NSEC3)
        && rrset.name.num_labels() != rrsig.data().input().num_labels
    {
        warn!(
            "{} record signature claims to be expanded from a wildcard",
            rrset.record_type
        );
        return None;
    }

    // DNSKEYs were already validated by the inner query in the above lookup
    let dnskeys = dnskey_message.answers().iter().filter_map(|r| {
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
                if let Ok(proof) =
                    verify_rrset_with_dnskey(dnskey, dnskey.proof(), rrsig, rrset, current_time)
                {
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

/// Find the SOA record, if present, in the response and return its name.
///
/// Note that a SOA record may not be present in all responses that must be NSEC/NSEC3 validated.
/// See RFC 4035 B.4 - Referral to Signed Zone, B.5 Referral to Unsigned Zone, B.6 - Wildcard
/// Expansion, RFC 5155 B.3 - Referral to an Opt-Out Unsigned Zone, and B.4 - Wildcard Expansion.
fn find_soa_name(verified_message: &DnsResponse) -> Option<&Name> {
    for record in verified_message.authorities() {
        if record.record_type() == RecordType::SOA {
            return Some(record.name());
        }
    }

    None
}

/// This verifies a DNSKEY record against DS records from a secure delegation.
fn verify_dnskey(
    rr: &RecordRef<'_, DNSKEY>,
    ds_records: &[Record<DS>],
) -> Result<Proof, ProofError> {
    let key_rdata = rr.data();
    let key_tag = key_rdata.calculate_key_tag().map_err(|_| {
        ProofError::new(
            Proof::Insecure,
            ProofErrorKind::ErrorComputingKeyTag {
                name: rr.name().clone(),
            },
        )
    })?;
    let key_algorithm = key_rdata.algorithm();

    if !key_algorithm.is_supported() {
        return Err(ProofError::new(
            Proof::Insecure,
            ProofErrorKind::UnsupportedKeyAlgorithm,
        ));
    }

    // DS check if covered by DS keys
    let mut key_authentication_attempts = 0;
    for r in ds_records.iter().filter(|ds| ds.proof().is_secure()) {
        if r.data().algorithm() != key_algorithm {
            trace!(
                "skipping DS record due to algorithm mismatch, expected algorithm {}: ({}, {})",
                key_algorithm,
                r.name(),
                r.data(),
            );

            continue;
        }

        if r.data().key_tag() != key_tag {
            trace!(
                "skipping DS record due to key tag mismatch, expected tag {key_tag}: ({}, {})",
                r.name(),
                r.data(),
            );

            continue;
        }

        // Count the number of DS records with the same algorithm and key tag as this DNSKEY.
        // Ignore remaining DS records if there are too many key tag collisions. Doing so before
        // checking hashes or signatures protects us from KeyTrap denial of service attacks.
        key_authentication_attempts += 1;
        if key_authentication_attempts > MAX_KEY_TAG_COLLISIONS {
            warn!(
                key_tag,
                attempts = key_authentication_attempts,
                "too many DS records with same key tag; skipping"
            );
            continue;
        }

        if !r.data().covers(rr.name(), key_rdata).unwrap_or(false) {
            continue;
        }

        debug!(
            "validated dnskey ({}, {key_rdata}) with {} {}",
            rr.name(),
            r.name(),
            r.data(),
        );

        // If this key is valid, then it is secure
        return Ok(Proof::Secure);
    }

    trace!("bogus dnskey: {}", rr.name());
    Err(ProofError::new(
        Proof::Bogus,
        ProofErrorKind::DnsKeyHasNoDs {
            name: rr.name().clone(),
        },
    ))
}

/// Verifies the given SIG of the RRSET with the DNSKEY.
fn verify_rrset_with_dnskey(
    dnskey: RecordRef<'_, DNSKEY>,
    dnskey_proof: Proof,
    rrsig: &RecordRef<'_, RRSIG>,
    rrset: &Rrset<'_>,
    current_time: u32,
) -> Result<(Proof, Option<u32>), ProofError> {
    match dnskey_proof {
        Proof::Secure => (),
        proof => {
            debug!("insecure dnskey {} {}", dnskey.name(), dnskey.data());
            return Err(ProofError::new(
                proof,
                ProofErrorKind::InsecureDnsKey {
                    name: dnskey.name().clone(),
                    key_tag: rrsig.data().input.key_tag,
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
                key_tag: rrsig.data().input.key_tag,
            },
        ));
    } // TODO: does this need to be validated? RFC 5011
    if !dnskey.data().zone_key() {
        return Err(ProofError::new(
            Proof::Bogus,
            ProofErrorKind::NotZoneDnsKey {
                name: dnskey.name().clone(),
                key_tag: rrsig.data().input.key_tag,
            },
        ));
    }
    if dnskey.data().algorithm() != rrsig.data().input.algorithm {
        return Err(ProofError::new(
            Proof::Bogus,
            ProofErrorKind::AlgorithmMismatch {
                rrsig: rrsig.data().input.algorithm,
                dnskey: dnskey.data().algorithm(),
            },
        ));
    }

    let validity = RrsigValidity::check(*rrsig, rrset, dnskey, current_time);
    if !matches!(validity, RrsigValidity::ValidRrsig) {
        // TODO better error handling when the error payload is not immediately discarded by
        // the caller
        return Err(ProofError::new(
            Proof::Bogus,
            ProofErrorKind::Msg(format!("{validity:?}")),
        ));
    }

    dnskey
        .data()
        .verify_rrsig(
            &rrset.name,
            rrset.record_class,
            rrsig.data(),
            rrset.records.iter().copied(),
        )
        .map(|_| {
            debug!(
                "validated ({}, {:?}) with ({}, {})",
                rrset.name,
                rrset.record_type,
                dnskey.name(),
                dnskey.data()
            );
            (
                Proof::Secure,
                Some(rrsig.data().authenticated_ttl(rrset.record(), current_time)),
            )
        })
        .map_err(|e| {
            debug!(
                "failed validation of ({}, {:?}) with ({}, {})",
                rrset.name,
                rrset.record_type,
                dnskey.name(),
                dnskey.data()
            );
            ProofError::new(
                Proof::Bogus,
                ProofErrorKind::DnsKeyVerifyRrsig {
                    name: dnskey.name().clone(),
                    key_tag: rrsig.data().input.key_tag,
                    error: e,
                },
            )
        })
}

#[derive(Clone, Copy, Debug)]
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

impl RrsigValidity {
    // see section 5.3.1 of RFC4035 "Checking the RRSIG RR Validity"
    fn check(
        rrsig: RecordRef<'_, RRSIG>,
        rrset: &Rrset<'_>,
        dnskey: RecordRef<'_, DNSKEY>,
        current_time: u32,
    ) -> Self {
        let Ok(dnskey_key_tag) = dnskey.data().calculate_key_tag() else {
            return Self::WrongDnskey;
        };

        let current_time = SerialNumber(current_time);
        let sig_input = rrsig.data().input();
        if !(
            // "The RRSIG RR and the RRset MUST have the same owner name and the same class"
            rrsig.name() == &rrset.name &&
            rrsig.dns_class() == rrset.record_class &&

            // "The RRSIG RR's Signer's Name field MUST be the name of the zone that contains the RRset"
            // TODO(^) the zone name is in the SOA record, which is not accessible from here

            // "The RRSIG RR's Type Covered field MUST equal the RRset's type"
            sig_input.type_covered == rrset.record_type &&

            // "The number of labels in the RRset owner name MUST be greater than or equal to the value
            // in the RRSIG RR's Labels field"
            rrset.name.num_labels() >= sig_input.num_labels
        ) {
            return Self::WrongRrsig;
        }

        // Section 3.1.5 of RFC4034 states that 'all comparisons involving these fields MUST use
        // "Serial number arithmetic", as defined in RFC1982'
        if !(
            // "The validator's notion of the current time MUST be less than or equal to the time listed
            // in the RRSIG RR's Expiration field"
            current_time <= sig_input.sig_expiration &&

            // "The validator's notion of the current time MUST be greater than or equal to the time
            // listed in the RRSIG RR's Inception field"
            current_time >= sig_input.sig_inception
        ) {
            return Self::ExpiredRrsig;
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
            return Self::WrongDnskey;
        }

        Self::ValidRrsig
    }
}

#[derive(Clone)]
struct RrsetProof {
    proof: Proof,
    adjusted_ttl: Option<u32>,
    rrsig_index: Option<usize>,
}

#[derive(Clone)]
#[allow(clippy::type_complexity)]
struct ValidationCache(
    Arc<Mutex<LruCache<ValidationCacheKey, (Instant, Result<RrsetProof, ProofError>)>>>,
);

impl ValidationCache {
    fn new(capacity: usize) -> Self {
        Self(Arc::new(Mutex::new(LruCache::new(capacity))))
    }

    fn get(
        &self,
        key: &ValidationCacheKey,
        context: &RrsetVerificationContext<'_>,
    ) -> Option<Result<RrsetProof, ProofError>> {
        let (ttl, cached) = self.0.lock().get_mut(key)?.clone();

        if Instant::now() < ttl {
            debug!(
                name = ?context.rrset.name,
                record_type = ?context.rrset.record_type,
                "returning cached DNSSEC validation",
            );
            Some(cached)
        } else {
            debug!(
                name = ?context.rrset.name,
                record_type = ?context.rrset.record_type,
                "cached DNSSEC validation expired"
            );
            None
        }
    }

    fn insert(&self, key: ValidationCacheKey, ttl: Instant, proof: Result<RrsetProof, ProofError>) {
        self.0.lock().insert(key, (ttl, proof));
    }
}

struct RrsetVerificationContext<'a> {
    query: &'a Query,
    rrset: &'a Rrset<'a>,
    rrsigs: Vec<RecordRef<'a, RRSIG>>,
    options: DnsRequestOptions,
    current_time: u32,
}

impl<'a> RrsetVerificationContext<'a> {
    // Build a cache lookup key based on the query, rrset, and rrsigs contents, minus the TTLs
    // for each, since the recursor cache will return an adjusted TTL for each request and
    // cause cache misses.
    fn key(&self) -> ValidationCacheKey {
        let mut hasher = DefaultHasher::new();
        self.query.name().hash(&mut hasher);
        self.query.query_class().hash(&mut hasher);
        self.query.query_type().hash(&mut hasher);
        self.rrset.name.hash(&mut hasher);
        self.rrset.record_class.hash(&mut hasher);
        self.rrset.record_type.hash(&mut hasher);

        for rec in &self.rrset.records {
            rec.name().hash(&mut hasher);
            rec.dns_class().hash(&mut hasher);
            rec.data().hash(&mut hasher);
        }

        for rec in &self.rrsigs {
            rec.name().hash(&mut hasher);
            rec.dns_class().hash(&mut hasher);
            rec.data().hash(&mut hasher);
        }

        ValidationCacheKey(hasher.finish())
    }
}

#[derive(Hash, Eq, PartialEq)]
struct ValidationCacheKey(u64);

/// Verifies NSEC records
///
/// ```text
/// RFC 4035             DNSSEC Protocol Modifications            March 2005
///
/// 5.4.  Authenticated Denial of Existence
///
///  A resolver can use authenticated NSEC RRs to prove that an RRset is
///  not present in a signed zone.  Security-aware name servers should
///  automatically include any necessary NSEC RRs for signed zones in
///  their responses to security-aware resolvers.
///
///  Denial of existence is determined by the following rules:
///
///  o  If the requested RR name matches the owner name of an
///     authenticated NSEC RR, then the NSEC RR's type bit map field lists
///     all RR types present at that owner name, and a resolver can prove
///     that the requested RR type does not exist by checking for the RR
///     type in the bit map.  If the number of labels in an authenticated
///     NSEC RR's owner name equals the Labels field of the covering RRSIG
///     RR, then the existence of the NSEC RR proves that wildcard
///     expansion could not have been used to match the request.
///
///  o  If the requested RR name would appear after an authenticated NSEC
///     RR's owner name and before the name listed in that NSEC RR's Next
///     Domain Name field according to the canonical DNS name order
///     defined in [RFC4034], then no RRsets with the requested name exist
///     in the zone.  However, it is possible that a wildcard could be
///     used to match the requested RR owner name and type, so proving
///     that the requested RRset does not exist also requires proving that
///     no possible wildcard RRset exists that could have been used to
///     generate a positive response.
///
///  In addition, security-aware resolvers MUST authenticate the NSEC
///  RRsets that comprise the non-existence proof as described in Section
///  5.3.
///
///  To prove the non-existence of an RRset, the resolver must be able to
///  verify both that the queried RRset does not exist and that no
///  relevant wildcard RRset exists.  Proving this may require more than
///  one NSEC RRset from the zone.  If the complete set of necessary NSEC
///  RRsets is not present in a response (perhaps due to message
///  truncation), then a security-aware resolver MUST resend the query in
///  order to attempt to obtain the full collection of NSEC RRs necessary
///  to verify the non-existence of the requested RRset.  As with all DNS
///  operations, however, the resolver MUST bound the work it puts into
///  answering any particular query.
///
///  Since a validated NSEC RR proves the existence of both itself and its
///  corresponding RRSIG RR, a validator MUST ignore the settings of the
///  NSEC and RRSIG bits in an NSEC RR.
/// ```
fn verify_nsec(
    query: &Query,
    soa_name: Option<&Name>,
    response_code: ResponseCode,
    answers: &[Record],
    nsecs: &[(&Name, &NSEC)],
) -> Proof {
    // TODO: consider converting this to Result, and giving explicit reason for the failure

    let nsec1_yield =
        |proof: Proof, msg: &str| -> Proof { proof_log_yield(proof, query, "nsec1", msg) };

    if response_code != ResponseCode::NXDomain && response_code != ResponseCode::NoError {
        return nsec1_yield(Proof::Bogus, "unsupported response code");
    }

    // The SOA name, if present, must be an ancestor of the query name.  If a SOA is present,
    // we'll use that as the starting value for next_closest_encloser, otherwise, fall back to
    // the parent of the query name.
    let mut next_closest_encloser = if let Some(soa_name) = soa_name {
        if !soa_name.zone_of(query.name()) {
            return nsec1_yield(Proof::Bogus, "SOA record is for the wrong zone");
        }
        soa_name.clone()
    } else {
        query.name().base_name()
    };

    let have_answer = !answers.is_empty();

    // For a no data response with a directly matching NSEC record, we just need to verify the NSEC
    // type set does not contain the query type or CNAME.
    if let Some((_, nsec_data)) = nsecs.iter().find(|(name, _)| query.name() == *name) {
        return if nsec_data.type_set().contains(query.query_type())
            || nsec_data.type_set().contains(RecordType::CNAME)
        {
            nsec1_yield(Proof::Bogus, "direct match, record type should be present")
        } else if response_code == ResponseCode::NoError && !have_answer {
            nsec1_yield(Proof::Secure, "direct match")
        } else {
            nsec1_yield(
                Proof::Bogus,
                "nxdomain response or answers present when direct match exists",
            )
        };
    }

    let Some((covering_nsec_name, covering_nsec_data)) =
        find_nsec_covering_record(soa_name, query.name(), nsecs)
    else {
        return nsec1_yield(
            Proof::Bogus,
            "no NSEC record matches or covers the query name",
        );
    };

    // Identify the names that exist (including names of empty non terminals) that are parents of
    // the query name. Pick the longest such name, because wildcard synthesis would start looking
    // for a wildcard record there.
    for seed_name in [covering_nsec_name, covering_nsec_data.next_domain_name()] {
        let mut candidate_name = seed_name.clone();
        while candidate_name.num_labels() > next_closest_encloser.num_labels() {
            if candidate_name.zone_of(query.name()) {
                next_closest_encloser = candidate_name;
                break;
            }
            candidate_name = candidate_name.base_name();
        }
    }

    let Ok(wildcard_name) = next_closest_encloser.prepend_label("*") else {
        // This fails if the prepended label is invalid or if the wildcard name would be too long.
        // However, we already know that the query name is not too long. The next closest enclosing
        // name must be strictly shorter than the query name, since we know that there is no NSEC
        // record matching the query name. Thus the query name must be as long or longer than this
        // wildcard name we are trying to construct, because we removed at least one label from the
        // query name, and tried to add a single-byte label. This error condition should thus be
        // unreachable.
        return nsec1_yield(Proof::Bogus, "unreachable error constructing wildcard name");
    };

    debug!(%wildcard_name, "looking for NSEC for wildcard");

    // Identify the name of wildcard used to generate the response.  This will be used to prove that no closer matches
    // exist between the query name and the wildcard.
    let wildcard_base_name = if have_answer {
        // For wildcard expansion responses, identify an RRSIG that:
        // 1) Is a wildcard RRSIG (fewer rrsig labels than owner name labels) and is not longer than the query name.
        // 2) Is a parent of the query name
        //
        // There should be only one of these, but if there are multiple, we'll pick the one with the fewest labels (the harder of the
        // provided RRSIGs to validate, since more names have to be covered as a result.)
        answers
            .iter()
            .filter_map(|r| {
                let rrsig_labels = r.data().as_dnssec()?.as_rrsig()?.input.num_labels;

                if r.proof() != Proof::Secure {
                    debug!(name = ?r.name(), "ignoring RRSIG with insecure proof for wildcard_base_name");
                    return None;
                }

                if rrsig_labels >= r.name().num_labels() || rrsig_labels >= query.name().num_labels() {
                    debug!(name = ?r.name(), labels = ?r.name().num_labels(), rrsig_labels, "ignoring RRSIG for wildcard base name rrsig_labels >= labels");
                    return None;
                }

                let trimmed_name = r.name().trim_to(rrsig_labels as usize);
                if !trimmed_name.zone_of(query.name()) {
                    debug!(name = ?r.name(), query_name = ?query.name(), "ignoring RRSIG for wildcard base name: RRSIG wildcard labels not a parent of query name");
                    return None;
                }

                Some((rrsig_labels, trimmed_name.prepend_label("*").ok()?))
            }).min_by_key(|(labels, _)| *labels)
            .map(|(_, name)| name)
    } else {
        // For no data responses, we have to recover the base name from a wildcard NSEC record as there are no answer RRSIGs present.
        nsecs
            .iter()
            .filter(|(name, _)| name.is_wildcard() && name.base_name().zone_of(query.name()))
            .min_by_key(|(name, _)| name.num_labels())
            .map(|(name, _)| (*name).clone())
    };

    match find_nsec_covering_record(soa_name, &wildcard_name, nsecs) {
        // For NXDomain responses, we've already proved the record does not exist. Now we just need to prove
        // the wildcard name is covered.
        Some((_, _)) if response_code == ResponseCode::NXDomain && !have_answer => {
            nsec1_yield(Proof::Secure, "no direct match, no wildcard")
        }
        // For wildcard expansion responses, we need to prove there are no closer matches and no exact match.
        // (RFC 4035 5.3.4 and B.6/C.6)
        Some((_, _))
            if response_code == ResponseCode::NoError
                && have_answer
                && no_closer_matches(
                    query.name(),
                    soa_name,
                    nsecs,
                    wildcard_base_name.as_ref(),
                )
                && find_nsec_covering_record(soa_name, query.name(), nsecs).is_some() =>
        {
            nsec1_yield(
                Proof::Secure,
                "no direct match, covering wildcard present for wildcard expansion response",
            )
        }
        // For wildcard no data responses, we need to prove a wildcard matching wildcard_name does not contain
        // the requested record type and that no closer match exists. (RFC 4035 3.1.3.4 and B.7/C.7)
        None if !have_answer
            && response_code == ResponseCode::NoError
            && nsecs.iter().any(|(name, nsec_data)| {
                name == &&wildcard_name
                    && !nsec_data.type_set().contains(query.query_type())
                    && !nsec_data.type_set().contains(RecordType::CNAME)
                    && no_closer_matches(query.name(), soa_name, nsecs, wildcard_base_name.as_ref())
            }) =>
        {
            nsec1_yield(Proof::Secure, "no direct match, covering wildcard present")
        }
        _ => nsec1_yield(
            Proof::Bogus,
            "no NSEC record matches or covers the wildcard name",
        ),
    }
}

// Prove that no closer name exists between the query name and wildcard_base_name
fn no_closer_matches(
    query_name: &Name,
    soa: Option<&Name>,
    nsecs: &[(&'_ Name, &'_ NSEC)],
    wildcard_base_name: Option<&Name>,
) -> bool {
    let Some(wildcard_base_name) = wildcard_base_name else {
        return false;
    };

    // If the SOA name is present, the query name and wildcard base name must be children of it.
    if let Some(soa) = soa {
        if !soa.zone_of(wildcard_base_name) {
            debug!(%wildcard_base_name, %soa, "wildcard_base_name is not a child of SOA");
            return false;
        }

        if !soa.zone_of(query_name) {
            debug!(%query_name, %soa, "query_name is not a child of SOA");
            return false;
        }
    }

    if wildcard_base_name.num_labels() > query_name.num_labels() {
        debug!(%wildcard_base_name, %query_name, "wildcard_base_name cannot have more labels than query_name");
        return false;
    }

    // The query name must be a child of the wildcard (minus the *)
    if !wildcard_base_name.base_name().zone_of(query_name) {
        debug!(%wildcard_base_name, %query_name, "query_name is not a child of wildcard_name");
        return false;
    }

    // Verify that an appropriate proof exists for each wildcard between query.name() and wildcard_base_name.
    let mut name = query_name.base_name();
    while name.num_labels() > wildcard_base_name.num_labels() {
        let Ok(wildcard) = name.prepend_label("*") else {
            return false;
        };

        if find_nsec_covering_record(soa, &wildcard, nsecs).is_none() {
            debug!(%wildcard, %name, ?nsecs, "covering record does not exist for name");
            return false;
        }

        name = name.base_name();
    }

    true
}

/// Find the NSEC record covering `test_name`, if any.
fn find_nsec_covering_record<'a>(
    soa_name: Option<&Name>,
    test_name: &Name,
    nsecs: &[(&'a Name, &'a NSEC)],
) -> Option<(&'a Name, &'a NSEC)> {
    nsecs.iter().copied().find(|(nsec_name, nsec_data)| {
        let next_domain_name = nsec_data.next_domain_name();

        test_name > nsec_name
            && (test_name < next_domain_name || Some(next_domain_name) == soa_name)
    })
}

/// Logs a debug message and yields a Proof type for return
pub(super) fn proof_log_yield(
    proof: Proof,
    query: &Query,
    nsec_type: &str,
    msg: impl Display,
) -> Proof {
    debug!(
        "{nsec_type} proof for {name}, returning {proof}: {msg}",
        name = query.name()
    );
    proof
}

mod rrset {
    use alloc::vec::Vec;

    use crate::rr::{DNSClass, Name, Record, RecordType};

    // TODO: combine this with crate::rr::RecordSet?
    #[derive(Debug)]
    pub(super) struct Rrset<'r> {
        pub(super) name: Name,
        pub(super) record_class: DNSClass,
        pub(super) record_type: RecordType,
        pub(super) records: Vec<&'r Record>,
    }

    impl<'r> Rrset<'r> {
        pub(super) fn new(record: &'r Record) -> Self {
            Self {
                name: record.name().clone(),
                record_class: record.dns_class(),
                record_type: record.record_type(),
                records: vec![record],
            }
        }

        /// Adds `record` to this RRset IFF it belongs to it
        pub(super) fn add(&mut self, record: &'r Record) {
            if self.name == *record.name()
                && self.record_type == record.record_type()
                && self.record_class == record.dns_class()
            {
                self.records.push(record);
            }
        }

        /// Returns the first (main) record.
        pub(super) fn record(&self) -> &Record {
            self.records[0]
        }
    }
}

/// The maximum number of key tag collisions to accept when:
///
/// 1) Retrieving DNSKEY records for a zone
/// 2) Retrieving DS records from a parent zone
///
/// Any colliding records encountered beyond this limit will be discarded.
const MAX_KEY_TAG_COLLISIONS: usize = 2;

/// The maximum number of RRSIGs to attempt to validate for each RRSET.
const MAX_RRSIGS_PER_RRSET: usize = 8;

/// The default validation cache size.  This is somewhat arbitrary, but set to the same size as the default
/// recursor response cache
const DEFAULT_VALIDATION_CACHE_SIZE: usize = 1_048_576;

#[cfg(test)]
mod test {
    use std::io::Error;

    use super::{no_closer_matches, verify_nsec};
    use crate::{
        dnssec::{
            Algorithm, Proof,
            rdata::{DNSSECRData, NSEC as rdataNSEC, RRSIG as rdataRRSIG, SigInput},
        },
        op::{Query, ResponseCode},
        rr::{
            Name, RData, Record,
            RecordType::{A, AAAA, DNSKEY, MX, NS, NSEC, RRSIG, SOA, TXT},
            SerialNumber, rdata,
        },
    };
    use test_support::subscribe;

    #[test]
    fn test_no_closer_matches() -> Result<(), Error> {
        subscribe();

        assert!(no_closer_matches(
            &Name::from_ascii("a.a.a.z.w.example")?,
            Some(&Name::from_ascii("example.")?),
            &[
                // This NSEC encloses the query name and proves that no closer wildcard match
                // exists in the zone.
                (
                    &Name::from_ascii("x.y.w.example.")?,
                    &rdataNSEC::new(Name::from_ascii("xx.example.")?, [MX, NSEC, RRSIG],),
                ),
            ],
            Some(&Name::from_ascii("*.w.example.")?),
        ),);

        assert!(!no_closer_matches(
            &Name::from_ascii("a.a.a.z.w.example")?,
            Some(&Name::from_ascii("example.")?),
            &[
                // This doesn't prove the non-existence of the closer wildcard
                (
                    &Name::from_ascii("*.w.example.")?,
                    &rdataNSEC::new(Name::from_ascii("z.w.example.")?, [MX, NSEC, RRSIG],),
                ),
            ],
            Some(&Name::from_ascii("*.w.example.")?),
        ),);

        assert!(!no_closer_matches(
            &Name::from_ascii("a.a.a.z.w.example")?,
            Some(&Name::from_ascii("example.")?),
            &[(
                &Name::from_ascii("x.y.w.example.")?,
                &rdataNSEC::new(Name::from_ascii("xx.example.")?, [MX, NSEC, RRSIG],),
            ),],
            // no_closer_matches requires a wildcard base name be present
            None,
        ),);

        // SOA mismatch
        assert!(!no_closer_matches(
            &Name::from_ascii("a.a.a.z.w.example")?,
            Some(&Name::from_ascii("z.example.")?),
            &[
                // This NSEC encloses the query name and proves that no closer wildcard match
                // exists in the zone.
                (
                    &Name::from_ascii("x.y.w.example.")?,
                    &rdataNSEC::new(Name::from_ascii("xx.example.")?, [MX, NSEC, RRSIG],),
                ),
                // This NSEC proves the requested record type does not exist at the wildcard
                (
                    &Name::from_ascii("*.w.example.")?,
                    &rdataNSEC::new(Name::from_ascii("xw.example.")?, [MX, NSEC, RRSIG],),
                ),
            ],
            Some(&Name::from_ascii("*.w.example.")?),
        ),);

        // Irrelevant wildcard.
        assert!(!no_closer_matches(
            &Name::from_ascii("a.a.a.z.w.example")?,
            Some(&Name::from_ascii("example.")?),
            &[
                // This NSEC encloses the query name and proves that no closer wildcard match
                // exists in the zone.
                (
                    &Name::from_ascii("x.y.w.example.")?,
                    &rdataNSEC::new(Name::from_ascii("xx.example.")?, [MX, NSEC, RRSIG],),
                ),
                // This NSEC proves the requested record type does not exist at the wildcard
                (
                    &Name::from_ascii("*.x.example.")?,
                    &rdataNSEC::new(Name::from_ascii("xw.example.")?, [MX, NSEC, RRSIG],),
                ),
            ],
            Some(&Name::from_ascii("*.x.example.")?),
        ),);

        Ok(())
    }

    // These test cases prove a name does not exist
    #[test]
    fn nsec_name_error() -> Result<(), Error> {
        subscribe();

        // Based on RFC 4035 B.2 - Name Error
        assert_eq!(
            verify_nsec(
                &Query::query(Name::from_ascii("ml.example.")?, A),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NXDomain,
                &[],
                &[
                    // This NSEC encloses the query name and proves the record does not exist.
                    (
                        &Name::from_ascii("b.example.")?,
                        &rdataNSEC::new(Name::from_ascii("ns1.example.")?, [NS, RRSIG, NSEC],),
                    ),
                    // This NSEC proves no covering wildcard record exists (i.e., it encloses
                    // *.example. and thus proves that record does not exist.)
                    (
                        &Name::from_ascii("example.")?,
                        &rdataNSEC::new(
                            Name::from_ascii("a.example.")?,
                            [DNSKEY, MX, NS, NSEC, RRSIG, SOA],
                        ),
                    )
                ],
            ),
            Proof::Secure
        );

        // Single NSEC that proves the record does not exist, and no covering wildcard exists.
        assert_eq!(
            verify_nsec(
                &Query::query(Name::from_ascii("a.example.")?, A),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NXDomain,
                &[],
                &[(
                    &Name::from_ascii("example.")?,
                    &rdataNSEC::new(Name::from_ascii("c.example.")?, [SOA, NS, RRSIG, NSEC],),
                ),],
            ),
            Proof::Secure
        );

        Ok(())
    }

    /// Ensure invalid name error NSEC scenarios fail
    #[test]
    fn nsec_invalid_name_error() -> Result<(), Error> {
        subscribe();
        assert_eq!(
            verify_nsec(
                &Query::query(Name::from_ascii("ml.example.")?, A),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NXDomain,
                &[],
                &[
                    // This NSEC does not enclose the query name and so should cause this
                    // verification to fail
                    (
                        &Name::from_ascii("ml.example.")?,
                        &rdataNSEC::new(Name::from_ascii("ns1.example.")?, [NS, RRSIG, NSEC],),
                    ),
                    // This NSEC proves no covering wildcard record exists (i.e., it encloses
                    // *.example. and thus proves that record does not exist.)
                    (
                        &Name::from_ascii("example.")?,
                        &rdataNSEC::new(
                            Name::from_ascii("a.example.")?,
                            [DNSKEY, MX, NS, NSEC, RRSIG, SOA],
                        ),
                    )
                ],
            ),
            Proof::Bogus
        );

        // Test without proving wildcard non-existence.
        assert_eq!(
            verify_nsec(
                &Query::query(Name::from_ascii("ml.example.")?, A),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NXDomain,
                &[],
                &[
                    // This NSEC encloses the query name and proves the record does not exist.
                    (
                        &Name::from_ascii("ml.example.")?,
                        &rdataNSEC::new(Name::from_ascii("ns1.example.")?, [NS, RRSIG, NSEC],),
                    ),
                ],
            ),
            Proof::Bogus
        );

        // Invalid SOA
        assert_eq!(
            verify_nsec(
                &Query::query(Name::from_ascii("ml.example.")?, A),
                Some(&Name::from_ascii("example2.")?),
                ResponseCode::NXDomain,
                &[],
                &[
                    // This NSEC encloses the query name and proves the record does not exist.
                    (
                        &Name::from_ascii("b.example.")?,
                        &rdataNSEC::new(Name::from_ascii("ns1.example.")?, [NS, RRSIG, NSEC],),
                    ),
                    // This NSEC proves no covering wildcard record exists (i.e., it encloses
                    // *.example. and thus proves that record does not exist.)
                    (
                        &Name::from_ascii("example.")?,
                        &rdataNSEC::new(
                            Name::from_ascii("a.example.")?,
                            [DNSKEY, MX, NS, NSEC, RRSIG, SOA],
                        ),
                    )
                ],
            ),
            Proof::Bogus
        );

        Ok(())
    }

    // These test cases prove that the requested record type does not exist at the query name
    #[test]
    fn nsec_no_data_error() -> Result<(), Error> {
        subscribe();

        // Based on RFC 4035 B.3 - No Data Error
        assert_eq!(
            verify_nsec(
                &Query::query(Name::from_ascii("ns1.example.")?, MX),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[],
                &[
                    // This NSEC encloses the query name and proves the record does exist, but
                    // the requested record type does not.
                    (
                        &Name::from_ascii("ns1.example.")?,
                        &rdataNSEC::new(Name::from_ascii("ns2.example.")?, [A, NSEC, RRSIG],),
                    ),
                ],
            ),
            Proof::Secure
        );

        // Record type at the SOA does not exist.
        assert_eq!(
            verify_nsec(
                &Query::query(Name::from_ascii("example.")?, MX),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[],
                &[
                    // This NSEC encloses the query name and proves the record does exist, but
                    // the requested record type does not.
                    (
                        &Name::from_ascii("example.")?,
                        &rdataNSEC::new(Name::from_ascii("a.example.")?, [A, NSEC, RRSIG, SOA],),
                    ),
                ],
            ),
            Proof::Secure
        );

        Ok(())
    }

    // Ensure invalid no data NSEC scenarios fails
    #[test]
    fn nsec_invalid_no_data_error() -> Result<(), Error> {
        subscribe();

        assert_eq!(
            verify_nsec(
                &Query::query(Name::from_ascii("ns1.example.")?, MX),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[],
                &[
                    // This NSEC claims the requested record type DOES exist at ns1.example.
                    (
                        &Name::from_ascii("ns1.example.")?,
                        &rdataNSEC::new(Name::from_ascii("ns2.example.")?, [A, NSEC, RRSIG, MX],),
                    ),
                ],
            ),
            Proof::Bogus
        );

        assert_eq!(
            verify_nsec(
                &Query::query(Name::from_ascii("ns1.example.")?, MX),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[],
                &[
                    // In this case, the response indicates *some* record exists at ns1.example., just not an
                    // MX record. This NSEC claims ns1.example. does not exist at all.
                    (
                        &Name::from_ascii("ml.example.")?,
                        &rdataNSEC::new(Name::from_ascii("ns2.example.")?, [A, NSEC, RRSIG],),
                    ),
                ],
            ),
            Proof::Bogus
        );

        assert_eq!(
            verify_nsec(
                &Query::query(Name::from_ascii("ns1.example.")?, MX),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[],
                &[
                    // This NSEC claims nothing exists from the SOA to ns2.example.
                    (
                        &Name::from_ascii("example.")?,
                        &rdataNSEC::new(Name::from_ascii("ns2.example.")?, [A, NSEC, RRSIG],),
                    ),
                ],
            ),
            Proof::Bogus
        );

        Ok(())
    }

    // Ensure that positive answers expanded from wildcards pass validation
    #[test]
    fn nsec_wildcard_expansion() -> Result<(), Error> {
        subscribe();

        let input = SigInput {
            type_covered: MX,
            algorithm: Algorithm::ED25519,
            num_labels: 2,
            original_ttl: 3600,
            sig_expiration: SerialNumber(0),
            sig_inception: SerialNumber(0),
            key_tag: 0,
            signer_name: Name::root(),
        };

        let rrsig = rdataRRSIG::from_sig(input, vec![]);
        let mut rrsig_record = Record::from_rdata(
            Name::from_ascii("a.z.w.example.")?,
            3600,
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
        );
        rrsig_record.set_proof(Proof::Secure);

        let answers = [
            Record::from_rdata(
                Name::from_ascii("a.z.w.example.")?,
                3600,
                RData::MX(rdata::MX::new(10, Name::from_ascii("a.z.w.example.")?)),
            ),
            rrsig_record,
        ];

        // Based on RFC 4035 B.6 - Wildcard Expansion
        assert_eq!(
            verify_nsec(
                &Query::query(Name::from_ascii("a.z.w.example.")?, MX),
                None,
                ResponseCode::NoError,
                &answers,
                &[
                    // This NSEC encloses the query name and proves that no closer wildcard match
                    // exists in the zone.
                    (
                        &Name::from_ascii("x.y.w.example.")?,
                        &rdataNSEC::new(Name::from_ascii("xx.example.")?, [MX, NSEC, RRSIG],),
                    ),
                ],
            ),
            Proof::Secure
        );

        // This response could not have been synthesized from the query name (z.example can't be expanded from *.w.example
        assert_eq!(
            verify_nsec(
                &Query::query(Name::from_ascii("z.example.")?, MX),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &answers,
                &[
                    // This NSEC encloses the query name and proves that z.example. does not exist.
                    (
                        &Name::from_ascii("y.example.")?,
                        &rdataNSEC::new(Name::from_ascii("example.")?, [A, NSEC, RRSIG],),
                    ),
                    // This NSEC proves *.example. exists and contains an MX record.
                    (
                        &Name::from_ascii("example.")?,
                        &rdataNSEC::new(
                            Name::from_ascii("a.example.")?,
                            [MX, NS, NSEC, RRSIG, SOA],
                        ),
                    ),
                ],
            ),
            Proof::Bogus
        );

        Ok(())
    }

    // Ensure that defective wildcard expansion positive answer scenarios fail validation
    #[test]
    fn nsec_invalid_wildcard_expansion() -> Result<(), Error> {
        subscribe();

        let input = SigInput {
            type_covered: MX,
            algorithm: Algorithm::ED25519,
            num_labels: 2,
            original_ttl: 0,
            sig_expiration: SerialNumber(0),
            sig_inception: SerialNumber(0),
            key_tag: 0,
            signer_name: Name::root(),
        };

        let rrsig = rdataRRSIG::from_sig(input, vec![]);
        let mut rrsig_record = Record::from_rdata(
            Name::from_ascii("a.z.w.example.")?,
            3600,
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
        );
        rrsig_record.set_proof(Proof::Secure);

        let answers = [
            Record::from_rdata(
                Name::from_ascii("a.z.w.example.")?,
                3600,
                RData::MX(rdata::MX::new(10, Name::from_ascii("a.z.w.example.")?)),
            ),
            rrsig_record,
        ];

        assert_eq!(
            verify_nsec(
                &Query::query(Name::from_ascii("a.z.w.example.")?, MX),
                None,
                ResponseCode::NoError,
                &answers,
                &[
                    // This NSEC does not prove the non-existence of *.z.w.example.
                    (
                        &Name::from_ascii("x.y.w.example.")?,
                        &rdataNSEC::new(Name::from_ascii("z.w.example.")?, [MX, NSEC, RRSIG],),
                    ),
                ],
            ),
            Proof::Bogus
        );

        assert_eq!(
            verify_nsec(
                &Query::query(Name::from_ascii("a.z.w.example.")?, MX),
                None,
                ResponseCode::NoError,
                &answers,
                &[],
            ),
            Proof::Bogus
        );

        Ok(())
    }

    #[test]
    fn nsec_wildcard_no_data_error() -> Result<(), Error> {
        subscribe();

        // Based on RFC 4035 B.7 - Wildcard No Data Error
        assert_eq!(
            verify_nsec(
                &Query::query(Name::from_ascii("a.z.w.example.")?, AAAA),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[],
                &[
                    // This NSEC encloses the query name and proves that no closer wildcard match
                    // exists in the zone.
                    (
                        &Name::from_ascii("x.y.w.example.")?,
                        &rdataNSEC::new(Name::from_ascii("xx.example.")?, [MX, NSEC, RRSIG],),
                    ),
                    // This NSEC proves the requested record type does not exist at the wildcard
                    (
                        &Name::from_ascii("*.w.example.")?,
                        &rdataNSEC::new(Name::from_ascii("xw.example.")?, [MX, NSEC, RRSIG],),
                    ),
                ],
            ),
            Proof::Secure
        );

        assert_eq!(
            verify_nsec(
                &Query::query(Name::from_ascii("zzzzzz.hickory-dns.testing.")?, TXT),
                Some(&Name::from_ascii("hickory-dns.testing.")?),
                ResponseCode::NoError,
                &[],
                &[
                    // This NSEC proves zzzzzz.hickory-dns.testing. does not exist.
                    (
                        &Name::from_ascii("record.hickory-dns.testing.")?,
                        &rdataNSEC::new(
                            Name::from_ascii("hickory-dns.testing.")?,
                            [A, NSEC, RRSIG],
                        ),
                    ),
                    // This NSEC proves a wildcard does exist at *.hickory-dns.testing. but does not contain the
                    // requested record type.
                    (
                        &Name::from_ascii("*.hickory-dns.testing.")?,
                        &rdataNSEC::new(
                            Name::from_ascii("primary0.hickory-dns.testing.")?,
                            [A, NSEC, RRSIG],
                        ),
                    ),
                ],
            ),
            Proof::Secure
        );

        Ok(())
    }

    #[test]
    fn nsec_invalid_wildcard_no_data_error() -> Result<(), Error> {
        subscribe();

        assert_eq!(
            verify_nsec(
                &Query::query(Name::from_ascii("a.z.w.example.")?, AAAA),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[],
                &[
                    // This NSEC doesn't prove the non-existence of the query name
                    (
                        &Name::from_ascii("x.y.w.example.")?,
                        &rdataNSEC::new(Name::from_ascii("z.w.example.")?, [MX, NSEC, RRSIG],),
                    ),
                    // This NSEC proves the wildcard does not contain the requested record type
                    (
                        &Name::from_ascii("*.w.example.")?,
                        &rdataNSEC::new(Name::from_ascii("x.y.w.example.")?, [MX, NSEC, RRSIG],),
                    ),
                ],
            ),
            Proof::Bogus
        );

        assert_eq!(
            verify_nsec(
                &Query::query(Name::from_ascii("a.z.w.example.")?, AAAA),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[],
                &[
                    // This NSEC proves the query name does not exist
                    (
                        &Name::from_ascii("x.y.w.example.")?,
                        &rdataNSEC::new(Name::from_ascii("xx.example.")?, [MX, NSEC, RRSIG],),
                    ),
                    // This NSEC proves the requested record type exists at the wildcard
                    (
                        &Name::from_ascii("*.w.example.")?,
                        &rdataNSEC::new(Name::from_ascii("xw.example.")?, [AAAA, MX, NSEC, RRSIG],),
                    ),
                ],
            ),
            Proof::Bogus
        );

        assert_eq!(
            verify_nsec(
                &Query::query(Name::from_ascii("r.hickory-dns.testing.")?, TXT),
                Some(&Name::from_ascii("hickory-dns.testing.")?),
                ResponseCode::NoError,
                &[],
                &[
                    // There is no NSEC proving the non-existence of r.hickory-dns.testing.

                    // This NSEC proves a wildcard does exist at *.hickory-dns.testing. but does not contain the
                    // requested record type.
                    (
                        &Name::from_ascii("*.hickory-dns.testing.")?,
                        &rdataNSEC::new(
                            Name::from_ascii("primary0.hickory-dns.testing.")?,
                            [A, NSEC, RRSIG],
                        ),
                    ),
                ],
            ),
            Proof::Bogus
        );

        Ok(())
    }
}
