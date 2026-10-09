// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The `DnssecDnsHandle` is used to validate all DNS responses for correct DNSSEC signatures.

use core::{
    clone::Clone,
    fmt::Display,
    hash::{Hash, Hasher},
    mem,
    ops::RangeInclusive,
    time::Duration,
};
use std::{collections::HashMap, sync::Arc, time::Instant};

use futures_util::future::{self, FutureExt};
use lru_cache::LruCache;
use parking_lot::Mutex;
use tracing::{debug, error, trace, warn};

use crate::{
    error::{DnsError, NetError, NoRecords},
    proto::{
        dnssec::{
            Proof, TrustAnchors, Verifier,
            rdata::{DNSKEY, DNSSECRData, DS, RRSIG},
        },
        op::{DnsRequest, DnsRequestOptions, DnsResponse, Edns, Message, OpCode, Query},
        rr::{LowerName, Name, RData, Record, RecordRef, RecordType},
    },
    runtime::{RuntimeProvider, Time},
    xfer::dns_handle::DnsHandle,
};

mod context;
use context::{
    RrsetMap, RrsetProof, RrsetVerificationContext, RrsigVerificationOutcome, VerifiedRrsetMap,
};

mod error;
pub use error::{ProofError, ProofErrorKind};

mod nsec;
use nsec::verify_nsec;

mod nsec3;
use nsec3::{verify_nsec3, verify_nsec3_insecure_delegation};

#[cfg(all(test, feature = "tokio"))]
mod handle_tests;

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
        self.validation_cache.negative_ttl = Some(ttl);
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
        self.validation_cache.positive_ttl = Some(ttl);
        self
    }

    async fn verify_response(
        self,
        result: Result<DnsResponse, NetError>,
        query: Query,
        options: DnsRequestOptions,
    ) -> Result<DnsResponse, NetError> {
        let mut message = match result {
            Ok(response) => response,
            // Translate NoRecordsFound errors into a DnsResponse message so the rest of the
            // DNSSEC handler chain can validate negative responses.
            Err(NetError::Dns(DnsError::NoRecordsFound(NoRecords {
                query,
                soa,
                authorities,
                response_code,
                ..
            }))) => {
                debug!("translating NoRecordsFound to DnsResponse for {query}");
                let mut msg = Message::query();
                msg.add_query(*query);
                msg.metadata.response_code = response_code;

                if let Some(authorities) = authorities {
                    for record in authorities.iter() {
                        msg.add_authority(record.clone());
                    }
                }

                // Make sure we preserve the SOA record. It is not obvious whether we need this;
                // most callers should preserve it, but not every caller might.
                // TODO: be more principled about how this is handled.
                if let Some(soa) = soa {
                    let soa = soa.into_record_of_rdata();
                    if !msg.authorities.iter().any(|r| r == &soa) {
                        msg.add_authority(soa);
                    }
                }

                match DnsResponse::from_message(msg.into_response()) {
                    Ok(response) => response,
                    Err(err) => {
                        return Err(NetError::from(format!(
                            "unable to construct DnsResponse: {err:?}"
                        )));
                    }
                }
            }
            Err(err) => return Err(err),
        };

        // Reject foreign-class records in answers/authorities/additionals.
        // We only issue IN-class queries.
        for record in message
            .answers
            .iter()
            .chain(message.authorities.iter())
            .chain(message.additionals.iter())
        {
            if record.dns_class == query.query_class {
                continue;
            }
            error!(
                %query,
                record_name = %record.name,
                record_class = %record.dns_class,
                record_type = %record.record_type(),
                "rejecting response: record class does not match query class",
            );
            return Err(NetError::ForeignClassRecord {
                record_name: record.name.clone(),
                record_class: record.dns_class,
                record_type: record.record_type(),
            });
        }

        debug!(
            "validating message_response: {}, with {} trust_anchors",
            message.id,
            self.trust_anchor.len(),
        );

        // Use the same current time value for all rrsig + rrset pairs.
        let current_time = <H::Runtime as RuntimeProvider>::Timer::current_time() as u32;

        // Group the record sets by name and type.
        // Each rrset type needs to validated independently.
        let Message {
            answers,
            authorities,
            additionals,
            ..
        } = &mut *message;
        let answers = RrsetMap::new(answers);
        let authorities = RrsetMap::new(authorities);
        let additionals = RrsetMap::new(additionals);

        // Verify signatures over each RRset.
        let mut answers = self
            .verify_rrsets(&query, answers, options, current_time)
            .await;
        let mut authorities = self
            .verify_rrsets(&query, authorities, options, current_time)
            .await;
        let mut additionals = self
            .verify_rrsets(&query, additionals, options, current_time)
            .await;

        // Check NSEC3 iteration count against limits.
        //
        // [RFC 9276 3.2](https://www.rfc-editor.org/rfc/rfc9276.html#name-recommendation-for-validati).
        let max_iterations = authorities
            .iter()
            .filter(|(key, rrsets)| {
                key.record_type == RecordType::NSEC3
                    && matches!(rrsets.outcome, RrsigVerificationOutcome::Secure { .. })
            })
            .flat_map(|(_, rrsets)| rrsets.records.iter())
            .flat_map(|record| match &record.data {
                RData::DNSSEC(DNSSECRData::NSEC3(nsec3)) => Some(nsec3.iterations()),
                _ => None,
            })
            .max()
            .unwrap_or_default();
        if max_iterations > self.nsec3_hard_iteration_limit {
            debug!(
                %query,
                iterations = max_iterations,
                nsec3_hard_iteration_limit = self.nsec3_hard_iteration_limit,
                "iteration count is over hard limit"
            );
            return Err(NetError::from(DnsError::Nsec {
                query: Box::new(query.clone()),
                response: Box::new(message),
                proof: Proof::Bogus,
            }));
        }
        if max_iterations > self.nsec3_soft_iteration_limit {
            debug!(
                %query,
                iterations = max_iterations,
                nsec3_soft_iteration_limit = self.nsec3_soft_iteration_limit,
                "iteration count is over soft limit"
            );
            return Err(NetError::from(DnsError::Nsec {
                query: Box::new(query.clone()),
                response: Box::new(message),
                proof: Proof::Insecure,
            }));
        }

        // Make a copy of the NSEC and NSEC3 RRsets, so that we can refer to them while still
        // holding a mutable reference to other RRsets.
        let nsec_records = authorities.gather_nsec_records();
        let nsec3_records = authorities.gather_nsec3_records();

        // Verify that wildcard expansion was performed correctly on each RRset.
        let wildcards_valid = answers.verify_wildcard_expansion(&nsec_records, &nsec3_records)
            & authorities.verify_wildcard_expansion(&nsec_records, &nsec3_records)
            & additionals.verify_wildcard_expansion(&nsec_records, &nsec3_records);

        if !wildcards_valid {
            return Err(NetError::from(DnsError::Nsec {
                query: Box::new(query.clone()),
                response: Box::new(message),
                proof: Proof::Bogus,
            }));
        }

        if !authorities.is_empty()
            && authorities.iter().all(|(_, rrset)| {
                rrset.records.iter().all(|x| x.proof == Proof::Insecure)
                    && rrset.signatures.iter().all(|x| x.proof == Proof::Insecure)
            })
        {
            return Ok(message);
        }

        // Return Ok if this is a valid positive response.
        if message
            .answers
            .iter()
            .any(|record| query.matches_record(record))
        {
            return Ok(message);
        }

        let nsec3s = message
            .authorities
            .iter()
            .filter_map(|rr| {
                if rr.proof == Proof::Secure {
                    match &rr.data {
                        RData::DNSSEC(DNSSECRData::NSEC3(nsec3)) => Some((&rr.name, nsec3)),
                        _ => None,
                    }
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let nsecs = message
            .authorities
            .iter()
            .filter_map(|rr| {
                if rr.proof == Proof::Secure {
                    match &rr.data {
                        RData::DNSSEC(DNSSECRData::NSEC(nsec)) => Some((&rr.name, nsec)),
                        _ => None,
                    }
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // Both NSEC and NSEC3 records cannot coexist during
        // transition periods, as per RFC 5515 10.4.3 and
        // 10.5.2
        let nsec_proof = match (!nsec3s.is_empty(), !nsecs.is_empty()) {
            (true, false) => verify_nsec3(
                &query,
                find_soa_name(&message),
                message.response_code,
                &nsec3s,
            ),
            (false, true) => verify_nsec(
                &query,
                find_soa_name(&message),
                message.response_code,
                &nsecs,
            ),
            (true, true) => {
                warn!(
                    "response contains both NSEC and NSEC3 records\nQuery:\n{query:?}\nResponse:\n{message:?}"
                );
                Proof::Bogus
            }
            (false, false) => {
                // Calling find_ds_records for a DS query will cause a validation loop if the zone being
                // queried is insecure and its parent zone is insecure (no DS records will exist and no
                // NSEC records will be available to prove that non-existence.)  Return ok/insecure:
                //
                // * If the query type is DS *and* the parent zone is Insecure
                // * For other query types, if the queried name is provably Insecure
                if let Err(err) = self
                    .find_ds_records(
                        match query.query_type {
                            RecordType::DS => query.name.base_name(),
                            _ => query.name.clone(),
                        },
                        options,
                    )
                    .await
                {
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
            debug!("returning Nsec error for {} {nsec_proof}", query.name);
            // TODO change this to remove the NSECs, like we do for the others?
            return Err(NetError::from(DnsError::Nsec {
                query: Box::new(query.clone()),
                response: Box::new(message),
                proof: nsec_proof,
            }));
        }

        Ok(message)
    }

    /// Validates signatures over record sets.
    async fn verify_rrsets<'a>(
        &self,
        query: &Query,
        rrsets: RrsetMap<'a>,
        options: DnsRequestOptions,
        current_time: u32,
    ) -> VerifiedRrsetMap<'a> {
        // There were no records to verify.
        if rrsets.is_empty() {
            return VerifiedRrsetMap::default();
        }

        let mut map = HashMap::with_capacity(rrsets.len());
        for (key, rrset) in rrsets.0.into_iter() {
            let name = &key.name;
            let record_type = key.record_type;

            if self.request_depth > 1
                && !matches!(
                    key.record_type,
                    RecordType::DNSKEY
                        | RecordType::DS
                        | RecordType::NSEC
                        | RecordType::NSEC3
                        | RecordType::SOA
                )
            {
                // If we are at a depth greater than 1, we are only interested in proving evaluation chains.
                // This means that only DNSKEY, DS, NSEC, NSEC3, and SOA are interesting at that point.
                // This protects against looping over things like NS records and DNSKEYs in responses.
                // TODO: is there a cleaner way to prevent cycles in the evaluations?
                continue;
            }

            debug!(
                "verifying: {name} record_type: {record_type}, rrsigs: {rrsig_len}",
                rrsig_len = rrset.signatures.len()
            );

            // verify this rrset
            let context = RrsetVerificationContext {
                query,
                key: &key,
                rrset: &rrset,
                options,
                current_time,
            };

            let cache_key = context.key();
            let result = match self.validation_cache.get(&cache_key, &context) {
                Some(cached) => cached,
                None => {
                    // Generally, the RRSET will be validated by `verify_default_rrset()`. There are additional
                    //  checks that happen after the RRSET is successfully validated. In the case of DNSKEYs this
                    //  triggers `verify_dnskey_rrset()`. If it's an NSEC record, then the NSEC record will be
                    //  validated to prove it's correctness. There is a special case for DNSKEY, where if the RRSET
                    //  is unsigned, `rrsigs` is empty, then an immediate `verify_dnskey_rrset()` is triggered. In
                    //  this case, it's possible the DNSKEY is a trust_anchor and is not self-signed.
                    let proof = match context.key.record_type {
                        RecordType::DNSKEY => self.verify_dnskey_rrset(&context).await,
                        _ => self.verify_default_rrset(&context).await,
                    };

                    match &proof {
                        // These could be transient errors that should be retried.
                        Err(e) if matches!(e.kind(), ProofErrorKind::Net { .. }) => {
                            debug!("not caching DNSSEC validation with ProofErrorKind::Net")
                        }
                        _ => {
                            self.validation_cache
                                .insert(proof.clone(), cache_key, &context);
                        }
                    }

                    proof
                }
            };

            let verified = rrset.verified(result, name, record_type);
            map.insert(key, verified);
        }

        VerifiedRrsetMap(map)
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
            key,
            rrset,
            options,
            ..
        } = *context;

        // Ensure that this method is not misused
        if RecordType::DNSKEY != key.record_type {
            panic!("All other RRSETs must use verify_default_rrset");
        }

        debug!(
            rrset_name = ?key.name,
            rrset_type = ?key.record_type,
            "validating rrset with dnskeys",
        );

        let mut dnskey_proofs: Vec<(Proof, Option<u32>, Option<usize>)> =
            vec![(Proof::Bogus, None, None); rrset.records.len()];

        // Check if the DNSKEYs are in the trust anchors.
        for (r, proof) in rrset.records.iter().zip(dnskey_proofs.iter_mut()) {
            let Some(dnskey) = r.try_borrow::<DNSKEY>() else {
                continue;
            };

            proof.0 = self.is_dnskey_in_root_store(&dnskey, &key.name);
        }

        // If not all DNSKEYs are trust anchors, and this isn't the root DNSKEY RRset, then we
        // should look for DS records to possibly verify more keys.
        let ds_records = if !dnskey_proofs.iter().all(|p| p.0.is_secure()) && !key.name.is_root() {
            // Need to get DS records for each DNSKEY.
            // Every DNSKEY other than the root zone's keys may have a corresponding DS record.
            self.fetch_ds_records(Name::from(&key.name), options)
                .await?
        } else {
            debug!("ignoring DS lookup for root zone or registered keys");
            Vec::default()
        };

        // if the DS records are not empty and they also have no supported algorithms, then this is INSECURE
        // for secure DS records the BOGUS check happens after DNSKEYs are evaluated against the DS
        if ds_records
            .iter()
            .filter(|ds| ds.proof.is_secure() || ds.proof.is_insecure())
            .all(|ds| !ds.data.algorithm().is_supported() || !ds.data.digest_type().is_supported())
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
        for (i, rrsig) in rrset.signatures.iter().enumerate() {
            // These should all match, but double checking...
            let Some(rrsig) = rrsig.try_borrow::<RRSIG>() else {
                continue;
            };
            let signer_name = &rrsig.data().input().signer_name;

            let rrset_proof = rrset
                .records
                .iter()
                .zip(dnskey_proofs.iter())
                .filter(|(_, (proof, ..))| proof.is_secure())
                .filter(|(r, _)| &r.name == signer_name)
                .filter_map(|(r, (proof, ..))| {
                    RecordRef::<'_, DNSKEY>::try_from(&**r)
                        .ok()
                        .map(|r| (r, proof))
                })
                .find_map(|(dnskey, proof)| {
                    context.verify_with_dnskey(dnskey, *proof, &rrsig).ok()
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
            trace!(
                rrset_name = ?key.name,
                ?ds_records,
                "bogus validation: missing dnskeys, but have ds records",
            );
            return Err(ProofError::new(
                Proof::Bogus,
                ProofErrorKind::DsRecordsButNoDnskey {
                    name: Name::from(&key.name),
                },
            ));
        }

        // There were DS records or RRSIGs, but none of the signatures could be validated, so we're in a
        // bogus state. If there was no DS record, it should have gotten an NSEC upstream, and returned
        // early above.
        trace!(rrset_name = ?key.name, "no dnskey found");
        Err(ProofError::new(
            Proof::Bogus,
            ProofErrorKind::DnskeyNotFound {
                name: Name::from(&key.name),
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
            let query = Query::new(ancestor.clone(), RecordType::NS);
            let result = self.handle.lookup(query.clone(), options).await;
            match result {
                Ok(response) => {
                    if response.all_sections().any(|record| {
                        record.record_type() == RecordType::NS && record.name == ancestor
                    }) {
                        break ancestor;
                    }
                }
                Err(e) if e.is_no_records_found() || e.is_nx_domain() => {}
                Err(net) => {
                    return Err(ProofError::new(
                        Proof::Bogus,
                        ProofErrorKind::Net { query, net },
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
        let query = Query::new(zone.clone(), RecordType::DS);
        let mut response = match Box::pin(self.lookup(query, options)).await {
            Ok(response) => response,
            Err(net) => {
                return Err(ProofError::new(
                    Proof::Bogus,
                    ProofErrorKind::Net {
                        query: Query::new(zone.clone(), RecordType::DS),
                        net,
                    },
                ));
            }
        };

        if response
            .answers
            .iter()
            .filter(|r| r.record_type() == RecordType::DS)
            .any(|r| r.proof.is_secure())
        {
            // This is a secure DS RRset.
            let all_records = mem::take(&mut response.answers)
                .into_iter()
                .filter_map(|r| {
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
                if (!record.data.algorithm().is_supported()
                    || !record.data.digest_type().is_supported())
                    && (record.proof.is_secure() || record.proof.is_insecure())
                {
                    all_unknown.get_or_insert(true);
                    continue;
                }
                all_unknown = Some(false);

                supported_records.push(record);
            }

            return if all_unknown.unwrap_or(false) {
                Err(ProofError::new(
                    Proof::Insecure,
                    ProofErrorKind::UnknownKeyAlgorithm,
                ))
            } else if !supported_records.is_empty() {
                Ok(supported_records)
            } else {
                Err(ProofError::ds_should_exist(zone))
            };
        }

        if response
            .answers
            .iter()
            .any(|r| r.record_type() == RecordType::DS)
        {
            return Err(ProofError::ds_should_exist(zone));
        }

        // Per RFC 6840 section 4.4, beyond checking the proof of nonexistence of a DS
        // record at this name, we also need to check for proof that there is an NS
        // record, or could be an NS record, at this name.

        // Case 1: Matching NSEC record exists that proves NS is present and DS is not
        // present. This is definitively an insecure delegation.
        if response.authorities.iter().any(|record| {
            if record.proof != Proof::Secure {
                return false;
            }
            let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = &record.data else {
                return false;
            };
            record.name == zone
                && nsec.type_set().contains(RecordType::NS)
                && !nsec.type_set().contains(RecordType::DS)
                && !nsec.type_set().contains(RecordType::SOA)
        }) {
            debug!(
                %zone,
                "marking zone as insecure based on secure NSEC proof",
            );
            return Err(ProofError::new(
                Proof::Insecure,
                ProofErrorKind::DsResponseInsecure { name: zone },
            ));
        }

        // Gather NSEC3 records.
        let nsec3s = response
            .authorities
            .iter()
            .filter_map(|record| {
                if record.proof != Proof::Secure {
                    return None;
                }

                let RData::DNSSEC(DNSSECRData::NSEC3(nsec3)) = &record.data else {
                    return None;
                };

                Some((&record.name, nsec3))
            })
            .collect::<Vec<_>>();

        // Case 2: Matching NSEC3 record exists that proves NS is present and DS is not
        // present. This is definitively an insecure delegation.
        //
        // Case 3: There is an NSEC3 record that covers the name and has the opt-out bit
        // set. There could be an insecure delegation at this name, but there is no way
        // to know for certain due to the use of the opt-out flag.
        if !nsec3s.is_empty() && verify_nsec3_insecure_delegation(&zone, &nsec3s) {
            debug!(
                %zone,
                "marking zone as insecure based on secure NSEC3 proof",
            );
            return Err(ProofError::new(
                Proof::Insecure,
                ProofErrorKind::DsResponseInsecure { name: zone },
            ));
        }

        // Case 4: There is an insecure delegation further up the tree.
        //
        // We check that parent zone is insecure by looking for at least one `Proof::Insecure`
        // attached to a record with name that is at or above the child zone. Most servers
        // will include an SOA record in NODATA responses, so we should see an insecure
        // proof on at least that record.
        if response
            .all_sections()
            .any(|r| r.name.zone_of(&zone) && r.proof == Proof::Insecure)
        {
            debug!(
                %zone,
                "marking zone as insecure based on insecure parent zone",
            );
            return Err(ProofError::new(
                Proof::Insecure,
                ProofErrorKind::DsResponseInsecure { name: zone },
            ));
        }

        // Case 5: The response does not contain any records that could carry an
        // insecure proof (some servers return an empty authority section for DS
        // queries in insecure zones). Check whether the parent zone is insecure
        // directly instead.
        match Box::pin(self.find_ds_records(zone.base_name(), options)).await {
            Err(err) if err.proof == Proof::Insecure => {
                debug!(
                    %zone,
                    "marking zone as insecure based on insecure parent zone lookup",
                );
                return Err(ProofError::new(
                    Proof::Insecure,
                    ProofErrorKind::DsResponseInsecure { name: zone },
                ));
            }
            Ok(()) | Err(_) => {}
        }

        debug!(
            %zone,
            "could not prove insecure delegation",
        );
        Err(ProofError::new(
            Proof::Bogus,
            ProofErrorKind::DsRecordShouldExist { name: zone },
        ))
    }

    /// Verifies that the key is a trust anchor.
    ///
    /// # Returns
    ///
    /// Proof::Secure if registered in the root store, Proof::Bogus if not
    fn is_dnskey_in_root_store(&self, rr: &RecordRef<'_, DNSKEY>, name: &LowerName) -> Proof {
        let dns_key = rr.data();
        let pub_key = dns_key.public_key();

        // Checks to see if the key is valid against the registered root certificates
        if self.trust_anchor.contains(pub_key, name) {
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
            key,
            rrset,
            options,
            ..
        } = *context;

        // Ensure that this method is not misused
        if RecordType::DNSKEY == key.record_type {
            panic!("DNSKEYs must be validated with verify_dnskey_rrset");
        }

        if rrset.signatures.is_empty() {
            // Decide if we're:
            //    1) "insecure", the zone has a valid NSEC for the DS record in the parent zone
            //    2) "bogus", the parent zone has a valid DS record, but the child zone didn't have the RRSIGs/DNSKEYs
            //       or the parent zone has a DS record without covering RRSIG records.
            if key.record_type != RecordType::DS {
                let mut search_name = Name::from(&key.name);
                if key.record_type == RecordType::NSEC3 {
                    // No need to look for a zone cut at an NSEC3 owner name. Look at its parent
                    // instead, which ought to be a zone apex.
                    search_name = search_name.base_name();
                }

                // If this is the response to a DS query and the unsigned record is at or below
                // the queried name, searching for DS records from `search_name` would find the
                // same zone cut and issue the same DS query again, recursing until the maximum
                // request depth is exceeded. This happens with servers that answer DS queries
                // from the child zone, returning the child zone's SOA record instead of the
                // parent's. The only thing such a record can tell us is whether the parent zone
                // is insecure, so start the search at the parent of the queried name instead.
                if original_query.query_type == RecordType::DS
                    && original_query.name.zone_of(&search_name)
                {
                    search_name = original_query.name.base_name();
                }

                self.find_ds_records(search_name, options).await?; // insecure will return early here
            }

            return Err(ProofError::new(
                Proof::Bogus,
                ProofErrorKind::RrsigsNotPresent {
                    name: Name::from(&key.name),
                    record_type: key.record_type,
                },
            ));
        }

        // the record set is going to be shared across a bunch of futures, Arc for that.
        trace!(
            rrset_name = ?key.name,
            rrset_type = ?key.record_type,
            "default rrset validation",
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
        let verifications = rrset
            .signatures
            .iter()
            .enumerate()
            .filter_map(|(i, rrsig)| {
                let rrsig = rrsig.try_borrow::<RRSIG>()?;
                if i > MAX_RRSIGS_PER_RRSET {
                    warn!(
                        rrset_name = ?key.name,
                        rrset_type = ?key.record_type,
                        count = rrset.signatures.len(),
                        "too many RRSIGs for rrset; skipping"
                    );
                    return None;
                }

                // RFC 4035 §5.3.1: signer must be an ancestor of (or equal to) the RRset owner
                if !rrsig.data().input().signer_name.zone_of(&key.name) {
                    warn!(
                        signer_name = %rrsig.data().input().signer_name,
                        rrset_name = %key.name,
                        "RRSIG signer name is not in the same zone as the RRset; skipping",
                    );
                    return None;
                }

                let query =
                    Query::new(rrsig.data().input().signer_name.clone(), RecordType::DNSKEY);

                // Break verification cycle
                if query.name == original_query.name
                    && query.query_type == original_query.query_type
                {
                    warn!(
                        query_name = %query.name,
                        query_type = %query.query_type,
                        original_query_name = %original_query.name,
                        original_query_type = %original_query.query_type,
                        "stopping verification cycle in verify_default_rrset",
                    );
                    return None;
                }

                Some(Box::pin(self.lookup(query.clone(), options)).map(
                    move |result| match result {
                        Ok(message) => {
                            // Report a failed signature as an error, so that select_ok()
                            // below tries the remaining RRSIGs.
                            match context.verify_rrsig_with_keys(message, &rrsig) {
                                Some((proof, adjusted_ttl)) => Ok(RrsetProof {
                                    proof,
                                    adjusted_ttl,
                                    rrsig_index: Some(i),
                                }),
                                None => Err(ProofError::new(
                                    Proof::Bogus,
                                    ProofErrorKind::RrsigsUnverified {
                                        name: Name::from(&key.name),
                                        record_type: key.record_type,
                                    },
                                )),
                            }
                        }
                        Err(net) => Err(ProofError::new(
                            Proof::Bogus,
                            ProofErrorKind::Net { query, net },
                        )),
                    },
                ))
            })
            .collect::<Vec<_>>();

        // if there are no available verifications, then we are in a failed state.
        if verifications.is_empty() {
            return Err(ProofError::new(
                Proof::Bogus,
                ProofErrorKind::RrsigsNotPresent {
                    name: Name::from(&key.name),
                    record_type: key.record_type,
                },
            ));
        }

        // as long as any of the verifications is good, then the RRSET is valid.
        let (proof, rest) = future::select_ok(verifications).await?;
        drop(rest);

        Ok(proof)
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
        }
    }

    /// Get a reference to the underlying handle.
    pub fn inner(&self) -> &H {
        &self.handle
    }
}

impl<H: DnsHandle> DnsHandle for DnssecDnsHandle<H> {
    type Runtime = H::Runtime;

    fn is_verifying_dnssec(&self) -> bool {
        // This handler is always verifying...
        true
    }

    async fn send(&self, mut request: DnsRequest) -> Result<DnsResponse, NetError> {
        // backstop
        if self.request_depth > request.options().max_request_depth {
            error!("exceeded max validation depth");
            return Err(NetError::from("exceeded max validation depth"));
        }

        // dnssec only matters on queries.
        match request.op_code {
            OpCode::Query => {}
            _ => return self.handle.send(request).await,
        }

        // This will fail on no queries, that is a very odd type of request, isn't it?
        // TODO: with mDNS there can be multiple queries
        let Some(query) = request.queries.first().cloned() else {
            return Err(NetError::from("no query in request"));
        };

        request.edns.get_or_insert_with(Edns::new).enable_dnssec();

        request.metadata.authentic_data = true;
        request.metadata.checking_disabled = false;
        let options = *request.options();

        let result = self.handle.send(request).await;
        self.clone_with_context()
            .verify_response(result, query, options)
            .await
    }
}

/// Find the SOA record, if present, in the response and return its name.
///
/// Note that a SOA record may not be present in all responses that must be NSEC/NSEC3 validated.
/// See RFC 4035 B.4 - Referral to Signed Zone, B.5 Referral to Unsigned Zone, B.6 - Wildcard
/// Expansion, RFC 5155 B.3 - Referral to an Opt-Out Unsigned Zone, and B.4 - Wildcard Expansion.
fn find_soa_name(verified_message: &DnsResponse) -> Option<&Name> {
    for record in &verified_message.authorities {
        if record.record_type() == RecordType::SOA && record.proof == Proof::Secure {
            return Some(&record.name);
        }
    }

    None
}

/// This verifies a DNSKEY record against DS records from a secure delegation.
fn verify_dnskey(
    dnskey_record: &RecordRef<'_, DNSKEY>,
    ds_records: &[Record<DS>],
) -> Result<Proof, ProofError> {
    let key_rdata = dnskey_record.data();
    let key_tag = key_rdata.calculate_key_tag().map_err(|_| {
        ProofError::new(
            Proof::Insecure,
            ProofErrorKind::ErrorComputingKeyTag {
                name: dnskey_record.name().clone(),
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
    for ds_record in ds_records.iter().filter(|ds| ds.proof.is_secure()) {
        if ds_record.data.algorithm() != key_algorithm {
            trace!(
                "skipping DS record due to algorithm mismatch, expected algorithm {}: ({}, {})",
                key_algorithm, ds_record.name, ds_record.data,
            );

            continue;
        }

        if ds_record.data.key_tag() != key_tag {
            trace!(
                "skipping DS record due to key tag mismatch, expected tag {key_tag}: ({}, {})",
                ds_record.name, ds_record.data,
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

        if !ds_record
            .data
            .covers(dnskey_record.name(), key_rdata)
            .unwrap_or(false)
        {
            continue;
        }

        debug!(
            "validated dnskey ({}, {key_rdata}) with {} {}",
            dnskey_record.name(),
            ds_record.name,
            ds_record.data,
        );

        // If this key is valid, then it is secure
        return Ok(Proof::Secure);
    }

    trace!("bogus dnskey: {}", dnskey_record.name());
    Err(ProofError::new(
        Proof::Bogus,
        ProofErrorKind::DnsKeyHasNoDs {
            name: dnskey_record.name().clone(),
        },
    ))
}

#[derive(Clone)]
#[allow(clippy::type_complexity)]
struct ValidationCache {
    inner: Arc<Mutex<LruCache<ValidationCacheKey, (Instant, Result<RrsetProof, ProofError>)>>>,
    negative_ttl: Option<RangeInclusive<Duration>>,
    positive_ttl: Option<RangeInclusive<Duration>>,
}

impl ValidationCache {
    fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(LruCache::new(capacity))),
            negative_ttl: Some(Duration::from_secs(1)..=BOGUS_CACHE_TTL),
            positive_ttl: None,
        }
    }

    fn get(
        &self,
        key: &ValidationCacheKey,
        context: &RrsetVerificationContext<'_>,
    ) -> Option<Result<RrsetProof, ProofError>> {
        let (ttl, cached) = self.inner.lock().get_mut(key)?.clone();

        if Instant::now() < ttl {
            debug!(
                name = ?context.key.name,
                record_type = ?context.key.record_type,
                "returning cached DNSSEC validation",
            );
            Some(cached)
        } else {
            debug!(
                name = ?context.key.name,
                record_type = ?context.key.record_type,
                "cached DNSSEC validation expired"
            );
            None
        }
    }

    fn insert(
        &self,
        proof: Result<RrsetProof, ProofError>,
        key: ValidationCacheKey,
        cx: &RrsetVerificationContext<'_>,
    ) {
        debug!(
            name = ?cx.key.name,
            record_type = ?cx.key.record_type,
            "inserting DNSSEC validation cache entry",
        );

        let (mut min, mut max) = (Duration::from_secs(0), Duration::from_secs(u64::MAX));
        if proof.is_err() {
            if let Some(negative_bounds) = self.negative_ttl.clone() {
                (min, max) = negative_bounds.into_inner();
            }
        } else if let Some(positive_bounds) = self.positive_ttl.clone() {
            (min, max) = positive_bounds.into_inner();
        }

        let Some(first_record) = cx.rrset.records.first() else {
            debug!(
                name = ?cx.key.name,
                record_type = ?cx.key.record_type,
                "unable to insert cache entry - no record in rrset",
            );
            return;
        };

        self.inner.lock().insert(
            key,
            (
                Instant::now() + Duration::from_secs(first_record.ttl.into()).clamp(min, max),
                proof.clone(),
            ),
        );
    }
}

#[derive(Eq, PartialEq)]
struct ValidationCacheKey(u64, Query);

impl Hash for ValidationCacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
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
        name = query.name
    );
    proof
}

/// Maximum cache lifetime for an RRset with BOGUS validation.
///
/// RFC 4035 §4.7 requires implementations to assign a small TTL since the wire TTL
/// is attacker-influenced and RFC 9520 §3.2 caps cached resolution failures at 300s.
pub const BOGUS_CACHE_TTL: Duration = Duration::from_secs(60);

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
    use std::time::{Duration, Instant};

    use super::{
        DnsRequestOptions, Proof, ProofError, ProofErrorKind, RrsetVerificationContext,
        ValidationCache,
        context::{Rrset, RrsetMap, RrsigVerificationOutcome, VerifiedRrset, VerifiedRrsetMap},
    };
    use crate::proto::{
        dnssec::rdata::DNSSECRData,
        op::Query,
        rr::{Name, RData, Record, RecordType::A, RrKey, rdata},
    };

    #[test]
    fn validation_cache_clamps_bogus_ttl() {
        // RFC 4035 §4.7:
        //   Since RRsets that fail to validate do not have trustworthy TTLs,
        //   the implementation MUST assign a TTL.  This TTL SHOULD be small,
        //   in order to mitigate the effect of caching the results of an
        //   attack.

        let name = Name::from_ascii("bogus.example.").unwrap();
        let query = Query::new(name.clone(), A);

        let key = RrKey::new((&name).into(), A);
        let mut record = Record::from_rdata(name, 3600, RData::A(rdata::A::new(10, 0, 0, 1)));
        let rrset = Rrset {
            records: vec![&mut record],
            signatures: vec![],
        };

        let cx = RrsetVerificationContext {
            query: &query,
            key: &key,
            rrset: &rrset,
            options: DnsRequestOptions::default(),
            current_time: 0,
        };

        let cache = ValidationCache::new(8);
        let before = Instant::now();
        cache.insert(
            Err(ProofError::new(
                Proof::Bogus,
                ProofErrorKind::Msg("forced bogus".into()),
            )),
            cx.key(),
            &cx,
        );

        let stored_until = cache
            .inner
            .lock()
            .get_mut(&cx.key())
            .expect("entry just inserted")
            .0;
        let lifetime = stored_until.duration_since(before);
        assert!(
            // RFC 4035 §3.2:
            //   resolution failures MUST NOT be cached for longer than 5 minutes.
            lifetime <= Duration::from_secs(60 * 5),
            "Bogus validation cached for {lifetime:?}, must be <= 5m",
        );
    }

    pub(super) fn test_verify_wildcard_expansion(
        answers: &[Record],
        authorities: &[Record],
    ) -> bool {
        let mut answers = answers.to_vec();
        let mut authorities = authorities.to_vec();

        let answers = RrsetMap::new(&mut answers);
        let authorities = RrsetMap::new(&mut authorities);

        let mut answers = mock_verified_rrset_map(answers);
        let authorities = mock_verified_rrset_map(authorities);

        let nsec_records = authorities.gather_nsec_records();
        let nsec3_records = authorities.gather_nsec3_records();

        answers.verify_wildcard_expansion(&nsec_records, &nsec3_records)
    }

    /// Mock out signature verification and return a [`VerifiedRrsetMap`] containing the given
    /// records.
    pub(super) fn mock_verified_rrset_map<'a>(rrsets: RrsetMap<'a>) -> VerifiedRrsetMap<'a> {
        let map = rrsets
            .0
            .into_iter()
            .map(|(key, rrset)| {
                let signatures = rrset
                    .signatures
                    .into_iter()
                    .map(|r| &*r)
                    .collect::<Vec<&Record>>();
                let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &signatures[0].data else {
                    panic!("wrong RDATA in signature record");
                };
                (
                    key.clone(),
                    VerifiedRrset {
                        records: rrset.records,
                        signatures,
                        outcome: RrsigVerificationOutcome::Secure { rrsig },
                    },
                )
            })
            .collect();
        VerifiedRrsetMap(map)
    }
}
