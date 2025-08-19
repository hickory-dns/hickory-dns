// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The `DnssecDnsHandle` is used to validate all DNS responses for correct DNSSEC signatures.

use alloc::{borrow::ToOwned, boxed::Box, sync::Arc, vec::Vec};
use core::{clone::Clone, fmt::Display, pin::Pin};
use std::{
    collections::{HashMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

use futures_util::{
    future::{self, FutureExt},
    stream::{self, Stream, StreamExt},
};
use tracing::{debug, error, trace, warn};

use crate::{
    dnssec::{
        Proof, ProofError, ProofErrorKind, TrustAnchors, Verifier,
        nsec3::verify_nsec3,
        rdata::{DNSKEY, DNSSECRData, DS, NSEC, RRSIG},
    },
    error::{NoRecords, ProtoError, ProtoErrorKind},
    op::{Edns, Message, OpCode, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType, RecordTypeSet, SerialNumber, resource::RecordRef},
    xfer::{DnsRequest, DnsRequestOptions, DnsResponse, FirstAnswer, dns_handle::DnsHandle},
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
                ProtoErrorKind::NoRecordsFound(NoRecords {
                    query,
                    authorities,
                    response_code,
                    ..
                }) => {
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

        // group the record sets by name and type
        //  each rrset type needs to validated independently
        let answers = message.take_answers();
        let authorities = message.take_authorities();
        let additionals = message.take_additionals();

        let answers = self.verify_rrsets(answers, options).await;
        let authorities = self.verify_rrsets(authorities, options).await;
        let additionals = self.verify_rrsets(additionals, options).await;

        message.insert_answers(answers);
        message.insert_authorities(authorities);
        message.insert_additionals(additionals);

        // NSEC and NSEC3 validation:
        if !message.answers().is_empty() {
            return Ok(message);
        }

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
        let nsec_proof = match (!nsec3s.is_empty(), !nsecs.is_empty()) {
            (true, false) => verify_nsec3(
                &query,
                find_soa_name(&message)?,
                message.response_code(),
                message.answers(),
                &nsec3s,
                self.nsec3_soft_iteration_limit,
                self.nsec3_hard_iteration_limit,
            ),
            (false, true) => verify_nsec(
                &query,
                find_soa_name(&message)?,
                message.response_code(),
                nsecs.as_slice(),
            ),
            (true, true) => {
                warn!(
                    "response contains both NSEC and NSEC3 records\nQuery:\n{query:?}\nResponse:\n{message:?}"
                );
                Proof::Bogus
            }
            (false, false) => {
                // Check if the zone is insecure first.
                if let Err(err) = self.find_ds_records(query.name().clone(), options).await {
                    if err.proof == Proof::Insecure {
                        return Ok(message);
                    }
                }

                warn!(
                    "response does not contain NSEC or NSEC3 records. Query: {query:?} response: {message:?}"
                );
                Proof::Bogus
            }
        };

        if !nsec_proof.is_secure() {
            debug!("returning Nsec error for {} {nsec_proof}", query.name());
            // TODO change this to remove the NSECs, like we do for the others?
            return Err(ProtoError::from(ProtoErrorKind::Nsec {
                query: Box::new(query.clone()),
                response: Box::new(message),
                proof: nsec_proof,
            }));
        }

        Ok(message)
    }

    /// This pulls all answers returned in a Message response and returns a future which will
    ///  validate all of them.
    async fn verify_rrsets(&self, records: Vec<Record>, options: DnsRequestOptions) -> Vec<Record> {
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
            let proof = self.verify_rrset(&rrset, rrsigs, options).await;

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
                    (err.proof, None, None)
                }
            };

            let (proof, adjusted_ttl, rrsig_idx) = proof;
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
    /// If Ok, the set of (Proof, AdjustedTTL, and IndexOfRRSIG) is returned, where the index is the one of the RRSIG that validated
    ///   the Rrset
    async fn verify_rrset(
        &self,
        rrset: &Rrset<'_>,
        rrsigs: Vec<RecordRef<'_, RRSIG>>,
        options: DnsRequestOptions,
    ) -> Result<(Proof, Option<u32>, Option<usize>), ProofError> {
        // use the same current time value for all rrsig + rrset pairs.
        let current_time = current_time();

        // DNSKEYS have different logic for their verification
        if matches!(rrset.record_type, RecordType::DNSKEY) {
            let proof = self
                .verify_dnskey_rrset(rrset, &rrsigs, current_time, options)
                .await?;

            return Ok(proof);
        }

        self.verify_default_rrset(rrset, &rrsigs, current_time, options)
            .await
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
    /// If Ok, the set of (Proof, AdjustedTTL, and IndexOfRRSIG) is returned, where the index is the one of the RRSIG that validated
    ///   the Rrset
    ///
    /// # Panics
    ///
    /// This method should only be called to validate DNSKEYs, see `verify_default_rrset` for other record types.
    ///  if a non-DNSKEY RRSET is passed into this method it will always panic.
    async fn verify_dnskey_rrset(
        &self,
        rrset: &Rrset<'_>,
        rrsigs: &[RecordRef<'_, RRSIG>],
        current_time: u32,
        options: DnsRequestOptions,
    ) -> Result<(Proof, Option<u32>, Option<usize>), ProofError> {
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
            self.fetch_ds_records(rrset.name.clone(), options).await?
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
                    verify_rrset_with_dnskey(dnskey, *proof, rrsig, rrset, current_time).ok()
                });

            if let Some(rrset_proof) = rrset_proof {
                return Ok((rrset_proof.0, rrset_proof.1, Some(i)));
            }
        }

        // if it was just the root DNSKEYS with no RRSIG, we'll accept the entire set, or none
        if dnskey_proofs.iter().all(|(proof, ..)| proof.is_secure()) {
            return Ok(dnskey_proofs.pop().unwrap(/* This can not happen due to above test */));
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
        if let Some((query, _resp, proof)) =
            error_opt.as_ref().and_then(|error| error.kind().as_nsec())
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
        rrset: &Rrset<'_>,
        rrsigs: &[RecordRef<'_, RRSIG>],
        current_time: u32,
        options: DnsRequestOptions,
    ) -> Result<(Proof, Option<u32>, Option<usize>), ProofError> {
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

                self.find_ds_records(search_name, options).await?; // insecure will return early here
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
                Some(
                    self.lookup(query.clone(), options)
                        .first_answer()
                        .map(move |result| match result {
                            Ok(message) => {
                                Ok(verify_rrsig_with_keys(message, rrsig, rrset, current_time)
                                    .map(|(proof, adjusted_ttl)| (proof, adjusted_ttl, Some(i))))
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

/// Find the SOA record in the response and return its name.
fn find_soa_name(verified_message: &DnsResponse) -> Result<&Name, ProtoError> {
    for record in verified_message.authorities() {
        if record.record_type() == RecordType::SOA {
            return Ok(record.name());
        }
    }

    Err(ProtoError::from(
        "could not validate negative response missing SOA",
    ))
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
    soa_name: &Name,
    response_code: ResponseCode,
    nsecs: &[(&Name, &NSEC)],
) -> Proof {
    // TODO: consider converting this to Result, and giving explicit reason for the failure

    if response_code != ResponseCode::NXDomain && response_code != ResponseCode::NoError {
        return nsec1_yield(Proof::Bogus, query, "unsupported response code");
    }

    let handle_matching_nsec = |type_set: &RecordTypeSet,
                                message_secure: &str,
                                message_record_exists: &str,
                                message_name_exists| {
        if type_set.contains(query.query_type()) || type_set.contains(RecordType::CNAME) {
            nsec1_yield(Proof::Bogus, query, message_record_exists)
        } else if response_code == ResponseCode::NoError {
            nsec1_yield(Proof::Secure, query, message_secure)
        } else {
            nsec1_yield(Proof::Bogus, query, message_name_exists)
        }
    };

    // Look for an NSEC record that matches the query name first. If such a record exists, then the
    // query type and CNAME must mot be present at this name.
    if let Some((_, nsec_data)) = nsecs.iter().find(|(name, _)| query.name() == *name) {
        return handle_matching_nsec(
            nsec_data.type_set(),
            "direct match",
            "direct match, record should be present",
            "nxdomain when direct match exists",
        );
    }

    if !soa_name.zone_of(query.name()) {
        return nsec1_yield(Proof::Bogus, query, "SOA record is for the wrong zone");
    }

    let Some((covering_nsec_name, covering_nsec_data)) =
        find_nsec_covering_record(soa_name, query.name(), nsecs)
    else {
        return nsec1_yield(
            Proof::Bogus,
            query,
            "no NSEC record matches or covers the query name",
        );
    };

    // Identify the names that exist (including names of empty non terminals) that are parents of
    // the query name. Pick the longest such name, because wildcard synthesis would start looking
    // for a wildcard record there.
    let mut next_closest_encloser = soa_name.clone();
    for seed_name in [covering_nsec_name, covering_nsec_data.next_domain_name()] {
        if !soa_name.zone_of(seed_name) {
            // This is a sanity check, in case the next domain name is out-of-bailiwick.
            continue;
        }
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
        return nsec1_yield(
            Proof::Bogus,
            query,
            "unreachable error constructing wildcard name",
        );
    };
    debug!(%wildcard_name, "looking for NSEC for wildcard");

    if let Some((_, wildcard_nsec_data)) = nsecs.iter().find(|(name, _)| &wildcard_name == *name) {
        // Wildcard NSEC exists.
        return handle_matching_nsec(
            wildcard_nsec_data.type_set(),
            "wildcard match",
            "wildcard match, record should be present",
            "nxdomain when wildcard match exists",
        );
    }

    if find_nsec_covering_record(soa_name, &wildcard_name, nsecs).is_some() {
        // Covering NSEC records exist for both the query name and the wildcard name.
        if response_code == ResponseCode::NXDomain {
            return nsec1_yield(Proof::Secure, query, "no direct match, no wildcard");
        } else {
            return nsec1_yield(Proof::Bogus, query, "expected NXDOMAIN");
        }
    }

    nsec1_yield(
        Proof::Bogus,
        query,
        "no NSEC record matches or covers the wildcard name",
    )
}

/// Find the NSEC record covering `test_name`, if any.
fn find_nsec_covering_record<'a>(
    soa_name: &Name,
    test_name: &Name,
    nsecs: &[(&'a Name, &'a NSEC)],
) -> Option<(&'a Name, &'a NSEC)> {
    nsecs.iter().copied().find(|(nsec_name, nsec_data)| {
        let next_domain_name = nsec_data.next_domain_name();
        soa_name.zone_of(nsec_name)
            && test_name > nsec_name
            && (test_name < next_domain_name || next_domain_name == soa_name)
    })
}

/// Returns the current system time as Unix timestamp in seconds.
fn current_time() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

/// Logs a debug message and returns a [`Proof`]. This is specific to NSEC validation.
fn nsec1_yield(proof: Proof, query: &Query, msg: impl Display) -> Proof {
    proof_log_yield(proof, query, "nsec1", msg)
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
