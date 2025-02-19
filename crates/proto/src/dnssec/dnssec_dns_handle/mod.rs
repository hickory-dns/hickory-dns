// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The `DnssecDnsHandle` is used to validate all DNS responses for correct DNSSEC signatures.

use alloc::{borrow::ToOwned, boxed::Box, string::ToString, sync::Arc, vec::Vec};
use core::{clone::Clone, pin::Pin};
use std::{
    collections::{HashMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

use async_recursion::async_recursion;
use futures_util::{
    future::{self, TryFutureExt},
    stream::{self, Stream, TryStreamExt},
};
use tracing::{debug, trace, warn};

use crate::{
    dnssec::{
        Algorithm, Proof, ProofError, ProofErrorKind, TrustAnchor, Verifier,
        rdata::{DNSKEY, DS, RRSIG},
    },
    error::{ProtoError, ProtoErrorKind},
    op::{Edns, Message, OpCode, Query},
    rr::{Name, Record, RecordData, RecordType, SerialNumber, resource::RecordRef},
    xfer::{DnsRequest, DnsRequestOptions, DnsResponse, FirstAnswer, dns_handle::DnsHandle},
};

use self::rrset::Rrset;

mod nsec3_validation;
use nsec3_validation::verify_nsec3;

use super::{PublicKey, rdata::NSEC};

/// Performs DNSSEC validation of all DNS responses from the wrapped DnsHandle
///
/// This wraps a DnsHandle, changing the implementation `send()` to validate all
///  message responses for Query operations. Update operation responses are not validated by
///  this process.
#[derive(Clone)]
#[must_use = "queries can only be sent through a DnsHandle"]
pub struct DnssecDnsHandle<H>
where
    H: DnsHandle + Unpin + 'static,
{
    handle: H,
    trust_anchor: Arc<TrustAnchor>,
    request_depth: usize,
    minimum_key_len: usize,
    minimum_algorithm: Algorithm, // used to prevent down grade attacks...
}

impl<H> DnssecDnsHandle<H>
where
    H: DnsHandle + Unpin + 'static,
{
    /// Create a new DnssecDnsHandle wrapping the specified handle.
    ///
    /// This uses the compiled in TrustAnchor default trusted keys.
    ///
    /// # Arguments
    /// * `handle` - handle to use for all connections to a remote server.
    pub fn new(handle: H) -> Self {
        Self::with_trust_anchor(handle, Arc::new(TrustAnchor::default()))
    }

    /// Create a new DnssecDnsHandle wrapping the specified handle.
    ///
    /// This allows a custom TrustAnchor to be define.
    ///
    /// # Arguments
    /// * `handle` - handle to use for all connections to a remote server.
    /// * `trust_anchor` - custom DNSKEYs that will be trusted, can be used to pin trusted keys.
    pub fn with_trust_anchor(handle: H, trust_anchor: Arc<TrustAnchor>) -> Self {
        Self {
            handle,
            trust_anchor,
            request_depth: 0,
            minimum_key_len: 0,
            minimum_algorithm: Algorithm::RSASHA256,
        }
    }

    /// An internal function used to clone the handle, but maintain some information back to the
    ///  original handle, such as the request_depth such that infinite recursion does
    ///  not occur.
    fn clone_with_context(&self) -> Self {
        Self {
            handle: self.handle.clone(),
            trust_anchor: Arc::clone(&self.trust_anchor),
            request_depth: self.request_depth + 1,
            minimum_key_len: self.minimum_key_len,
            minimum_algorithm: self.minimum_algorithm,
        }
    }
}

impl<H> DnsHandle for DnssecDnsHandle<H>
where
    H: DnsHandle + Sync + Unpin,
{
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send>>;

    fn is_verifying_dnssec(&self) -> bool {
        // This handler is always verifying...
        true
    }

    fn send<R: Into<DnsRequest>>(&self, request: R) -> Self::Response {
        let mut request = request.into();

        // backstop
        if self.request_depth > request.options().max_request_depth {
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

        Box::pin(
            self.handle
                .send(request)
                .or_else(move |res| {
                    // Translate NoRecordsFound errors into a DnsResponse message so the rest of the
                    // DNSSEC handler chain can validate negative responses.
                    match res.kind() {
                        ProtoErrorKind::NoRecordsFound {
                            query,
                            authorities,
                            response_code,
                            ..
                        } => {
                            let mut msg = Message::new();

                            debug!("translating NoRecordsFound to DnsResponse for {query}");

                            msg.add_query(*query.clone());

                            msg.set_response_code(*response_code);

                            if let Some(authorities) = authorities {
                                for ns in authorities.iter() {
                                    msg.add_name_server(ns.clone());
                                }
                            }

                            match DnsResponse::from_message(msg) {
                                Ok(res) => future::ok(res),
                                Err(_e) => future::err(ProtoError::from(
                                    "unable to construct DnsResponse: {_e:?}",
                                )),
                            }
                        }
                        _ => future::err(ProtoError::from(res.to_string())),
                    }
                })
                .and_then(move |message_response| {
                    verify_response(handle.clone(), message_response, options)
                })
                .and_then(move |verified_message| {
                    future::ready(check_nsec(verified_message, &query))
                }),
        )
    }
}

/// TODO: I've noticed upstream resolvers don't always return NSEC responses
///   this causes bottom up evaluation to fail
///
/// at this point all of the message is verified.
/// This is where NSEC and NSEC3 validation occurs
fn check_nsec(verified_message: DnsResponse, query: &Query) -> Result<DnsResponse, ProtoError> {
    if !verified_message.answers().is_empty() {
        return Ok(verified_message);
    }

    if verified_message
        .name_servers()
        .iter()
        .all(|x| x.proof() == Proof::Insecure)
    {
        return Ok(verified_message);
    }

    // get SOA name
    let soa_name = if let Some(soa_name) = verified_message
        .name_servers()
        .iter()
        // there should only be one
        .find(|rr| rr.record_type() == RecordType::SOA)
        .map(Record::name)
    {
        soa_name
    } else {
        return Err(ProtoError::from(
            "could not validate negative response missing SOA",
        ));
    };

    let nsec3s = verified_message
        .name_servers()
        .iter()
        .filter_map(|rr| {
            rr.data()
                .as_dnssec()?
                .as_nsec3()
                .map(|data| (rr.name(), data))
        })
        .collect::<Vec<_>>();

    let nsecs = verified_message
        .name_servers()
        .iter()
        .filter_map(|rr| {
            rr.data()
                .as_dnssec()?
                .as_nsec()
                .map(|data| (rr.name(), data))
        })
        .collect::<Vec<_>>();

    // Both NSEC and NSEC3 records cannot coexist during
    // transition periods, as per RFC 5515 10.4.3 and
    // 10.5.2
    let nsec_proof = match (!nsec3s.is_empty(), !nsecs.is_empty()) {
        (true, false) => verify_nsec3(
            query,
            soa_name,
            verified_message.response_code(),
            verified_message.answers(),
            &nsec3s,
        ),
        (false, true) => verify_nsec(query, soa_name, nsecs.as_slice()),
        (true, true) => {
            warn!(
                "response contains both NSEC and NSEC3 records\nQuery:\n{query:?}\nResponse:\n{verified_message:?}"
            );
            Proof::Bogus
        }
        (false, false) => {
            warn!(
                "response does not contain NSEC or NSEC3 records. Query: {query:?} response: {verified_message:?}"
            );
            Proof::Bogus
        }
    };

    if !nsec_proof.is_secure() {
        debug!("returning Nsec error for {} {nsec_proof}", query.name());
        // TODO change this to remove the NSECs, like we do for the others?
        return Err(ProtoError::from(ProtoErrorKind::Nsec {
            query: Box::new(query.clone()),
            proof: nsec_proof,
        }));
    }

    Ok(verified_message)
}

/// Extracts the different sections of a message and verifies the RRSIGs
async fn verify_response<H>(
    handle: DnssecDnsHandle<H>,
    mut message: DnsResponse,
    options: DnsRequestOptions,
) -> Result<DnsResponse, ProtoError>
where
    H: DnsHandle + Sync + Unpin,
{
    debug!(
        "validating message_response: {}, with {} trust_anchors",
        message.id(),
        handle.trust_anchor.len(),
    );

    // group the record sets by name and type
    //  each rrset type needs to validated independently
    let answers = message.take_answers();
    let nameservers = message.take_name_servers();
    let additionals = message.take_additionals();

    let answers = verify_rrsets(&handle, answers, options).await;
    let nameservers = verify_rrsets(&handle, nameservers, options).await;
    let additionals = verify_rrsets(&handle, additionals, options).await;

    message.insert_answers(answers);
    message.insert_name_servers(nameservers);
    message.insert_additionals(additionals);

    Ok(message)
}

/// This pulls all answers returned in a Message response and returns a future which will
///  validate all of them.
#[allow(clippy::type_complexity)]
async fn verify_rrsets<H>(
    handle: &DnssecDnsHandle<H>,
    records: Vec<Record>,
    options: DnsRequestOptions,
) -> Vec<Record>
where
    H: DnsHandle + Sync + Unpin,
{
    let mut rrset_types: HashSet<(Name, RecordType)> = HashSet::new();

    for rrset in records
        .iter()
        .filter(|rr| {
            !is_dnssec(rr, RecordType::RRSIG) &&
                             // if we are at a depth greater than 1, we are only interested in proving evaluation chains
                             //   this means that only DNSKEY and DS are interesting at that point.
                             //   this protects against looping over things like NS records and DNSKEYs in responses.
                             // TODO: is there a cleaner way to prevent cycles in the evaluations?
                                          (handle.request_depth <= 1 ||
                                           is_dnssec(rr, RecordType::DNSKEY) ||
                                           is_dnssec(rr, RecordType::DS))
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
                .map(|rr| rr.name() == &name && rr.data().type_covered() == record_type)
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
            .filter(|rrsig| rrsig.data().type_covered() == record_type)
            .collect();

        // if there is already an active validation going on, assume the other validation will
        //  complete properly or error if it is invalid

        // TODO: support non-IN classes?
        debug!(
            "verifying: {name} record_type: {record_type}, rrsigs: {rrsig_len}",
            rrsig_len = rrsigs.len()
        );

        // verify this rrset
        let proof = verify_rrset(handle.clone_with_context(), &rrset, rrsigs, options).await;

        let proof = match proof {
            Ok(proof) => {
                debug!("verified: {name} record_type: {record_type}",);
                proof
            }
            Err(ProofError { proof, kind }) => {
                match kind {
                    ProofErrorKind::DsResponseNsec { .. } => {
                        debug!("verified insecure {name}/{record_type}")
                    }
                    _ => debug!("failed to verify: {name} record_type: {record_type}: {kind}"),
                }
                (proof, None, None)
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

// TODO: is this method useful/necessary?
fn is_dnssec<D: RecordData>(rr: &Record<D>, dnssec_type: RecordType) -> bool {
    rr.record_type().is_dnssec() && dnssec_type.is_dnssec() && rr.record_type() == dnssec_type
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
async fn verify_rrset<H>(
    handle: DnssecDnsHandle<H>,
    rrset: &Rrset<'_>,
    rrsigs: Vec<RecordRef<'_, RRSIG>>,
    options: DnsRequestOptions,
) -> Result<(Proof, Option<u32>, Option<usize>), ProofError>
where
    H: DnsHandle + Sync + Unpin,
{
    // use the same current time value for all rrsig + rrset pairs.
    let current_time = current_time();

    // DNSKEYS have different logic for their verification
    if matches!(rrset.record_type(), RecordType::DNSKEY) {
        let proof = verify_dnskey_rrset(
            handle.clone_with_context(),
            rrset,
            &rrsigs,
            current_time,
            options,
        )
        .await?;

        return Ok(proof);
    }

    verify_default_rrset(
        &handle.clone_with_context(),
        rrset,
        &rrsigs,
        current_time,
        options,
    )
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
async fn verify_dnskey_rrset<H>(
    handle: DnssecDnsHandle<H>,
    rrset: &Rrset<'_>,
    rrsigs: &Vec<RecordRef<'_, RRSIG>>,
    current_time: u32,
    options: DnsRequestOptions,
) -> Result<(Proof, Option<u32>, Option<usize>), ProofError>
where
    H: DnsHandle + Sync + Unpin,
{
    // Ensure that this method is not misused
    if RecordType::DNSKEY != rrset.record_type() {
        panic!("All other RRSETs must use verify_default_rrset");
    }

    debug!(
        "dnskey validation {}, record_type: {:?}",
        rrset.name(),
        rrset.record_type()
    );

    let mut dnskey_proofs =
        Vec::<(Proof, Option<u32>, Option<usize>)>::with_capacity(rrset.records().len());
    dnskey_proofs.resize(rrset.records().len(), (Proof::Bogus, None, None));

    // check if the DNSKEYs are in the root store
    for (r, proof) in rrset.records().iter().zip(dnskey_proofs.iter_mut()) {
        let Some(dnskey) = r.try_borrow::<DNSKEY>() else {
            continue;
        };

        proof.0 = is_dnskey_in_root_store(&handle, &dnskey);
    }

    // if not all of the DNSKEYs are in the root store, then we need to look for DS records to verify
    let ds_records = if !dnskey_proofs.iter().all(|p| p.0.is_secure()) && !rrset.name().is_root() {
        // need to get DS records for each DNSKEY
        //   there will be a DS record for everything under the root keys
        find_ds_records(&handle, rrset.name().clone(), options).await?
    } else {
        debug!("ignoring DS lookup for root zone or registered keys");
        Vec::default()
    };

    // if the DS records are not empty and they also have no supported algorithms, then this is INSECURE
    // for secure DS records the BOGUS check happens after DNSKEYs are evaluated against the DS
    if ds_records
        .iter()
        .filter(|ds| ds.proof().is_secure() || ds.proof().is_insecure())
        .all(|ds| !ds.data().algorithm().is_supported() || !ds.data().digest_type().is_supported())
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
    for (r, proof) in rrset.records().iter().zip(dnskey_proofs.iter_mut()) {
        let Some(dnskey) = r.try_borrow() else {
            continue;
        };

        if proof.0.is_secure() {
            continue;
        }

        // need to track each proof on each dnskey to ensure they are all validated
        match verify_dnskey(&dnskey, &ds_records) {
            Ok(pf) => {
                *proof = (pf, None, None);
            }
            Err(err) => {
                *proof = (err.proof, None, None);
            }
        }
    }

    // There may have been a key-signing key for the zone,
    //   we need to verify all the other DNSKEYS in the zone against it (i.e. the rrset)
    for (i, rrsig) in rrsigs.iter().enumerate() {
        // These should all match, but double checking...
        let signer_name = rrsig.data().signer_name();

        let rrset_proof = rrset
            .records()
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
        trace!("bogus dnskey: {}", rrset.name());
        return Err(ProofError::new(
            Proof::Bogus,
            ProofErrorKind::DsRecordsButNoDnskey {
                name: rrset.name().clone(),
            },
        ));
    }

    // There were DS records or RRSIGs, but none of the signatures could be validated, so we're in a
    // bogus state. If there was no DS record, it should have gotten an NSEC upstream, and returned
    // early above.
    trace!("no dnskey found: {}", rrset.name());
    Err(ProofError::new(
        Proof::Bogus,
        ProofErrorKind::DnskeyNotFound {
            name: rrset.name().clone(),
        },
    ))
}

/// Verifies that the key is a trust anchor.
///
/// # Returns
///
/// Proof::Secure if registered in the root store, Proof::Bogus if not
fn is_dnskey_in_root_store<H>(handle: &DnssecDnsHandle<H>, rr: &RecordRef<'_, DNSKEY>) -> Proof
where
    H: DnsHandle + Sync + Unpin,
{
    let dns_key = rr.data();
    let pub_key = dns_key.public_key();

    // Checks to see if the key is valid against the registered root certificates
    if handle
        .trust_anchor
        .contains_dnskey_bytes(pub_key.public_bytes(), pub_key.algorithm())
    {
        debug!(
            "validated dnskey with trust_anchor: {}, {dns_key}",
            rr.name(),
        );

        Proof::Secure
    } else {
        Proof::Bogus
    }
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

#[async_recursion]
async fn find_ds_records<H>(
    handle: &DnssecDnsHandle<H>,
    zone: Name,
    options: DnsRequestOptions,
) -> Result<Vec<Record<DS>>, ProofError>
where
    H: DnsHandle + Sync + Unpin,
{
    // need to get DS records for each DNSKEY
    //   there will be a DS record for everything under the root keys
    let ds_message = handle
        .lookup(Query::query(zone.clone(), RecordType::DS), options)
        .first_answer()
        .await;

    let error: ProtoError = match ds_message {
        Ok(mut ds_message)
            if ds_message
                .answers()
                .iter()
                .filter(|r| r.record_type() == RecordType::DS)
                .any(|r| r.proof().is_secure()) =>
        {
            // this is a secure DS record, perfect

            let all_records = ds_message
                .take_answers()
                .into_iter()
                .filter_map(|r| Record::<DS>::try_from(r).ok());

            let mut supported_records = vec![];
            let mut all_unknown = None;
            for record in all_records {
                // A chain can be either SECURE or INSECURE, but we should not trust BOGUS or other records
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
                ProtoError::from(ProtoErrorKind::NoError)
            }
        }
        Ok(_) => ProtoError::from(ProtoErrorKind::NoError),
        Err(error) => error,
    };

    // if the DS record was an NSEC then we have an insecure zone
    if let Some((query, _proof)) = error
        .kind()
        .as_nsec()
        .filter(|(_query, proof)| proof.is_insecure())
    {
        debug!(
            "marking {} as insecure based on NSEC/NSEC3 proof",
            query.name()
        );
        return Err(ProofError::new(
            Proof::Insecure,
            ProofErrorKind::DsResponseNsec {
                name: query.name().to_owned(),
            },
        ));
    }

    // otherwise we need to recursively discover the status of DS up the chain,
    //   if we find a valid DS, then we're in a Bogus state,
    //   if we get ProofError, our result is the same

    let parent = zone.base_name();
    if zone == parent {
        // zone is `.`. do not call `find_ds_records(.., parent, ..)` or that will lead to infinite
        // recursion
        return Err(ProofError::new(
            Proof::Bogus,
            ProofErrorKind::DsRecordShouldExist { name: zone },
        ));
    }

    match find_ds_records(handle, parent, options).await {
        Ok(ds_records) if !ds_records.is_empty() => Err(ProofError::new(
            Proof::Bogus,
            ProofErrorKind::DsRecordShouldExist { name: zone },
        )),
        result => result,
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
#[allow(clippy::blocks_in_conditions)]
async fn verify_default_rrset<H>(
    handle: &DnssecDnsHandle<H>,
    rrset: &Rrset<'_>,
    rrsigs: &Vec<RecordRef<'_, RRSIG>>,
    current_time: u32,
    options: DnsRequestOptions,
) -> Result<(Proof, Option<u32>, Option<usize>), ProofError>
where
    H: DnsHandle + Sync + Unpin,
{
    // Ensure that this method is not misused
    if RecordType::DNSKEY == rrset.record_type() {
        panic!("DNSKEYs must be validated with verify_dnskey_rrset");
    }

    if rrsigs.is_empty() {
        // Decide if we're:
        //    1) "insecure", the zone has a valid NSEC for the DS record in the parent zone
        //    2) "bogus", the parent zone has a valid DS record, but the child zone didn't have the RRSIGs/DNSKEYs
        find_ds_records(handle, rrset.name().clone(), options).await?; // insecure will return early here

        return Err(ProofError::new(
            Proof::Bogus,
            ProofErrorKind::RrsigsNotPresent {
                name: rrset.name().clone(),
                record_type: rrset.record_type(),
            },
        ));
    }

    // the record set is going to be shared across a bunch of futures, Arc for that.
    trace!(
        "default validation {}, record_type: {:?}",
        rrset.name(),
        rrset.record_type()
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
            let handle = handle.clone_with_context();
            let query = Query::query(rrsig.data().signer_name().clone(), RecordType::DNSKEY);

            if i > MAX_RRSIGS_PER_RRSET {
                warn!("too many ({i}) RRSIGs for rrset {rrset:?}; skipping");
                return None;
            }

            // TODO: Should this sig.signer_name should be confirmed to be in the same zone as the rrsigs and rrset?
            Some(handle
                .lookup(query.clone(), options)
                .first_answer()
                .map_err(|proto| {
                    ProofError::new(Proof::Bogus, ProofErrorKind::Proto { query, proto })
                })
                .map_ok(move |message| {
                    let mut tag_count = HashMap::<u16, usize>::new();

                    // DNSKEYs were already validated by the inner query in the above lookup
                    let dnskeys = message
                        .answers()
                        .iter()
                        .filter_map(|r| {
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
                                    return Some((proof.0, proof.1, Some(i)));
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
                        Some((Proof::Insecure, None, None))
                    } else {
                        None
                    }
                }))
        })
        .collect::<Vec<_>>();

    // if there are no available verifications, then we are in a failed state.
    if verifications.is_empty() {
        return Err(ProofError::new(
            Proof::Bogus,
            ProofErrorKind::RrsigsNotPresent {
                name: rrset.name().clone(),
                record_type: rrset.record_type(),
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
        ProofError::new(Proof::Bogus, ProofErrorKind::RrsigsUnverified{name: rrset.name().clone(), record_type: rrset.record_type()})
    )
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
                    key_tag: rrsig.data().key_tag(),
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
                key_tag: rrsig.data().key_tag(),
            },
        ));
    } // TODO: does this need to be validated? RFC 5011
    if !dnskey.data().zone_key() {
        return Err(ProofError::new(
            Proof::Bogus,
            ProofErrorKind::NotZoneDnsKey {
                name: dnskey.name().clone(),
                key_tag: rrsig.data().key_tag(),
            },
        ));
    }
    if dnskey.data().algorithm() != rrsig.data().algorithm() {
        return Err(ProofError::new(
            Proof::Bogus,
            ProofErrorKind::AlgorithmMismatch {
                rrsig: rrsig.data().algorithm(),
                dnskey: dnskey.data().algorithm(),
            },
        ));
    }

    let validity = check_rrsig_validity(*rrsig, rrset, dnskey, current_time);
    if !matches!(validity, RrsigValidity::ValidRrsig) {
        // TODO better error handling when the error payload is not immediately discarded by
        // the caller
        return Err(ProofError::new(
            Proof::Bogus,
            ProofErrorKind::Msg(format!("{:?}", validity)),
        ));
    }

    dnskey
        .data()
        .verify_rrsig(
            rrset.name(),
            rrset.record_class(),
            rrsig.data(),
            rrset.records().iter().copied(),
        )
        .map(|_| {
            debug!(
                "validated ({}, {:?}) with ({}, {})",
                rrset.name(),
                rrset.record_type(),
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
                rrset.name(),
                rrset.record_type(),
                dnskey.name(),
                dnskey.data()
            );
            ProofError::new(
                Proof::Bogus,
                ProofErrorKind::DnsKeyVerifyRrsig {
                    name: dnskey.name().clone(),
                    key_tag: rrsig.data().key_tag(),
                    error: e,
                },
            )
        })
}

// see section 5.3.1 of RFC4035 "Checking the RRSIG RR Validity"
fn check_rrsig_validity(
    rrsig: RecordRef<'_, RRSIG>,
    rrset: &Rrset<'_>,
    dnskey: RecordRef<'_, DNSKEY>,
    current_time: u32,
) -> RrsigValidity {
    let current_time = SerialNumber(current_time);
    let expiration = rrsig.data().sig_expiration();
    let inception = rrsig.data().sig_inception();

    let Ok(dnskey_key_tag) = dnskey.data().calculate_key_tag() else {
        return RrsigValidity::WrongDnskey;
    };

    if !(
        // "The RRSIG RR and the RRset MUST have the same owner name and the same class"
        rrsig.name() == rrset.name() &&
        rrsig.dns_class() == rrset.record_class() &&

        // "The RRSIG RR's Signer's Name field MUST be the name of the zone that contains the RRset"
        // TODO(^) the zone name is in the SOA record, which is not accessible from here

        // "The RRSIG RR's Type Covered field MUST equal the RRset's type"
        rrsig.data().type_covered() == rrset.record_type() &&

        // "The number of labels in the RRset owner name MUST be greater than or equal to the value
        // in the RRSIG RR's Labels field"
        rrset.name().num_labels() >= rrsig.data().num_labels()
    ) {
        return RrsigValidity::WrongRrsig;
    }

    // Section 3.1.5 of RFC4034 states that 'all comparisons involving these fields MUST use
    // "Serial number arithmetic", as defined in RFC1982'
    if !(
        // "The validator's notion of the current time MUST be less than or equal to the time listed
        // in the RRSIG RR's Expiration field"
        current_time <= expiration &&

        // "The validator's notion of the current time MUST be greater than or equal to the time
        // listed in the RRSIG RR's Inception field"
        current_time >= inception
    ) {
        return RrsigValidity::ExpiredRrsig;
    }

    if !(
        // "The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST match the owner name,
        // algorithm, and key tag for some DNSKEY RR in the zone's apex DNSKEY RRset"
        rrsig.data().signer_name() == dnskey.name() &&
        rrsig.data().algorithm() == dnskey.data().algorithm() &&
        rrsig.data().key_tag() == dnskey_key_tag &&

        // "The matching DNSKEY RR MUST be present in the zone's apex DNSKEY RRset, and MUST have the
        // Zone Flag bit (DNSKEY RDATA Flag bit 7) set"
        dnskey.data().zone_key()
    ) {
        return RrsigValidity::WrongDnskey;
    }

    RrsigValidity::ValidRrsig
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
#[allow(clippy::blocks_in_conditions)]
#[doc(hidden)]
pub fn verify_nsec(query: &Query, soa_name: &Name, nsecs: &[(&Name, &NSEC)]) -> Proof {
    // TODO: consider converting this to Result, and giving explicit reason for the failure

    // DS queries resulting in NoData responses with accompanying NSEC records can prove that an
    // insecure delegation exists; this is used to return Proof::Insecure instead of Proof::Secure
    // in those situations.
    let ds_proof_override = match query.query_type() {
        RecordType::DS => Proof::Insecure,
        _ => Proof::Secure,
    };

    // first look for a record with the same name
    //  if they are, then the query_type should not exist in the NSEC record.
    //  if we got an NSEC record of the same name, but it is listed in the NSEC types,
    //    WTF? is that bad server, bad record
    if let Some((_, nsec_data)) = nsecs.iter().find(|(name, _)| query.name() == *name) {
        if !nsec_data.type_bit_maps().contains(&query.query_type()) {
            return proof_log_yield(ds_proof_override, query.name(), "nsec1", "direct match");
        } else {
            return proof_log_yield(Proof::Bogus, query.name(), "nsec1", "direct match");
        }
    }

    let verify_nsec_coverage = |query_name: &Name| -> bool {
        nsecs.iter().any(|(nsec_name, nsec_data)| {
            // the query name must be greater than nsec's label (or equal in the case of wildcard)
            query_name >= nsec_name && {
                // the query name is less than the next name
                // or this record wraps the end, i.e. is the last record
                query_name < nsec_data.next_domain_name()
                    || nsec_data.next_domain_name() < nsec_name
            }
        })
    };

    // continue to validate there is no wildcard
    if !verify_nsec_coverage(query.name()) {
        return proof_log_yield(Proof::Bogus, query.name(), "nsec1", "no wildcard");
    }

    // validate ANY or *.domain record existence

    // we need the wildcard proof, but make sure that it's still part of the zone.
    let wildcard = query.name().base_name();
    let wildcard = if soa_name.zone_of(&wildcard) {
        wildcard
    } else {
        soa_name.clone()
    };

    // don't need to validate the same name again
    if wildcard == *query.name() {
        // this was validated by the nsec coverage over the query.name()
        proof_log_yield(
            ds_proof_override,
            query.name(),
            "nsec1",
            "direct wildcard match",
        )
    } else {
        // this is the final check, return it's value
        //  if there is wildcard coverage, we're good.
        if verify_nsec_coverage(&wildcard) {
            proof_log_yield(
                ds_proof_override,
                query.name(),
                "nsec1",
                "covering wildcard match",
            )
        } else {
            proof_log_yield(
                Proof::Bogus,
                query.name(),
                "nsec1",
                "covering wildcard match",
            )
        }
    }
}

/// Returns the current system time as Unix timestamp in seconds.
fn current_time() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

/// Logs a debug message and yields a Proof type for return
fn proof_log_yield(proof: Proof, name: &Name, nsec_type: &str, msg: &str) -> Proof {
    debug!("{nsec_type} proof for {name}, returning {proof}: {msg}");
    proof
}

mod rrset {
    use alloc::vec::Vec;

    use crate::rr::{DNSClass, Name, Record, RecordType};

    // TODO: combine this with crate::rr::RecordSet?
    #[derive(Debug)]
    pub(super) struct Rrset<'r> {
        name: Name,
        record_class: DNSClass,
        record_type: RecordType,
        records: Vec<&'r Record>,
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

        pub(super) fn name(&self) -> &Name {
            &self.name
        }

        pub(super) fn record_class(&self) -> DNSClass {
            self.record_class
        }

        pub(super) fn record_type(&self) -> RecordType {
            self.record_type
        }

        pub(super) fn records(&self) -> &[&Record] {
            &self.records
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
