// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The `DnssecDnsHandle` is used to validate all DNS responses for correct DNSSEC signatures.

use alloc::{borrow::ToOwned, boxed::Box, vec::Vec};
use core::{clone::Clone, pin::Pin};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_recursion::async_recursion;
use futures_util::{
    future::{self, FutureExt, TryFutureExt},
    stream::{self, Stream, TryStreamExt},
};
use tracing::{debug, trace, warn};

use crate::{
    error::{ProtoError, ProtoErrorKind},
    op::{Edns, OpCode, Query},
    rr::{
        dnssec::{
            rdata::{DNSSECRData, DNSKEY, DS, RRSIG},
            Algorithm, Proof, ProofError, ProofErrorKind, SupportedAlgorithms, TrustAnchor,
        },
        rdata::opt::EdnsOption,
        Name, RData, Record, RecordData, RecordType, SerialNumber,
    },
    xfer::{dns_handle::DnsHandle, DnsRequest, DnsRequestOptions, DnsResponse, FirstAnswer},
};

#[cfg(feature = "dnssec")]
use crate::rr::dnssec::Verifier;
#[cfg(feature = "dnssec")]
use crate::rr::resource::RecordRef;

use self::rrset::Rrset;

use nsec3_validation::verify_nsec3;
mod nsec3_validation;

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

        // This will panic on no queries, that is a very odd type of request, isn't it?
        // TODO: with mDNS there can be multiple queries
        let query = if let Some(query) = request.queries().first().cloned() {
            query
        } else {
            return Box::pin(stream::once(future::err(ProtoError::from(
                "no query in request",
            ))));
        };

        let handle: Self = self.clone_with_context();

        // TODO: cache response of the server about understood algorithms
        #[cfg(feature = "dnssec")]
        {
            let edns = request.extensions_mut().get_or_insert_with(Edns::new);
            edns.set_dnssec_ok(true);

            // send along the algorithms which are supported by this handle
            let mut algorithms = SupportedAlgorithms::new();
            #[cfg(feature = "dnssec-ring")]
            {
                algorithms.set(Algorithm::ED25519);
            }
            algorithms.set(Algorithm::ECDSAP256SHA256);
            algorithms.set(Algorithm::ECDSAP384SHA384);
            algorithms.set(Algorithm::RSASHA256);

            let dau = EdnsOption::DAU(algorithms);
            let dhu = EdnsOption::DHU(algorithms);

            edns.options_mut().insert(dau);
            edns.options_mut().insert(dhu);
        }

        request.set_authentic_data(true);
        request.set_checking_disabled(false);
        let options = *request.options();

        Box::pin(
            self.handle
                .send(request)
                .and_then(move |message_response| {
                    // group the record sets by name and type
                    //  each rrset type needs to validated independently
                    debug!(
                        "validating message_response: {}, with {} trust_anchors",
                        message_response.id(),
                        handle.trust_anchor.len(),
                    );
                    verify_response(handle.clone(), message_response, options)
                        .map(Result::<DnsResponse, ProtoError>::Ok)
                })
                .and_then(move |verified_message| {
                    // TODO: I've noticed upstream resolvers don't always return NSEC responses
                    //   this causes bottom up evaluation to fail

                    // at this point all of the message is verified.
                    // This is where NSEC and NSEC3 validation occurs

                    if verified_message.answers().is_empty() {
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
                            return future::err(ProtoError::from(
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
                            .filter(|rr| is_dnssec(rr, RecordType::NSEC))
                            .collect::<Vec<_>>();

                        // Both NSEC and NSEC3 records cannot coexist during
                        // transition periods, as per RFC 5515 10.4.3 and
                        // 10.5.2
                        let nsec_proof = match (nsec3s.is_empty(), nsecs.is_empty()) {
                            (false, true) => verify_nsec3(
                                &query,
                                soa_name,
                                verified_message.response_code(),
                                verified_message.answers(),
                                &nsec3s,
                            ),
                            (true, false) => verify_nsec(&query, soa_name, nsecs.as_slice()),
                            (true, true) => {
                                warn!(
                                    "response contains both NSEC and NSEC3 records\nQuery:\n{query:?}\nResponse:\n{verified_message:?}"
                                );
                                Proof::Bogus
                            },
                            (false, false) => Proof::Bogus,
                        };

                        if !nsec_proof.is_secure() {
                            // TODO change this to remove the NSECs, like we do for the others?
                            return future::err(ProtoError::from(ProtoErrorKind::Nsec {
                                query: query.clone(),
                                proof: nsec_proof,
                            }));
                        }
                    }

                    future::ok(verified_message)
                }),
        )
    }
}

/// Extracts the different sections of a message and verifies the RRSIGs
async fn verify_response<H>(
    handle: DnssecDnsHandle<H>,
    mut message: DnsResponse,
    options: DnsRequestOptions,
) -> DnsResponse
where
    H: DnsHandle + Sync + Unpin,
{
    let answers = message.take_answers();
    let nameservers = message.take_name_servers();
    let additionals = message.take_additionals();

    let answers = verify_rrsets(handle.clone(), answers, options).await;
    let nameservers = verify_rrsets(handle.clone(), nameservers, options).await;
    let additionals = verify_rrsets(handle.clone(), additionals, options).await;

    message.insert_answers(answers);
    message.insert_name_servers(nameservers);
    message.insert_additionals(additionals);

    message
}

/// This pulls all answers returned in a Message response and returns a future which will
///  validate all of them.
#[allow(clippy::type_complexity)]
async fn verify_rrsets<H>(
    handle: DnssecDnsHandle<H>,
    records: Vec<Record>,
    options: DnsRequestOptions,
) -> Vec<Record>
where
    H: DnsHandle + Sync + Unpin,
{
    let mut rrset_types: HashSet<(Name, RecordType)> = HashSet::new();
    let mut rrset_proofs: HashMap<(Name, RecordType), (Proof, Option<u32>)> = HashMap::new();

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

    // collect all the rrsets to verify
    // TODO: is there a way to get rid of this clone() safely?
    for (name, record_type) in rrset_types {
        let mut rrs_to_verify = records
            .iter()
            .filter(|rr| rr.record_type() == record_type && rr.name() == &name);

        let mut rrset = Rrset::new(rrs_to_verify.next().unwrap());
        rrs_to_verify.for_each(|rr| rrset.add(rr));

        // RRSIGS are never modified after this point
        let rrsigs: Vec<_> = records
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
        let proof = verify_rrset(handle.clone_with_context(), rrset, rrsigs, options).await;

        let (proof, adjusted_ttl) = match proof {
            Ok((proof, adjusted_ttl)) => {
                debug!("verified: {name} record_type: {record_type}",);
                (proof, adjusted_ttl)
            }
            Err(ProofError { proof, kind }) => {
                debug!("failed to verify: {name} record_type: {record_type}: {kind}",);
                (proof, None)
            }
        };

        rrset_proofs.insert((name, record_type), (proof, adjusted_ttl));
    }

    // set the proofs of all the records, all records are returned, it's up to downstream users to check for correctness
    let mut records = records;
    for record in &mut records {
        // the RRSIG used to validate a record inherits the outcome of the validation
        // for RRSIGs, we need to use their TYPE_COVERED field instead of `RecordType::RRSIG` as the
        // `RecordType` key in `rrset_proofs`
        let record_type = if let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = record.data() {
            rrsig.type_covered()
        } else {
            record.record_type()
        };

        if let Some((proof, adjusted_ttl)) = rrset_proofs.get(&(record.name().clone(), record_type))
        {
            record.set_proof(*proof);
            if let (Proof::Secure, Some(ttl)) = (proof, adjusted_ttl) {
                record.set_ttl(*ttl);
            }
        }
    }

    records
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
async fn verify_rrset<H>(
    handle: DnssecDnsHandle<H>,
    rrset: Rrset<'_>,
    rrsigs: Vec<RecordRef<'_, RRSIG>>,
    options: DnsRequestOptions,
) -> Result<(Proof, Option<u32>), ProofError>
where
    H: DnsHandle + Sync + Unpin,
{
    // wrapper for some of the type conversion for typed DNSKEY fn calls.

    if matches!(rrset.record_type(), RecordType::DNSKEY) {
        let is_trust_anchor =
            verify_dnskey_rrset(handle.clone_with_context(), &rrset, options).await?;

        if is_trust_anchor {
            return Ok((Proof::Secure, None));
        }
    }

    verify_default_rrset(&handle.clone_with_context(), rrset, rrsigs, options).await
}

/// Additional, DNSKEY-specific verification
///
/// In addition to RRSIG validation, which happens in `verify_default_rrset`, a DNSKEY needs to be
/// checked against a DS record provided by the parent zone.
///
/// A DNSKEY that's part of the trust anchor does not need to have its DS record (which may
/// not exist as it's the case of the root zone) nor its RRSIG validated.
///
/// This function returns `true` when the DNSKEY is in the trust anchor; `false` when it's not and
/// its DS was validated; or an error when DS validation failed.
async fn verify_dnskey_rrset<H>(
    handle: DnssecDnsHandle<H>,
    rrset: &Rrset<'_>,
    options: DnsRequestOptions,
) -> Result<bool, ProofError>
where
    H: DnsHandle + Sync + Unpin,
{
    trace!(
        "dnskey validation {}, record_type: {:?}",
        rrset.name(),
        rrset.record_type()
    );

    // check the DNSKEYS against the trust_anchor, if it's approved allow it.
    //   this includes the root keys
    let mut all_unsupported = None;
    for r in rrset.records().iter() {
        let Some(key_rdata) = DNSKEY::try_borrow(r.data()) else {
            continue;
        };

        let algorithm = key_rdata.algorithm();
        if algorithm.is_supported() {
            all_unsupported = Some(false);
        } else {
            debug!("unsupported key algorithm {algorithm} in {key_rdata}",);

            all_unsupported.get_or_insert(true);
            continue;
        }

        if !handle
            .trust_anchor
            .contains_dnskey_bytes(key_rdata.public_key())
        {
            continue;
        }

        debug!(
            "validated dnskey with trust_anchor: {}, {key_rdata}",
            rrset.name(),
        );

        return Ok(true);
    }

    if all_unsupported.unwrap_or_default() {
        // cannot validate; mark as insecure
        return Err(ProofError::new(
            Proof::Insecure,
            ProofErrorKind::UnsupportedKeyAlgorithm,
        ));
    }

    // need to get DS records for each DNSKEY
    //   there will be a DS record for everything under the root keys
    let ds_records = find_ds_records(&handle, rrset.name().clone(), options).await?;
    for rr in rrset.records().iter() {
        let Some(key_rdata) = DNSKEY::try_borrow(rr.data()) else {
            continue;
        };

        let Ok(key_tag) = key_rdata.calculate_key_tag() else {
            continue;
        };
        let key_algorithm = key_rdata.algorithm();
        for r in ds_records.iter() {
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

            if !r.data().covers(rrset.name(), key_rdata).unwrap_or(false) {
                continue;
            }

            debug!(
                "validated dnskey ({}, {key_rdata}) with {} {}",
                rrset.name(),
                r.name(),
                r.data(),
            );

            // If all the keys are valid, then we are secure
            // FIXME: what if only some are invalid? we should return the good ones?
            return Ok(false);
        }
    }

    if !ds_records.is_empty() {
        // there were DS records, but no DNSKEYs, we're in a bogus state
        trace!("bogus dnskey: {}", rrset.name());
        Err(ProofError::new(
            Proof::Bogus,
            ProofErrorKind::DsRecordsButNoDnskey {
                name: rrset.name().clone(),
            },
        ))
    } else {
        // if rrset.records.is_empty() && ds_records.is_empty()
        // there were DS records, but no DNSKEYs, we're in a bogus state
        //   if there was no DS record, it should have gotten an NSEC upstream, and returned early above
        //   and all other cases...
        trace!("no dnskey found: {}", rrset.name());
        Err(ProofError::new(
            Proof::Indeterminate,
            ProofErrorKind::DnskeyNotFound {
                name: rrset.name().clone(),
            },
        ))
    }
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
                if matches!(record.data().algorithm(), Algorithm::Unknown(_)) {
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
    if let Some((query, proof)) = error
        .kind()
        .as_nsec()
        .filter(|(_query, proof)| proof.is_secure())
    {
        return Err(ProofError::new(
            *proof,
            ProofErrorKind::DsResponseNsec {
                name: query.name().to_owned(),
            },
        ));
    }

    // otherwise we need to recursively discover the status of DS up the chain,
    //   if we find a valid DS, then we're in a Bogus state,
    //   if we find no records, then we are Indeterminate
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
        Ok(ds_records) if ds_records.is_empty() => Err(ProofError::new(
            Proof::Indeterminate,
            ProofErrorKind::DsHasNoDnssecProof { name: zone },
        )),
        err => err,
    }
}

/// Verifies that a given RRSET is validly signed by any of the specified RRSIGs.
///
/// Invalid RRSIGs will be ignored. RRSIGs will only be validated against DNSKEYs which can
///  be validated through a chain back to the `trust_anchor`. As long as one RRSIG is valid,
///  then the RRSET will be valid.
#[allow(clippy::blocks_in_conditions)]
async fn verify_default_rrset<H>(
    handle: &DnssecDnsHandle<H>,
    rrset: Rrset<'_>,
    rrsigs: Vec<RecordRef<'_, RRSIG>>,
    options: DnsRequestOptions,
) -> Result<(Proof, Option<u32>), ProofError>
where
    H: DnsHandle + Sync + Unpin,
{
    if rrsigs.is_empty() {
        // Decide if we're:
        //    1) "indeterminate", i.e. no DNSSEC records are available back to the root
        //    2) "insecure", the zone has a valid NSEC for the DS record in the parent zone
        //    3) "bogus", the parent zone has a valid DS record, but the child zone didn't have the RRSIGs/DNSKEYs
        let ds_records = find_ds_records(handle, rrset.name().clone(), options).await?; // insecure will return early here

        if !ds_records.is_empty() {
            return Err(ProofError::new(
                Proof::Bogus,
                ProofErrorKind::DsRecordShouldExist {
                    name: rrset.name().clone(),
                },
            ));
        } else {
            return Err(ProofError::new(
                Proof::Indeterminate,
                ProofErrorKind::RrsigsNotPresent {
                    name: rrset.name().clone(),
                    record_type: rrset.record_type(),
                },
            ));
        }
    }

    // the record set is going to be shared across a bunch of futures, Arc for that.
    trace!(
        "default validation {}, record_type: {:?}",
        rrset.name(),
        rrset.record_type()
    );

    // use the same current time value for all rrsig + rrset pairs.
    let current_time = current_time();

    // Special case for self-signed DNSKEYS, validate with itself...
    if rrsigs.iter().any(|rrsig| {
        RecordType::DNSKEY == rrset.record_type() && rrsig.data().signer_name() == rrset.name()
    }) {
        // in this case it was looks like a self-signed key, first validate the signature
        //  then return rrset. Like the standard case below, the DNSKEY is validated
        //  after this function. This function is only responsible for validating the signature
        //  the DNSKey validation should come after, see verify_rrset().
        let (proof, adjusted_ttl) = rrsigs
            .iter()
            .find_map(|rrsig| {
                rrset
                    .records()
                    .iter()
                    .filter_map(|r| r.try_borrow::<DNSKEY>())
                    // DNSKEY must be signed using a KSK
                    .filter(|r| r.data().is_key_signing_key())
                    .find_map(|dnskey| {
                        // If we had rrsigs to verify, then we want them to be secure, or the result is a Bogus proof
                        verify_rrset_with_dnskey(dnskey, *rrsig, &rrset, current_time).ok()
                    })
            })
            .ok_or_else(|| {
                ProofError::new(
                    Proof::Bogus,
                    ProofErrorKind::SelfSignedKeyInvalid {
                        name: rrset.name().clone(),
                    },
                )
            })?;

        // Getting here means the rrset (and records), have been verified
        return Ok((proof, adjusted_ttl));
    }

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
        .map(|rrsig| {
            let handle = handle.clone_with_context();
            let query = Query::query(rrsig.data().signer_name().clone(), RecordType::DNSKEY);

            // TODO: Should this sig.signer_name should be confirmed to be in the same zone as the rrsigs and rrset?
            handle
                .lookup(query.clone(), options)
                .first_answer()
                .map_err(|proto| {
                    ProofError::new(Proof::Indeterminate, ProofErrorKind::Proto { query, proto })
                })
                .map_ok(|message| {
                    // DNSKEYs were already validated by the inner query in the above lookup
                    let dnskeys = message
                        .answers()
                        .iter()
                        .filter_map(|r| r.try_borrow::<DNSKEY>());

                    let mut all_insecure = None;
                    for dnskey in dnskeys {
                        match dnskey.proof() {
                            Proof::Secure => {
                                all_insecure = Some(false);
                                if let Ok(proof) =
                                    verify_rrset_with_dnskey(dnskey, *rrsig, &rrset, current_time)
                                {
                                    return Some(proof);
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
                })
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
#[cfg(feature = "dnssec")]
fn verify_rrset_with_dnskey(
    dnskey: RecordRef<'_, DNSKEY>,
    rrsig: RecordRef<'_, RRSIG>,
    rrset: &Rrset<'_>,
    current_time: u32,
) -> Result<(Proof, Option<u32>), ProofError> {
    if dnskey.data().revoke() {
        debug!("revoked");
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

    let validity = check_rrsig_validity(rrsig, rrset, dnskey, current_time);
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

/// Will always return an error. To enable record verification compile with the openssl feature.
#[cfg(not(feature = "dnssec"))]
fn verify_rrset_with_dnskey(_: &DNSKEY, _: &RRSIG, _: &Rrset) -> ProtoResult<()> {
    Err(ProtoErrorKind::Message("openssl or ring feature(s) not enabled").into())
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
pub fn verify_nsec(query: &Query, soa_name: &Name, nsecs: &[&Record]) -> Proof {
    // TODO: consider converting this to Result, and giving explicit reason for the failure

    // first look for a record with the same name
    //  if they are, then the query_type should not exist in the NSEC record.
    //  if we got an NSEC record of the same name, but it is listed in the NSEC types,
    //    WTF? is that bad server, bad record
    if let Some(nsec) = nsecs.iter().find(|nsec| query.name() == nsec.name()) {
        if nsec
            .data()
            .as_dnssec()
            .and_then(DNSSECRData::as_nsec)
            .map_or(false, |rdata| {
                // this should not be in the covered list
                !rdata.type_bit_maps().contains(&query.query_type())
            })
        {
            return Proof::Secure;
        } else {
            return Proof::Bogus;
        }
    }

    let verify_nsec_coverage = |name: &Name| -> bool {
        nsecs.iter().any(|nsec| {
            // the query name must be greater than nsec's label (or equal in the case of wildcard)
            name >= nsec.name() && {
                nsec.data()
                    .as_dnssec()
                    .and_then(DNSSECRData::as_nsec)
                    .map_or(false, |rdata| {
                        // the query name is less than the next name
                        // or this record wraps the end, i.e. is the last record
                        name < rdata.next_domain_name() || rdata.next_domain_name() < nsec.name()
                    })
            }
        })
    };

    // continue to validate there is no wildcard
    if !verify_nsec_coverage(query.name()) {
        return Proof::Bogus;
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
        Proof::Secure
    } else {
        // this is the final check, return it's value
        //  if there is wildcard coverage, we're good.
        if verify_nsec_coverage(&wildcard) {
            Proof::Secure
        } else {
            Proof::Bogus
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
