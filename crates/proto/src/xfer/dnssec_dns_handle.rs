// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The `DnssecDnsHandle` is used to validate all DNS responses for correct DNSSEC signatures.

use std::{
    clone::Clone,
    collections::{HashMap, HashSet},
    error::Error,
    pin::Pin,
    sync::Arc,
};

use async_recursion::async_recursion;
use futures_util::{
    future::{self, Future, FutureExt, TryFutureExt},
    stream::{self, Stream, TryStreamExt},
};
use tracing::{debug, trace};

use crate::{
    error::{ProtoError, ProtoErrorKind},
    op::{Edns, OpCode, Query},
    rr::{
        dnssec::{
            rdata::{DNSSECRData, DNSKEY, DS, RRSIG},
            Algorithm, Proof, ProofError, ProofErrorKind, SupportedAlgorithms, TrustAnchor,
        },
        rdata::opt::EdnsOption,
        DNSClass, Name, RData, Record, RecordData, RecordType,
    },
    xfer::{dns_handle::DnsHandle, DnsRequest, DnsRequestOptions, DnsResponse, FirstAnswer},
};

#[cfg(feature = "dnssec")]
use crate::rr::dnssec::Verifier;

// TODO: combine this with crate::rr::RecordSet?
#[derive(Debug)]
struct Rrset<'r> {
    pub(crate) name: Name,
    pub(crate) record_type: RecordType,
    pub(crate) record_class: DNSClass,
    pub(crate) records: Vec<&'r Record>,
}

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
        Self::with_trust_anchor(handle, TrustAnchor::default())
    }

    /// Create a new DnssecDnsHandle wrapping the specified handle.
    ///
    /// This allows a custom TrustAnchor to be define.
    ///
    /// # Arguments
    /// * `handle` - handle to use for all connections to a remote server.
    /// * `trust_anchor` - custom DNSKEYs that will be trusted, can be used to pin trusted keys.
    pub fn with_trust_anchor(handle: H, trust_anchor: TrustAnchor) -> Self {
        Self {
            handle,
            trust_anchor: Arc::new(trust_anchor),
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
        if let OpCode::Query = request.op_code() {
            // This will panic on no queries, that is a very odd type of request, isn't it?
            // TODO: with mDNS there can be multiple queries
            let query = if let Some(query) = request.queries().first().cloned() {
                query
            } else {
                return Box::pin(stream::once(future::err(ProtoError::from(
                    "no query in request",
                ))));
            };

            let query: Arc<Query> = Arc::new(query);
            let query2: Arc<Query> = Arc::clone(&query);

            let handle: Self = self.clone_with_context();

            // TODO: cache response of the server about understood algorithms
            #[cfg(feature = "dnssec")]
            {
                let edns = request.extensions_mut().get_or_insert_with(Edns::new);
                edns.set_dnssec_ok(true);

                // send along the algorithms which are supported by this handle
                let mut algorithms = SupportedAlgorithms::new();
                #[cfg(feature = "ring")]
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

            return Box::pin(
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
                        verify_response(
                            handle.clone(),
                            Arc::clone(&query),
                            message_response,
                            options,
                        )
                    })
                    .and_then(move |verified_message| {
                        // Query should be unowned at this point
                        let query = Arc::clone(&query2);

                        // at this point all of the message is verified.
                        //  This is where NSEC (and possibly NSEC3) validation occurs
                        // As of now, only NSEC is supported.
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

                            let nsecs = verified_message
                                .name_servers()
                                .iter()
                                .filter(|rr| is_dnssec(rr, RecordType::NSEC))
                                .collect::<Vec<_>>();

                            let nsec_proof =
                                verify_nsec(Arc::clone(&query), soa_name, nsecs.as_slice());
                            if !nsec_proof.is_secure() {
                                // TODO change this to remove the NSECs, like we do for the others?
                                return future::err(ProtoError::from(ProtoErrorKind::Nsec {
                                    query: (*query).clone(),
                                    proof: nsec_proof,
                                }));
                            }
                        }

                        future::ok(verified_message)
                    }),
            );
        }

        Box::pin(self.handle.send(request))
    }
}

/// Extracts the different sections of a message and verifies the RRSIGs
async fn verify_response<H>(
    handle: DnssecDnsHandle<H>,
    query: Arc<Query>,
    mut message: DnsResponse,
    options: DnsRequestOptions,
) -> Result<DnsResponse, ProtoError>
where
    H: DnsHandle + Sync + Unpin,
{
    let answers = message.take_answers();
    let nameservers = message.take_name_servers();
    let additionals = message.take_additionals();

    let answers = verify_rrsets(handle.clone(), &query, answers, options).await?;
    let nameservers = verify_rrsets(handle.clone(), &query, nameservers, options).await?;
    let additionals = verify_rrsets(handle.clone(), &query, additionals, options).await?;

    message.insert_answers(answers);
    message.insert_name_servers(nameservers);
    message.insert_additionals(additionals);

    Ok(message)
}

/// This pulls all answers returned in a Message response and returns a future which will
///  validate all of them.
#[allow(clippy::type_complexity)]
async fn verify_rrsets<H>(
    handle: DnssecDnsHandle<H>,
    query: &Query,
    records: Vec<Record>,
    options: DnsRequestOptions,
) -> Result<Vec<Record>, ProtoError>
where
    H: DnsHandle + Sync + Unpin,
{
    let mut rrset_types: HashSet<(Name, RecordType)> = HashSet::new();
    let mut rrset_proofs: HashMap<(Name, RecordType), Proof> = HashMap::new();

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
        return Ok(records);
    }

    // collect all the rrsets to verify
    // TODO: is there a way to get rid of this clone() safely?
    for (name, record_type) in rrset_types {
        let rrs_to_verify: Vec<&Record> = records
            .iter()
            .filter(|rr| rr.record_type() == record_type && rr.name() == &name)
            .collect();

        // RRSIGS are never modified after this point
        let rrsigs: Vec<&RRSIG> = records
            .iter()
            .filter(|rr| rr.record_type() == RecordType::RRSIG && rr.name() == &name)
            .filter_map(|rr| rr.data())
            .filter_map(|rrsig| RRSIG::try_borrow(rrsig))
            .filter(|rrsig| rrsig.type_covered() == record_type)
            .collect();

        // if there is already an active validation going on, assume the other validation will
        //  complete properly or error if it is invalid
        let rrset = Rrset {
            name: name.clone(),
            record_type,
            record_class: query.query_class(),
            records: rrs_to_verify,
        };

        // TODO: support non-IN classes?
        debug!(
            "verifying: {}, record_type: {:?}, rrsigs: {}",
            rrset.name,
            record_type,
            rrsigs.len()
        );

        // verify this rrset
        let proof = verify_rrset(handle.clone_with_context(), rrset, rrsigs, options).await?;
        rrset_proofs.insert((name, record_type), proof);
    }

    // set the proofs of all the records, all records are returned, it's up to downstream users to check for correctness
    let mut records = records;
    for record in &mut records {
        rrset_proofs
            .get(&(record.name().clone(), record.record_type()))
            .map(|proof| record.set_proof(*proof));
    }

    Ok(records)
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
    rrsigs: Vec<&RRSIG>,
    options: DnsRequestOptions,
) -> Result<Proof, ProtoError>
where
    H: DnsHandle + Sync + Unpin,
{
    // wrapper for some of the type conversion for typed DNSKEY fn calls.

    match rrset.record_type {
        // validation of DNSKEY records require different logic as they search for DS record coverage as well
        RecordType::DNSKEY => {
            verify_dnskey_rrset(handle.clone_with_context(), rrset, options).await
        }
        _ => verify_default_rrset(&handle.clone_with_context(), rrset, rrsigs, options).await,
    }
}

/// Verifies a dnskey rrset
///
/// This first checks to see if the key is in the set of trust_anchors. If so then it's returned
///  as a success. Otherwise, a query is sent to get the DS record, and the DNSKEY is validated
///  against the DS record.
async fn verify_dnskey_rrset<H>(
    handle: DnssecDnsHandle<H>,
    rrset: Rrset<'_>,
    options: DnsRequestOptions,
) -> Result<Proof, ProtoError>
where
    H: DnsHandle + Sync + Unpin,
{
    trace!(
        "dnskey validation {}, record_type: {:?}",
        rrset.name,
        rrset.record_type
    );

    // check the DNSKEYS against the trust_anchor, if it's approved allow it.
    //   this includes the root keys
    {
        let anchored_keys: Vec<&DNSKEY> = rrset
            .records
            .iter()
            .filter_map(|r| r.data())
            .filter_map(DNSKEY::try_borrow)
            .filter(|dnskey| {
                if handle
                    .trust_anchor
                    .contains_dnskey_bytes(dnskey.public_key())
                {
                    debug!(
                        "validated dnskey with trust_anchor: {}, {}",
                        rrset.name, dnskey
                    );

                    true
                } else {
                    false
                }
            })
            .collect::<Vec<_>>();

        if !anchored_keys.is_empty() {
            return Ok(Proof::Secure);
        }
    }

    // need to get DS records for each DNSKEY
    //   there will be a DS record for everything under the root keys
    let ds_records = match find_ds_records(handle, rrset.name.clone(), options).await {
        Ok(records) => records,
        Err(err) => {
            return Err(ProtoError::from(ProtoErrorKind::Msg(format!(
                "No valid DS records: {err}"
            ))))
        }
    };

    let valid_keys = rrset
        .records
        .iter()
        .enumerate()
        .filter_map(|(i, rr)| rr.data().map(|d| (i, d)))
        .filter_map(|(i, data)| DNSKEY::try_borrow(data).map(|d| (i, d)))
        .filter(|&(_, key_rdata)| {
            ds_records
                .iter()
                .filter_map(|r| r.data().map(|d| (d, r.name())))
                // must be covered by at least one DS record
                .any(|(ds_rdata, ds_name)| {
                    if ds_rdata.covers(&rrset.name, key_rdata).unwrap_or(false) {
                        debug!(
                            "validated dnskey ({}, {key_rdata}) with {ds_name} {ds_rdata}",
                            rrset.name
                        );

                        true
                    } else {
                        false
                    }
                })
        })
        .map(|(i, _)| i)
        .collect::<Vec<usize>>();

    if !valid_keys.is_empty() {
        trace!("validated dnskey: {}", rrset.name);
        Ok(Proof::Secure)
    } else {
        Err(ProtoError::from(ProtoErrorKind::Message(
            "Could not validate all DNSKEYs",
        )))
    }
}

#[async_recursion]
async fn find_ds_records<H>(
    handle: DnssecDnsHandle<H>,
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
            let ds_records = ds_message
                .take_answers()
                .into_iter()
                .filter_map(|r| Record::<DS>::try_from(r).ok())
                .collect::<Vec<_>>();

            return Ok(ds_records);
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
            Proof::Insecure,
            ProofErrorKind::DsResponseNsec {
                name: query.name().to_owned(),
            },
        ));
    }

    // otherwise we need to recursively discover the status of DS up the chain,
    //   if we find a valid DS, then we're in a Bogus state,
    //   if we find no records, then we are Indeterminate
    //   if we get ProofError, our result is the same
    match find_ds_records(handle, zone.base_name(), options).await {
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
    rrsigs: Vec<&RRSIG>,
    options: DnsRequestOptions,
) -> Result<Proof, ProtoError>
where
    H: DnsHandle + Sync + Unpin,
{
    // TODO: if there are no rrsigs, we are not necessarily failed first need to change this from an error return?
    if rrsigs.is_empty() {
        //let mut rrset = rrset;
        //assoc_rrset_proof(&mut rrset, Proof::Indeterminate);

        // instead of returning here, first deside if we're:
        //    1) "indeterminate", i.e. no DNSSEC records are available back to the root
        //    2) "insecure", the zone has a valid NSEC for the DS record in the parent zone
        //    3) "bogus", the parent zone has a valid DS record, but the child zone didn't have the RRSIGs/DNSKEYs
        return Err(ProtoError::from(ProtoErrorKind::RrsigsNotPresent {
            name: rrset.name.clone(),
            record_type: rrset.record_type,
        }));
    }

    // the record set is going to be shared across a bunch of futures, Arc for that.
    trace!(
        "default validation {}, record_type: {:?}",
        rrset.name,
        rrset.record_type
    );

    // Special case for self-signed DNSKEYS, validate with itself...
    if rrsigs
        .iter()
        .any(|rrsig| RecordType::DNSKEY == rrset.record_type && rrsig.signer_name() == &rrset.name)
    {
        // in this case it was looks like a self-signed key, first validate the signature
        //  then return rrset. Like the standard case below, the DNSKEY is validated
        //  after this function. This function is only responsible for validating the signature
        //  the DNSKey validation should come after, see verify_rrset().
        future::ready(
            rrsigs
                .iter()
                .find_map(|rrsig| {
                    if rrset
                        .records
                        .iter()
                        .filter_map(|r| r.data().map(|d| (d, r.name())))
                        .filter_map(|(d, n)| DNSKEY::try_borrow(d).map(|d| (d, n)))
                        .any(|(dnskey, dnskey_name)| {
                            // If we had rrsigs to verify, then we want them to be secure, or the result is a Bogus proof
                            verify_rrset_with_dnskey(dnskey_name, dnskey, rrsig, &rrset)
                                .unwrap_or(Proof::Bogus)
                                .is_secure()
                        })
                    {
                        Some(())
                    } else {
                        None
                    }
                })
                .ok_or_else(|| {
                    ProtoError::from(ProtoErrorKind::Message("self-signed dnskey is invalid"))
                }),
        )
        .await?;

        // Getting here means the rrset (and records), have been verified
        return Ok(Proof::Secure);
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
    let verifications = rrsigs.iter()
        .map(|rrsig| {
            let handle = handle.clone_with_context();

            // TODO: Should this sig.signer_name should be confirmed to be in the same zone as the rrsigs and rrset?
            handle
                .lookup(
                    Query::query(rrsig.signer_name().clone(), RecordType::DNSKEY),
                    options,
                )
                .first_answer()
                .and_then(|message|
                    // DNSKEYs were already validated by the inner query in the above lookup
                    future::ready(message
                        .answers()
                        .iter()
                        .filter(|r| is_dnssec(r, RecordType::DNSKEY))
                        .filter_map(|r| r.data().map(|data| (r.name(), data)))
                        .filter_map(|(dnskey_name, data)|
                           DNSKEY::try_borrow(data).map(|data| (dnskey_name, data)))
                        .find(|(dnskey_name, dnskey)|
                                verify_rrset_with_dnskey(dnskey_name, dnskey, rrsig, &rrset).is_ok()
                        )
                        .map(|_| ())
                        .ok_or_else(|| ProtoError::from(ProtoErrorKind::Message("validation failed"))))
                )
        })
        .collect::<Vec<_>>();

    // if there some were valid we have a
    Proof::Secure;
    // if there were No DNSKey records, and there is a valid NSSEC record for the DNSKey/DS/RRSIG records, then we have a
    Proof::Insecure;
    // if there were DNSKeys/DS/RRSIG, but none were verified, we have a Bogus situation
    Proof::Bogus;
    // if there were no DNSKeys and there are no NSSEC records for the DNSKeys/DS/RRSIG records then we have a
    Proof::Indeterminate;

    // if there are no available verifications, then we are in a failed state.
    if verifications.is_empty() {
        // TODO: this is a bogus state, technically we can return the Rrset and make all the records Bogus?
        return Err(ProtoError::from(ProtoErrorKind::RrsigsNotPresent {
            name: rrset.name.clone(),
            record_type: rrset.record_type,
        }));
    }

    // as long as any of the verifications is good, then the RRSET is valid.
    let select = future::select_ok(verifications)
        // getting here means at least one of the rrsigs succeeded...
        .map_ok(move |((), rest)| {
            drop(rest); // drop all others, should free up Arc
        });

    select.await?;

    // getting here means we have secure and verified records.
    //let mut rrset = rrset;
    //assoc_rrset_proof(&mut rrset, Proof::Secure);
    Ok(Proof::Secure)
}

/// Verifies the given SIG of the RRSET with the DNSKEY.
#[cfg(feature = "dnssec")]
fn verify_rrset_with_dnskey(
    dnskey_name: &Name,
    dnskey: &DNSKEY,
    rrsig: &RRSIG,
    rrset: &Rrset<'_>,
) -> Result<Proof, ProofError> {
    if dnskey.revoke() {
        debug!("revoked");
        return Err(ProofError::new(
            Proof::Bogus,
            ProofErrorKind::DnsKeyRevoked {
                name: dnskey_name.clone(),
                key_tag: rrsig.key_tag(),
            },
        ));
    } // TODO: does this need to be validated? RFC 5011
    if !dnskey.zone_key() {
        return Err(ProofError::new(
            Proof::Bogus,
            ProofErrorKind::NotZoneDnsKey {
                name: dnskey_name.clone(),
                key_tag: rrsig.key_tag(),
            },
        ));
    }
    if dnskey.algorithm() != rrsig.algorithm() {
        return Err(ProofError::new(
            Proof::Bogus,
            ProofErrorKind::AlgorithmMismatch {
                rrsig: rrsig.algorithm(),
                dnskey: dnskey.algorithm(),
            },
        ));
    }

    dnskey
        .verify_rrsig(&rrset.name, rrset.record_class, rrsig, &rrset.records)
        .map(|_| {
            debug!(
                "validated ({}, {:?}) with ({}, {})",
                rrset.name, rrset.record_type, dnskey_name, dnskey
            );
            Proof::Secure
        })
        .map_err(|e| {
            debug!(
                "failed validation of ({}, {:?}) with ({}, {})",
                rrset.name, rrset.record_type, dnskey_name, dnskey
            );
            ProofError::new(
                Proof::Bogus,
                ProofErrorKind::DnsKeyVerifyRrsig {
                    name: dnskey_name.clone(),
                    key_tag: rrsig.key_tag(),
                    error: e,
                },
            )
        })
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
pub fn verify_nsec(query: Arc<Query>, soa_name: &Name, nsecs: &[&Record]) -> Proof {
    // TODO: consider converting this to Result, and giving explicit reason for the failure

    // first look for a record with the same name
    //  if they are, then the query_type should not exist in the NSEC record.
    //  if we got an NSEC record of the same name, but it is listed in the NSEC types,
    //    WTF? is that bad server, bad record
    if let Some(nsec) = nsecs.iter().find(|nsec| query.name() == nsec.name()) {
        if nsec
            .data()
            .and_then(RData::as_dnssec)
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
                    .and_then(RData::as_dnssec)
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
