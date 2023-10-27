// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The `DnssecDnsHandle` is used to validate all DNS responses for correct DNSSEC signatures.

use std::{clone::Clone, collections::HashSet, error::Error, pin::Pin, sync::Arc};

use futures_util::{
    future::{self, Future, FutureExt, TryFutureExt},
    stream::{self, Stream, TryStreamExt},
};
use tracing::{debug, trace};

use crate::{
    error::{ProtoError, ProtoErrorKind, ProtoResult},
    op::{Edns, OpCode, Query},
    rr::{
        dnssec::{
            rdata::{DNSSECRData, DNSKEY, DS, RRSIG},
            Algorithm, Proof, SupportedAlgorithms, TrustAnchor,
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
struct Rrset<R: RecordData = RData> {
    pub(crate) name: Name,
    pub(crate) record_type: RecordType,
    pub(crate) record_class: DNSClass,
    pub(crate) records: Vec<Record<R>>,
}

impl Rrset<RData> {
    /// Attempts to convert into an Rrset of the specific RecordData type
    fn try_into_record<R: RecordData>(self) -> Result<Rrset<R>, Self> {
        // To avoid allocating we scan first to make sure all the types are valid
        if !self
            .records
            .iter()
            .filter_map(|r| r.data())
            .all(|data| R::try_borrow(data).is_some())
        {
            return Err(self);
        }

        let Self {
            name,
            record_type,
            record_class,
            records,
        } = self;

        let original_len = records.len();
        let ok = records
            .into_iter()
            .map_while(|r| Record::<R>::try_from(r).ok())
            .collect::<Vec<Record<R>>>();

        debug_assert_eq!(ok.len(), original_len);

        Ok(Rrset {
            name,
            record_type,
            record_class,
            records: ok,
        })
    }
}

impl<R: RecordData> Rrset<R> {
    /// Infallible conversion from a specific record type generic RData
    fn into_rdata(self) -> Rrset<RData> {
        let Self {
            name,
            record_type,
            record_class,
            records,
        } = self;

        let records = records
            .into_iter()
            .map(|r| r.into_record_of_rdata())
            .collect::<Vec<Record<RData>>>();

        Rrset {
            name,
            record_type,
            record_class,
            records,
        }
    }
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
            let dns_class = request
                .queries()
                .first()
                .map_or(DNSClass::IN, Query::query_class);
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
                        verify_rrsets(handle.clone(), message_response, dns_class, options)
                    })
                    .and_then(move |verified_message| {
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

                            let nsec_proof = verify_nsec(&query, soa_name, nsecs.as_slice());
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
            );
        }

        Box::pin(self.handle.send(request))
    }
}

/// This pulls all answers returned in a Message response and returns a future which will
///  validate all of them.
#[allow(clippy::type_complexity)]
async fn verify_rrsets<H>(
    handle: DnssecDnsHandle<H>,
    message_result: DnsResponse,
    dns_class: DNSClass,
    options: DnsRequestOptions,
) -> Result<DnsResponse, ProtoError>
where
    H: DnsHandle + Sync + Unpin,
{
    let mut rrset_types: HashSet<(Name, RecordType)> = HashSet::new();

    // TODO: why isn't this also looking additionals?
    for rrset in message_result
        .answers()
        .iter()
        .chain(message_result.name_servers())
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

    // there was no data returned in that message
    if rrset_types.is_empty() {
        let mut message_result = message_result.into_message();

        // there were no returned results, double check by dropping all the results
        message_result.take_answers();
        message_result.take_name_servers();
        message_result.take_additionals();

        return Err(ProtoError::from(ProtoErrorKind::Message(
            "no results to verify",
        )));
    }

    // collect all the rrsets to verify
    // TODO: is there a way to get rid of this clone() safely?
    let mut rrsets_to_verify = Vec::with_capacity(rrset_types.len());
    for (name, record_type) in rrset_types {
        // TODO: should we evaluate the different sections (answers and name_servers) separately?
        let records: Vec<Record> = message_result
            .answers()
            .iter()
            .chain(message_result.name_servers())
            .chain(message_result.additionals())
            .filter(|rr| rr.record_type() == record_type && rr.name() == &name)
            .cloned()
            .collect();

        // RRSIGS are never modified after this point
        let rrsigs: Vec<RRSIG> = message_result
            .answers()
            .iter()
            .chain(message_result.name_servers())
            .chain(message_result.additionals())
            .filter_map(|rr| rr.data())
            .filter_map(|rrsig| RRSIG::try_borrow(rrsig))
            .map(|rr| rr.to_owned())
            .collect();

        // if there is already an active validation going on, assume the other validation will
        //  complete properly or error if it is invalid
        let rrset = Rrset {
            name,
            record_type,
            record_class: dns_class,
            records,
        };

        // TODO: support non-IN classes?
        debug!(
            "verifying: {}, record_type: {:?}, rrsigs: {}",
            rrset.name,
            record_type,
            rrsigs.len()
        );
        rrsets_to_verify
            .push(verify_rrset(handle.clone_with_context(), rrset, rrsigs, options).boxed());
    }

    // spawn a select_all over this vec, these are the individual RRSet validators
    verify_all_rrsets(message_result, rrsets_to_verify).await
}

// TODO: is this method useful/necessary?
fn is_dnssec<D: RecordData>(rr: &Record<D>, dnssec_type: RecordType) -> bool {
    rr.record_type().is_dnssec() && dnssec_type.is_dnssec() && rr.record_type() == dnssec_type
}

async fn verify_all_rrsets<F, E>(
    message_result: DnsResponse,
    rrsets: Vec<F>,
) -> Result<DnsResponse, E>
where
    F: Future<Output = Result<Rrset, E>> + Send + Unpin,
    E: From<ProtoError> + Error + Clone + Send + Unpin + 'static,
{
    let mut verified_rrsets: HashSet<(Name, RecordType)> = HashSet::new();
    let mut rrsets = future::select_all(rrsets);
    let mut last_validation_err: Option<E> = None;

    // loop through all the rrset evaluations, filter all the rrsets in the Message
    //  down to just the ones that were able to be validated
    loop {
        let (rrset, _, remaining) = rrsets.await;
        match rrset {
            Ok(rrset) => {
                debug!(
                    "an rrset was verified: {}, {:?}",
                    rrset.name, rrset.record_type
                );
                verified_rrsets.insert((rrset.name, rrset.record_type));
            }
            // TODO: should we return the Message on errors? Allow the consumer to decide what to do
            //       on a validation failure?
            // any error, is an error for all
            Err(e) => {
                if tracing::enabled!(tracing::Level::DEBUG) {
                    let mut query = message_result
                        .queries()
                        .iter()
                        .map(|q| q.to_string())
                        .fold(String::new(), |s, q| format!("{q},{s}"));

                    query.truncate(query.len() - 1);
                    debug!("an rrset failed to verify ({}): {:?}", query, e);
                }

                last_validation_err = Some(e);
            }
        };

        if !remaining.is_empty() {
            // continue the evaluation
            rrsets = future::select_all(remaining);
        } else {
            break;
        }
    }

    // check if any are valid, otherwise return whatever error caused it to fail
    if verified_rrsets.is_empty() {
        if let Some(last_validation_err) = last_validation_err {
            return Err(last_validation_err);
        }
    }

    // validated not none above...
    let (mut message_result, message_buffer) = message_result.into_parts();

    // take all the rrsets from the Message, filter down each set to the validated rrsets
    // TODO: does the section in the message matter here?
    //       we could probably end up with record_types in any section.
    //       track the section in the rrset evaluation?
    let answers = message_result
        .take_answers()
        .into_iter()
        .chain(message_result.take_additionals().into_iter())
        .filter(|record| verified_rrsets.contains(&(record.name().clone(), record.record_type())))
        .collect::<Vec<Record>>();

    let name_servers = message_result
        .take_name_servers()
        .into_iter()
        .filter(|record| verified_rrsets.contains(&(record.name().clone(), record.record_type())))
        .collect::<Vec<Record>>();

    let additionals = message_result
        .take_additionals()
        .into_iter()
        .filter(|record| verified_rrsets.contains(&(record.name().clone(), record.record_type())))
        .collect::<Vec<Record>>();

    // add the filtered records back to the message
    message_result.insert_answers(answers);
    message_result.insert_name_servers(name_servers);
    message_result.insert_additionals(additionals);

    // breaks out of the loop... and returns the filtered Message.
    Ok(DnsResponse::new(message_result, message_buffer))
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
    rrset: Rrset,
    rrsigs: Vec<RRSIG>,
    options: DnsRequestOptions,
) -> Result<Rrset, ProtoError>
where
    H: DnsHandle + Sync + Unpin,
{
    // wrapper for some of the type conversion for typed DNSKEY fn calls.
    let typed_verify_dnskey = move |handle, rrset: Rrset| {
        async move {
            // TODO: validate that this DNSKEY is stronger than the one lower in the chain,
            //  also, set the min algorithm to this algorithm to prevent downgrade attacks.
            let rrset = rrset.try_into_record::<DNSKEY>().map_err(|_| {
                ProtoError::from(ProtoErrorKind::Message("Could not validate all DNSKEYs"))
            })?;
            let result = verify_dnskey_rrset(handle, rrset, options).await?;
            Ok(result.into_rdata())
        }
    };

    // Special case for unsigned DNSKEYs, it's valid for a DNSKEY to be bare in the zone if
    //  it's a trust_anchor, though some DNS servers choose to self-sign in this case,
    //  for self-signed KEYS they will drop through to the standard validation logic.
    if let RecordType::DNSKEY = rrset.record_type {
        if rrsigs.is_empty() {
            debug!("unsigned key: {}, {:?}", rrset.name, rrset.record_type);
            return typed_verify_dnskey(handle.clone_with_context(), rrset).await;
        }
    }

    // standard validation path
    let rrset = verify_default_rrset(&handle.clone_with_context(), rrset, rrsigs, options).await?;

    // validation of DNSKEY records
    match rrset.record_type {
        RecordType::DNSKEY => typed_verify_dnskey(handle.clone_with_context(), rrset).await,
        _ => Ok(rrset),
    }
}

/// Verifies a dnskey rrset
///
/// This first checks to see if the key is in the set of trust_anchors. If so then it's returned
///  as a success. Otherwise, a query is sent to get the DS record, and the DNSKEY is validated
///  against the DS record.
async fn verify_dnskey_rrset<H>(
    handle: DnssecDnsHandle<H>,
    rrset: Rrset<DNSKEY>,
    options: DnsRequestOptions,
) -> Result<Rrset<DNSKEY>, ProtoError>
where
    H: DnsHandle + Sync + Unpin,
{
    trace!(
        "dnskey validation {}, record_type: {:?}",
        rrset.name,
        rrset.record_type
    );

    // check the DNSKEYS against the trust_anchor, if it's approved allow it.
    {
        let anchored_keys = rrset
            .records
            .iter()
            .enumerate()
            .filter_map(|(i, rr)| rr.data().map(|d| (i, d)))
            .filter_map(|(i, rdata)| {
                if handle
                    .trust_anchor
                    .contains_dnskey_bytes(rdata.public_key())
                {
                    debug!(
                        "validated dnskey with trust_anchor: {}, {}",
                        rrset.name, rdata
                    );

                    Some(i)
                } else {
                    None
                }
            })
            .collect::<Vec<usize>>();

        if !anchored_keys.is_empty() {
            let mut rrset = rrset;
            preserve(&mut rrset.records, anchored_keys);
            return Ok(rrset);
        }
    }

    // need to get DS records for each DNSKEY
    let ds_message = handle
        .lookup(Query::query(rrset.name.clone(), RecordType::DS), options)
        .first_answer()
        .await?;

    // if DS record query is NSEC then this is
    Proof::Insecure;
    // if DS record query is NXdomain or no records found then
    Proof::Indeterminate;
    // otherwise, if DS record is Proof::Secure, then continue

    let valid_keys = rrset
        .records
        .iter()
        .enumerate()
        .filter_map(|(i, rr)| rr.data().map(|d| (i, d)))
        .filter(|&(_, key_rdata)| {
            ds_message
                .answers()
                .iter()
                .filter_map(|r| r.data().map(|d| (d, r.name())))
                .filter_map(|(ds, n)| DS::try_borrow(ds).map(|ds| (ds, n)))
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
        let mut rrset = rrset;
        preserve(&mut rrset.records, valid_keys);

        trace!("validated dnskey: {}", rrset.name);
        Ok(rrset)
    } else {
        Err(ProtoError::from(ProtoErrorKind::Message(
            "Could not validate all DNSKEYs",
        )))
    }
}

/// Preserves the specified indexes in vec, all others will be removed
///
/// # Arguments
///
/// * `vec` - vec to mutate
/// * `indexes` - ordered list of indexes to remove
fn preserve<T, I>(vec: &mut Vec<T>, indexes: I)
where
    I: IntoIterator<Item = usize>,
    <I as IntoIterator>::IntoIter: DoubleEndedIterator,
{
    // this removes all indexes that were not part of the anchored keys
    let mut indexes_iter = indexes.into_iter().rev();
    let mut i = indexes_iter.next();
    for j in (0..vec.len()).rev() {
        // check the next index to preserve
        if i.map_or(false, |i| i > j) {
            i = indexes_iter.next();
        }
        // if the key is not in the set of anchored_keys, remove it
        if i.map_or(true, |i| i != j) {
            vec.remove(j);
        }
    }
}

#[test]
fn test_preserve() {
    let mut vec = vec![1, 2, 3];
    let indexes = vec![];
    preserve(&mut vec, indexes);
    assert_eq!(vec, vec![]);

    let mut vec = vec![1, 2, 3];
    let indexes = vec![0];
    preserve(&mut vec, indexes);
    assert_eq!(vec, vec![1]);

    let mut vec = vec![1, 2, 3];
    let indexes = vec![1];
    preserve(&mut vec, indexes);
    assert_eq!(vec, vec![2]);

    let mut vec = vec![1, 2, 3];
    let indexes = vec![2];
    preserve(&mut vec, indexes);
    assert_eq!(vec, vec![3]);

    let mut vec = vec![1, 2, 3];
    let indexes = vec![0, 2];
    preserve(&mut vec, indexes);
    assert_eq!(vec, vec![1, 3]);

    let mut vec = vec![1, 2, 3];
    let indexes = vec![0, 1, 2];
    preserve(&mut vec, indexes);
    assert_eq!(vec, vec![1, 2, 3]);
}

/// Verifies that a given RRSET is validly signed by any of the specified RRSIGs.
///
/// Invalid RRSIGs will be ignored. RRSIGs will only be validated against DNSKEYs which can
///  be validated through a chain back to the `trust_anchor`. As long as one RRSIG is valid,
///  then the RRSET will be valid.
#[allow(clippy::blocks_in_conditions)]
async fn verify_default_rrset<H>(
    handle: &DnssecDnsHandle<H>,
    rrset: Rrset,
    rrsigs: Vec<RRSIG>,
    options: DnsRequestOptions,
) -> Result<Rrset, ProtoError>
where
    H: DnsHandle + Sync + Unpin,
{
    // the record set is going to be shared across a bunch of futures, Arc for that.
    let rrset = Arc::new(rrset);
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
        return future::ready(
            rrsigs
                .iter()
                .find_map(|rrsig| {
                    let rrset = Arc::clone(&rrset);

                    if rrset
                        .records
                        .iter()
                        .filter_map(|r| r.data().map(|d| (d, r.name())))
                        .filter_map(|(d, n)| DNSKEY::try_borrow(d).map(|d| (d, n)))
                        .any(|(dnskey, dnskey_name)| {
                            verify_rrset_with_dnskey(dnskey_name, dnskey, rrsig, &rrset).is_ok()
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
        .map_ok(move |_| Arc::try_unwrap(rrset).expect("unable to unwrap Arc"))
        .await;
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
        .map(|sig| {
            let rrset = Arc::clone(&rrset);
            let handle = handle.clone_with_context();

            // TODO: Should this sig.signer_name should be confirmed to be in the same zone as the rrsigs and rrset?
            handle
                .lookup(
                    Query::query(sig.signer_name().clone(), RecordType::DNSKEY),
                    options,
                )
                .first_answer()
                .and_then(move |message|
                    // DNSKEYs are validated by the inner query
                    future::ready(message
                        .answers()
                        .iter()
                        .filter(|r| is_dnssec(r, RecordType::DNSKEY))
                        .filter_map(|r| r.data().map(|data| (r.name(), data)))
                        .filter_map(|(dnskey_name, data)|
                           DNSKEY::try_borrow(data).map(|data| (dnskey_name, data)))
                        .find(|(dnskey_name, dnskey)|
                                verify_rrset_with_dnskey(dnskey_name, dnskey, &sig, &rrset).is_ok()
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
            Arc::try_unwrap(rrset).expect("unable to unwrap Arc")
        });

    select.await
}

/// Verifies the given SIG of the RRSET with the DNSKEY.
#[cfg(feature = "dnssec")]
fn verify_rrset_with_dnskey(
    dnskey_name: &Name,
    dnskey: &DNSKEY,
    sig: &RRSIG,
    rrset: &Rrset,
) -> ProtoResult<()> {
    if dnskey.revoke() {
        debug!("revoked");
        return Err(ProtoErrorKind::Message("revoked").into());
    } // TODO: does this need to be validated? RFC 5011
    if !dnskey.zone_key() {
        return Err(ProtoErrorKind::Message("is not a zone key").into());
    }
    if dnskey.algorithm() != sig.algorithm() {
        return Err(ProtoErrorKind::Message("mismatched algorithm").into());
    }

    dnskey
        .verify_rrsig(&rrset.name, rrset.record_class, sig, &rrset.records)
        .map(|r| {
            debug!(
                "validated ({}, {:?}) with ({}, {})",
                rrset.name, rrset.record_type, dnskey_name, dnskey
            );
            r
        })
        .map_err(Into::into)
        .map_err(|e| {
            debug!(
                "failed validation of ({}, {:?}) with ({}, {})",
                rrset.name, rrset.record_type, dnskey_name, dnskey
            );
            e
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
pub fn verify_nsec(query: &Query, soa_name: &Name, nsecs: &[&Record]) -> Proof {
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
