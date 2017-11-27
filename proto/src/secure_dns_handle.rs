// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::clone::Clone;
use std::collections::HashSet;
use std::mem;
use std::rc::Rc;

use futures::*;

use DnsHandle;
use error::*;
use op::{Message, OpCode, Query};
use rr::{domain, DNSClass, RData, Record, RecordType};
#[cfg(feature = "dnssec")]
use rr::dnssec::Verifier;
use rr::dnssec::{Algorithm, SupportedAlgorithms, TrustAnchor};
use rr::dnssec::rdata::{DNSSECRData, DNSSECRecordType, DNSKEY, SIG};
use rr::rdata::opt::EdnsOption;

#[derive(Debug)]
struct Rrset {
    pub name: domain::Name,
    pub record_type: RecordType,
    pub record_class: DNSClass,
    pub records: Vec<Record>,
}

/// Performs DNSSec validation of all DNS responses from the wrapped DnsHandle
///
/// This wraps a DnsHandle, changing the implementation `send()` to validate all
///  message responses for Query operations. Update operation responses are not validated by
///  this process.
#[derive(Clone)]
#[must_use = "queries can only be sent through a DnsHandle"]
pub struct SecureDnsHandle<H, E = <H as DnsHandle>::Error>
where
    H: DnsHandle<Error = E> + 'static,
    E: FromProtoError + 'static,
{
    handle: H,
    trust_anchor: Rc<TrustAnchor>,
    request_depth: usize,
    minimum_key_len: usize,
    minimum_algorithm: Algorithm, // used to prevent down grade attacks...
}

impl<H, E> SecureDnsHandle<H, E>
where
    H: DnsHandle<Error = E> + 'static,
    E: FromProtoError + 'static,
{
    /// Create a new SecureDnsHandle wrapping the speicified handle.
    ///
    /// This uses the compiled in TrustAnchor default trusted keys.
    ///
    /// # Arguments
    /// * `handle` - handle to use for all connections to a remote server.
    pub fn new(handle: H) -> SecureDnsHandle<H> {
        Self::with_trust_anchor(handle, TrustAnchor::default())
    }

    /// Create a new SecureDnsHandle wrapping the speicified handle.
    ///
    /// This allows a custom TrustAnchor to be define.
    ///
    /// # Arguments
    /// * `handle` - handle to use for all connections to a remote server.
    /// * `trust_anchor` - custom DNSKEYs that will be trusted, can be used to pin trusted keys.
    pub fn with_trust_anchor(handle: H, trust_anchor: TrustAnchor) -> SecureDnsHandle<H> {
        SecureDnsHandle {
            handle: handle,
            trust_anchor: Rc::new(trust_anchor),
            request_depth: 0,
            minimum_key_len: 0,
            minimum_algorithm: Algorithm::RSASHA256,
        }
    }

    /// An internal function used to clone the handle, but maintain some information back to the
    ///  original handle, such as the request_depth such that infinite recurssion does
    ///  not occur.
    fn clone_with_context(&self) -> Self {
        SecureDnsHandle {
            handle: self.handle.clone(),
            trust_anchor: Rc::clone(&self.trust_anchor),
            request_depth: self.request_depth + 1,
            minimum_key_len: self.minimum_key_len,
            minimum_algorithm: self.minimum_algorithm,
        }
    }
}

impl<H, E> DnsHandle for SecureDnsHandle<H>
where
    H: DnsHandle<Error = E>,
    E: FromProtoError + Clone,
{
    type Error = E;

    fn is_verifying_dnssec(&self) -> bool {
        // This handler is always verifying...
        true
    }

    fn send(&mut self, mut message: Message) -> Box<Future<Item = Message, Error = Self::Error>> {
        // backstop, this might need to be configurable at some point
        if self.request_depth > 20 {
            return Box::new(failed(E::from(
                ProtoErrorKind::Message("exceeded max validation depth").into(),
            )));
        }

        // dnssec only matters on queries.
        if let OpCode::Query = message.op_code() {
            // This will panic on no queries, that is a very odd type of request, isn't it?
            // TODO: there should only be one
            let query = message.queries().first().cloned().unwrap();
            let handle: SecureDnsHandle<H> = self.clone_with_context();

            // TODO: cache response of the server about understood algorithms
            #[cfg(feature = "dnssec")]
            {
                let edns = message.edns_mut();

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

                edns.set_option(dau);
                edns.set_option(dhu);
            }

            message.set_authentic_data(true);
            message.set_checking_disabled(false);
            let dns_class = message
                .queries()
                .first()
                .map_or(DNSClass::IN, |q| q.query_class());

            return Box::new(
                self.handle
                    .send(message)
                    .and_then(move |message_response| {
                        // group the record sets by name and type
                        //  each rrset type needs to validated independently
                        debug!("validating message_response: {}", message_response.id());
                        verify_rrsets(&handle, message_response, dns_class)
                    })
                    .and_then(move |verified_message| {
                        // at this point all of the message is verified.
                        //  This is where NSEC (and possibly NSEC3) validation occurs
                        // As of now, only NSEC is supported.
                        if verified_message.answers().is_empty() {
                            let nsecs = verified_message
                                .name_servers()
                                .iter()
                                .filter(|rr| is_dnssec(rr, DNSSECRecordType::NSEC))
                                .collect::<Vec<_>>();

                            if !verify_nsec(&query, nsecs.as_slice()) {
                                // TODO change this to remove the NSECs, like we do for the others?
                                return Err(E::from(
                                    ProtoErrorKind::Message(
                                        "could not validate nxdomain \
                                         with NSEC",
                                    ).into(),
                                ));
                            }
                        }

                        Ok(verified_message)
                    }),
            );
        }

        self.handle.send(message)
    }
}

/// A future to verify all RRSets in a returned Message.
struct VerifyRrsetsFuture<E> {
    message_result: Option<Message>,
    rrsets: SelectAll<Box<Future<Item = Rrset, Error = E>>>,
    verified_rrsets: HashSet<(domain::Name, RecordType)>,
}

/// this pulls all records returned in a Message respons and returns a future which will
///  validate all of them.
fn verify_rrsets<H, E>(
    handle: &SecureDnsHandle<H>,
    message_result: Message,
    dns_class: DNSClass,
) -> Box<Future<Item = Message, Error = E>>
where
    H: DnsHandle<Error = E>,
    E: FromProtoError + Clone,
{
    let mut rrset_types: HashSet<(domain::Name, RecordType)> = HashSet::new();
    for rrset in message_result
        .answers()
        .iter()
        .chain(message_result.name_servers())
        .filter(|rr| {
            !is_dnssec(rr, DNSSECRecordType::RRSIG) &&
                             // if we are at a depth greater than 1, we are only interested in proving evaluation chains
                             //   this means that only DNSKEY and DS are intersting at that point.
                             //   this protects against looping over things like NS records and DNSKEYs in responses.
                             // TODO: is there a cleaner way to prevent cycles in the evaluations?
                                          (handle.request_depth <= 1 ||
                                           is_dnssec(rr, DNSSECRecordType::DNSKEY) ||
                                           is_dnssec(rr, DNSSECRecordType::DS))
        })
        .map(|rr| (rr.name().clone(), rr.rr_type()))
    {
        rrset_types.insert(rrset);
    }

    // there was no data returned in that message
    if rrset_types.is_empty() {
        let mut message_result = message_result;

        // there were no returned results, double check by dropping all the results
        message_result.take_answers();
        message_result.take_name_servers();
        message_result.take_additionals();

        return Box::new(failed(E::from(
            ProtoErrorKind::Message("no results to verify").into(),
        )));
    }

    // collect all the rrsets to verify
    // TODO: is there a way to get rid of this clone() safely?
    let mut rrsets: Vec<Box<Future<Item = Rrset, Error = E>>> =
        Vec::with_capacity(rrset_types.len());
    for (name, record_type) in rrset_types {
        // TODO: should we evaluate the different sections (answers and name_servers) separately?
        let rrset: Vec<Record> = message_result
            .answers()
            .iter()
            .chain(message_result.name_servers())
            .chain(message_result.additionals())
            .filter(|rr| rr.rr_type() == record_type && rr.name() == &name)
            .cloned()
            .collect();

        let rrsigs: Vec<Record> = message_result
            .answers()
            .iter()
            .chain(message_result.name_servers())
            .chain(message_result.additionals())
            .filter(|rr| is_dnssec(rr, DNSSECRecordType::RRSIG))
            .filter(|rr| {
                if let RData::DNSSEC(DNSSECRData::SIG(ref rrsig)) = *rr.rdata() {
                    rrsig.type_covered() == record_type
                } else {
                    false
                }
            })
            .cloned()
            .collect();

        // if there is already an active validation going on, assume the other validation will
        //  complete properly or error if it is invalid
        let rrset = Rrset {
            name: name,
            record_type: record_type,
            record_class: dns_class,
            records: rrset,
        };

        // TODO: support non-IN classes?
        debug!(
            "verifying: {}, record_type: {:?}, rrsigs: {}",
            rrset.name,
            record_type,
            rrsigs.len()
        );
        rrsets.push(verify_rrset(handle.clone_with_context(), rrset, rrsigs));
    }

    // spawn a select_all over this vec, these are the individual RRSet validators
    let rrsets_to_verify = select_all(rrsets);

    // return the full Message validator
    Box::new(VerifyRrsetsFuture {
        message_result: Some(message_result),
        rrsets: rrsets_to_verify,
        verified_rrsets: HashSet::new(),
    })
}

fn is_dnssec(rr: &Record, dnssec_type: DNSSECRecordType) -> bool {
    rr.rr_type() == RecordType::DNSSEC(dnssec_type)
}

impl<E> Future for VerifyRrsetsFuture<E>
where
    E: FromProtoError,
{
    type Item = Message;
    type Error = E;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if self.message_result.is_none() {
            return Err(E::from(ProtoErrorKind::Message("message is none").into()));
        }

        // loop through all the rrset evaluations, filter all the rrsets in the Message
        //  down to just the ones that were able to be validated
        loop {
            let remaining = match self.rrsets.poll() {
                // one way the loop will stop, nothing is ready...
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                // all rrsets verified! woop!
                Ok(Async::Ready((rrset, _, remaining))) => {
                    debug!(
                        "an rrset was verified: {}, {:?}",
                        rrset.name,
                        rrset.record_type
                    );
                    self.verified_rrsets.insert((rrset.name, rrset.record_type));
                    remaining
                }
                // TODO, should we return the Message on errors? Allow the consumer to decide what to do
                //       on a validation failure?
                // any error, is an error for all
                Err((e, _, remaining)) => {
                    debug!("an rrset failed to verify: {:?}", e);
                    if remaining.is_empty() {
                        return Err(e);
                    }
                    remaining
                }
            };

            if !remaining.is_empty() {
                // continue the evaluation
                drop(mem::replace(&mut self.rrsets, select_all(remaining)));
            } else {
                // validated not none above...
                let mut message_result = mem::replace(&mut self.message_result, None).unwrap();

                // take all the rrsets from the Message, filter down each set to the validated rrsets
                // TODO: does the section in the message matter here?
                //       we could probably end up with record_types in any section.
                //       track the section in the rrset evaluation?
                let answers = message_result
                    .take_answers()
                    .into_iter()
                    .chain(message_result.take_additionals().into_iter())
                    .filter(|record| {
                        self.verified_rrsets
                            .contains(&(record.name().clone(), record.rr_type()))
                    })
                    .collect::<Vec<Record>>();

                let name_servers = message_result
                    .take_name_servers()
                    .into_iter()
                    .filter(|record| {
                        self.verified_rrsets
                            .contains(&(record.name().clone(), record.rr_type()))
                    })
                    .collect::<Vec<Record>>();

                let additionals = message_result
                    .take_additionals()
                    .into_iter()
                    .filter(|record| {
                        self.verified_rrsets
                            .contains(&(record.name().clone(), record.rr_type()))
                    })
                    .collect::<Vec<Record>>();

                // add the filtered records back to the message
                message_result.insert_answers(answers);
                message_result.insert_name_servers(name_servers);
                message_result.insert_additionals(additionals);

                // breaks out of the loop... and returns the filtered Message.
                return Ok(Async::Ready(message_result));
            }
        }
    }
}

/// Generic entrypoint to verify any RRSET against the provided signatures.
///
/// Generally, the RRSET will be validated by `verify_default_rrset()`. There are additional
///  checks that happen after the RRSET is successfully validated. In the case of DNSKEYs this
///  triggers `verify_dnskey_rrset()`. If it's an NSEC record, then the NSEC record will be
///  validated to prove it's correctness. There is a special case for DNSKEY, where if the RRSET
///  is unsigned, `rrsigs` is empty, then an immediate `verify_dnskey_rrset()` is triggered. In
///  this case, it's possible the DNSKEY is a trust_anchor and is not self-signed.
fn verify_rrset<H, E>(
    handle: SecureDnsHandle<H, E>,
    rrset: Rrset,
    rrsigs: Vec<Record>,
) -> Box<Future<Item = Rrset, Error = E>>
where
    H: DnsHandle<Error = E>,
    E: FromProtoError,
{
    // Special case for unsigned DNSKEYs, it's valid for a DNSKEY to be bare in the zone if
    //  it's a trust_anchor, though some DNS servers choose to self-sign in this case,
    //  for self-signed KEYS they will drop through to the standard validation logic.
    if let RecordType::DNSSEC(DNSSECRecordType::DNSKEY) = rrset.record_type {
        if rrsigs.is_empty() {
            debug!("unsigned key: {}, {:?}", rrset.name, rrset.record_type);
            // FIXME: validate that this DNSKEY is stronger than the one lower in the chain,
            //  also, set the min algorithm to this algorithm to prevent downgrade attacks.
            return verify_dnskey_rrset(handle.clone_with_context(), rrset);
        }
    }

    // standard validation path
    Box::new(
        verify_default_rrset(&handle.clone_with_context(), rrset, rrsigs)
            .and_then(|rrset|
          // POST validation
          match rrset.record_type {
            RecordType::DNSSEC(DNSSECRecordType::DNSKEY) =>
                verify_dnskey_rrset(handle, rrset),
            // RecordType::DNSSEC(DNSSECRecordType::DS) => verify_ds_rrset(handle, name, record_type, record_class, rrset, rrsigs),
            _ => Box::new(finished(rrset)),
          })
            .map_err(|e| {
                debug!("rrset failed validation: {}", e);
                e
            }),
    )
}

/// Verifies a dnskey rrset
///
/// This first checks to see if the key is in the set of trust_anchors. If so then it's returned
///  as a success. Otherwise, a query is sent to get the DS record, and the DNSKEY is validated
///  against the DS record.
fn verify_dnskey_rrset<H, E>(
    mut handle: SecureDnsHandle<H, E>,
    rrset: Rrset,
) -> Box<Future<Item = Rrset, Error = E>>
where
    H: DnsHandle<Error = E>,
    E: FromProtoError,
{
    debug!(
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
            .filter(|&(_, rr)| is_dnssec(rr, DNSSECRecordType::DNSKEY))
            .filter_map(|(i, rr)| {
                if let RData::DNSSEC(DNSSECRData::DNSKEY(ref rdata)) = *rr.rdata() {
                    Some((i, rdata))
                } else {
                    None
                }
            })
            .filter_map(|(i, rdata)| {
                if handle
                    .trust_anchor
                    .contains_dnskey_bytes(rdata.public_key())
                {
                    debug!("in trust_anchor");
                    Some(i)
                } else {
                    None
                }
            })
            .collect::<Vec<usize>>();

        if !anchored_keys.is_empty() {
            let mut rrset = rrset;
            preserve(&mut rrset.records, anchored_keys);

            debug!(
                "validated dnskey with trust_anchor: {}, {}",
                rrset.name,
                rrset.records.len()
            );
            return Box::new(finished(rrset));
        }
    }

    // need to get DS records for each DNSKEY
    let valid_dnskey = handle
        .lookup(Query::query(
            rrset.name.clone(),
            RecordType::DNSSEC(DNSSECRecordType::DS),
        ))
        .and_then(move |ds_message| {
            let valid_keys = rrset
                .records
                .iter()
                .enumerate()
                .filter(|&(_, rr)| is_dnssec(rr, DNSSECRecordType::DNSKEY))
                .filter_map(|(i, rr)| {
                    if let RData::DNSSEC(DNSSECRData::DNSKEY(ref rdata)) = *rr.rdata() {
                        Some((i, rdata))
                    } else {
                        None
                    }
                })
                .filter(|&(_, key_rdata)| {
                    ds_message.answers()
                              .iter()
                              .filter(|ds| is_dnssec(ds, DNSSECRecordType::DS))
                              .filter_map(|ds| if let RData::DNSSEC(DNSSECRData::DS(ref ds_rdata)) = *ds.rdata() {
                                Some(ds_rdata)
                              } else {
                                None
                              })
                              // must be convered by at least one DS record
                              .any(|ds_rdata| ds_rdata.covers(&rrset.name, key_rdata)
                                                      .unwrap_or(false))
                })
                .map(|(i, _)| i)
                .collect::<Vec<usize>>();

            if !valid_keys.is_empty() {
                let mut rrset = rrset;
                preserve(&mut rrset.records, valid_keys);

                debug!("validated dnskey: {}, {}", rrset.name, rrset.records.len());
                Ok(rrset)
            } else {
                Err(E::from(
                    ProtoErrorKind::Message("Could not validate all DNSKEYs").into(),
                ))
            }
        });

    Box::new(valid_dnskey)
}

/// Preseves the specified indexes in vec, all others will be removed
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
    // this removes all indexes theat were not part of the anchored keys
    let mut indexes_iter = indexes.into_iter().rev();
    let mut i = indexes_iter.next();
    for j in (0..vec.len()).rev() {
        // check the next indext to preserve
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
fn verify_default_rrset<H, E>(
    handle: &SecureDnsHandle<H>,
    rrset: Rrset,
    rrsigs: Vec<Record>,
) -> Box<Future<Item = Rrset, Error = E>>
where
    H: DnsHandle<Error = E>,
    E: FromProtoError,
{
    // the record set is going to be shared across a bunch of futures, Rc for that.
    let rrset = Rc::new(rrset);
    debug!(
        "default validation {}, record_type: {:?}",
        rrset.name,
        rrset.record_type
    );

    // Special case for self-signed DNSKEYS, validate with itself...
    if rrsigs
        .iter()
        .filter(|rrsig| is_dnssec(rrsig, DNSSECRecordType::RRSIG))
        .any(|rrsig| {
            if let RData::DNSSEC(DNSSECRData::SIG(ref sig)) = *rrsig.rdata() {
                return RecordType::DNSSEC(DNSSECRecordType::DNSKEY) == rrset.record_type
                    && sig.signer_name() == &rrset.name;
            } else {
                panic!("expected a SIG here");
            }
        }) {
        // in this case it was looks like a self-signed key, first validate the signature
        //  then return rrset. Like the standard case below, the DNSKEY is validated
        //  after this function. This function is only responsible for validating the signature
        //  the DNSKey validation should come after, see verify_rrset().
        return Box::new(
            done(
                rrsigs.into_iter()
            // this filter is technically unnecessary, can probably remove it...
            .filter(|rrsig| is_dnssec(rrsig, DNSSECRecordType::RRSIG))
            .map(|rrsig|
              if let RData::DNSSEC(DNSSECRData::SIG(sig)) = rrsig.unwrap_rdata() {
                // setting up the context explicitly.
                sig
              } else {
                panic!("expected a SIG here");
              }
            )
            .filter_map(|sig| {
              let rrset = Rc::clone(&rrset);

              if rrset.records.iter()
                              .any(|r| {
                                if let RData::DNSSEC(DNSSECRData::DNSKEY(ref dnskey)) = *r.rdata() {
                                  verify_rrset_with_dnskey(dnskey, &sig, &rrset).is_ok()
                                } else {
                                  panic!("expected a DNSKEY here: {:?}", r.rdata());
                                }
                              }) {
                                Some(rrset)
                              } else {
                                None
                              }
                            })
                            .next()
                            .ok_or_else(|| E::from(ProtoErrorKind::Message("self-signed dnskey is invalid").into())),
            ).map(move |rrset| {
                Rc::try_unwrap(rrset).expect("unable to unwrap Rc")
            }),
        );
    }

    // we can validate with any of the rrsigs...
    //  i.e. the first that validates is good enough
    //  TODO: could there be a cert downgrade attack here with a MITM stripping stronger RRSIGs?
    //         we could check for the strongest RRSIG and only use that...
    //         though, since the entire package isn't signed any RRSIG could have been injected,
    //         right? meaning if there is an attack on any of the acceptable algorithms, we'd be
    //         succeptable until that algorithm is removed as an option.
    //        dns over TLS will mitigate this.
    //  TODO: strip RRSIGS to accepted algorithms and make algorithms configurable.
    let verifications = rrsigs.into_iter()
                            // this filter is technically unnecessary, can probably remove it...
                            .filter(|rrsig| is_dnssec(rrsig, DNSSECRecordType::RRSIG))
                            .map(|rrsig|
                              if let RData::DNSSEC(DNSSECRData::SIG(sig)) = rrsig.unwrap_rdata() {
                                // setting up the context explicitly.
                                sig
                              } else {
                                panic!("expected a SIG here");
                              }
                            )
                            .map(|sig| {
                              let rrset = Rc::clone(&rrset);
                              let mut handle = handle.clone_with_context();

                              handle.lookup(Query::query(sig.signer_name().clone(), RecordType::DNSSEC(DNSSECRecordType::DNSKEY)))
                                    .and_then(move |message|
                                      // DNSKEYs are validated by the inner query
                                      message.answers()
                                             .iter()
                                             .filter(|r| is_dnssec(r, DNSSECRecordType::DNSKEY))
                                             .find(|r|
                                               if let RData::DNSSEC(DNSSECRData::DNSKEY(ref dnskey)) = *r.rdata() {
                                                 verify_rrset_with_dnskey(dnskey, &sig, &rrset).is_ok()
                                               } else {
                                                 panic!("expected a DNSKEY here: {:?}", r.rdata());
                                               }
                                             )
                                             .map(|_| rrset)
                                             .ok_or_else(|| E::from(ProtoErrorKind::Message("validation failed").into()))
                                    )
                            })
                            .collect::<Vec<_>>();

    // if there are no available verifications, then we are in a failed state.
    if verifications.is_empty() {
        return Box::new(failed(E::from(
            ProtoErrorKind::RrsigsNotPresent(rrset.name.clone(), rrset.record_type).into(),
        )));
    }

    // as long as any of the verifcations is good, then the RRSET is valid.
    let select = select_ok(verifications)
                          // getting here means at least one of the rrsigs succeeded...
                          .map(move |(rrset, rest)| {
                              drop(rest); // drop all others, should free up Rc
                              Rc::try_unwrap(rrset).expect("unable to unwrap Rc")
                          });

    Box::new(select)
}

/// Verifies the given SIG of the RRSET with the DNSKEY.
#[cfg(feature = "dnssec")]
fn verify_rrset_with_dnskey(dnskey: &DNSKEY, sig: &SIG, rrset: &Rrset) -> ProtoResult<()> {
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
        .map_err(Into::into)
}

/// Will always return an error. To enable record verification compile with the openssl feature.
#[cfg(not(feature = "dnssec"))]
fn verify_rrset_with_dnskey(_: &DNSKEY, _: &SIG, _: &Rrset) -> ProtoResult<()> {
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
fn verify_nsec(query: &Query, nsecs: &[&Record]) -> bool {
    // first look for a record with the same name
    //  if they are, then the query_type should not exist in the NSEC record.
    //  if we got an NSEC record of the same name, but it is listed in the NSEC types,
    //    WTF? is that bad server, bad record
    if nsecs.iter().any(|r| {
        query.name() == r.name() && {
            if let RData::DNSSEC(DNSSECRData::NSEC(ref rdata)) = *r.rdata() {
                !rdata.type_bit_maps().contains(&query.query_type())
            } else {
                panic!("expected NSEC was {:?}", r.rr_type()) // valid panic, never should happen
            }
        }
    }) {
        return true;
    }

    // based on the WTF? above, we will ignore any NSEC records of the same name
    if nsecs.iter().filter(|r| query.name() != r.name()).any(|r| {
        query.name() > r.name() && {
            if let RData::DNSSEC(DNSSECRData::NSEC(ref rdata)) = *r.rdata() {
                query.name() < rdata.next_domain_name()
            } else {
                panic!("expected NSEC was {:?}", r.rr_type()) // valid panic, never should happen
            }
        }
    }) {
        return true;
    }

    // TODO: need to validate ANY or *.domain record existance, which doesn't make sense since
    //  that would have been returned in the request
    // if we got here, then there are no matching NSEC records, no validation
    false
}
