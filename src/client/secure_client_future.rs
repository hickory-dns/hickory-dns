// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::collections::hash_set::Drain;
use std::mem;
use std::rc::Rc;

use chrono::UTC;
use futures;
use futures::{AndThen, Async, Complete, Future, Oneshot, Poll, task};
use futures::{collect, Collect, failed, finished, IntoFuture, select_all, SelectAll, SelectAllNext};
use futures::stream::{Peekable, Fuse as StreamFuse, Stream};
use futures::task::park;
use openssl::crypto::pkey::Role;
use rand::Rng;
use rand;
use tokio_core::reactor::Handle;
use tokio_core::channel::{channel, Sender, Receiver};

use ::client::{BasicClientHandle, ClientHandle};
use ::client::select_any::select_any;
use ::error::*;
use ::op::{Edns, Message, MessageType, OpCode, Query, UpdateMessage};
use ::rr::{domain, DNSClass, RData, Record, RecordType};
use ::rr::dnssec::{Signer, TrustAnchor};
use ::rr::rdata::{dnskey, DNSKEY, DS, NULL, SIG};
use ::tcp::{TcpClientStream, TcpClientStreamHandle};
use ::udp::{UdpClientStream, UdpClientStreamHandle};
use ::serialize::binary::{BinEncoder, BinSerializable};

#[derive(Debug)]
struct Rrset {
    pub name: domain::Name,
    pub record_type: RecordType,
    pub record_class: DNSClass,
    pub records: Vec<Record>,
}

/// A ClientHandle which will return DNSSec validating futures.
///
/// This wraps a ClientHandle, changing the implementation `send()` to validate all
///  message responses for Query operations. Update operations are not validated.
pub struct SecureClientHandle {
  client: BasicClientHandle,
  trust_anchor: Rc<TrustAnchor>,
  request_depth: usize,
  active_validations: Rc<RefCell<HashSet<(domain::Name, RecordType, DNSClass)>>>,
}

impl SecureClientHandle {
  /// Create a new SecureClientHandle wrapping the speicified client.
  ///
  /// This uses the compiled in TrustAnchor default trusted keys.
  ///
  /// # Arguments
  /// * `client` - client to use for all connections to a remote server.
  pub fn new(client: BasicClientHandle) -> SecureClientHandle {
    Self::with_trust_anchor(client, TrustAnchor::default())
  }

  /// Create a new SecureClientHandle wrapping the speicified client.
  ///
  /// This allows a custom TrustAnchor to be define.
  ///
  /// # Arguments
  /// * `client` - client to use for all connections to a remote server.
  /// * `trust_anchor` - custom DNSKEYs that will be trusted, can be used to pin trusted keys.
  pub fn with_trust_anchor(client: BasicClientHandle, trust_anchor: TrustAnchor) -> SecureClientHandle {
    SecureClientHandle {
      client: client,
      trust_anchor: Rc::new(trust_anchor),
      request_depth: 0,
      active_validations: Rc::new(RefCell::new(HashSet::new()))
    }
  }

  /// An internal function used to clone the client, but maintain some information back to the
  ///  original client, such as the set of active_validations such that infinite recurssion does
  ///  not occur.
  fn clone_with_context(&self) -> Self {
    SecureClientHandle {
      client: self.client.clone(),
      trust_anchor: self.trust_anchor.clone(),
      request_depth: self.request_depth + 1,
      active_validations: self.active_validations.clone()
    }
  }
}

impl ClientHandle for SecureClientHandle {
  fn send(&self, mut message: Message) -> Box<Future<Item=Message, Error=ClientError>> {
    // backstop, this might need to be configurable at some point
    if self.request_depth > 20 {
      return Box::new(failed(ClientErrorKind::Message("exceeded max validation depth").into()))
    }

    // dnssec only matters on queries.
    if let OpCode::Query = message.get_op_code() {
      let client: SecureClientHandle = self.clone_with_context();
      let active_validations = self.active_validations.clone();
      let request_depth = self.request_depth;

      {
        let edns = message.get_edns_mut();
        edns.set_dnssec_ok(true);
      }

      message.authentic_data(true);
      message.checking_disabled(false);
      let dns_class = message.get_queries().first().map_or(DNSClass::IN, |q| q.get_query_class());

      return Box::new(
        self.client.send(message)
                   .and_then(move |message_response|{
                     // group the record sets by name and type
                     //  each rrset type needs to validated independently
                     debug!("validating message_response: {}", message_response.get_id());
                     VerifyRrsetsFuture::new(
                       client,
                       message_response,
                       dns_class,
                     )
                   })
                   .then(move |verify| {
                     // TODO: this feels dirty, is there a cleaner way?
                     // if our request depth is zero then this is the top of the stack, clear
                     //  active_validations
                     if request_depth == 0 {
                       active_validations.borrow_mut().clear();
                     }

                     verify
                   })
                 )
    }

    self.client.send(message)
  }
}

/// A future to verify all RRSets in a returned Message.
pub struct VerifyRrsetsFuture {
  client: SecureClientHandle,
  message_result: Option<Message>,
  rrsets: Collect<Vec<Box<Future<Item=Rrset, Error=ClientError>>>>,
}

impl VerifyRrsetsFuture {
  /// this pulls all records returned in a Message respons and returns a future which will
  ///  validate all of them.
  fn new(
    client: SecureClientHandle,
    message_result: Message,
    dns_class: DNSClass,
  ) -> VerifyRrsetsFuture {
    let mut rrset_types: HashSet<(domain::Name, RecordType)> = HashSet::new();
    for rrset in message_result.get_answers()
                               .iter()
                               .chain(message_result.get_name_servers())
                               .filter(|rr| rr.get_rr_type() != RecordType::RRSIG)
                               .map(|rr| (rr.get_name().clone(), rr.get_rr_type())) {
      rrset_types.insert(rrset);
    }

    // collect all the rrsets to verify
    // TODO: is there a way to get rid of this clone() safely?
    let mut rrsets = Vec::with_capacity(rrset_types.len());
    for (name, record_type) in rrset_types {
      // if there is already an active validation going on, assume the other validation will
      //  complete properly or error if it is invalid
      let request_key = (name.clone(), record_type, dns_class);
      if client.active_validations.borrow().contains(&request_key) {
        debug!("skipping active validation: {}, {:?}, {:?}", name, record_type, dns_class);
        continue
      }

      let rrset: Vec<Record> = message_result.get_answers()
                                             .iter()
                                             .chain(message_result.get_name_servers())
                                             .filter(|rr| rr.get_rr_type() == record_type &&
                                                          rr.get_name() == &name)
                                             .cloned()
                                             .collect();

      let rrsigs: Vec<Record> = message_result.get_answers()
                                              .iter()
                                              .chain(message_result.get_name_servers())
                                              .filter(|rr| rr.get_rr_type() == RecordType::RRSIG)
                                              .filter(|rr| if let &RData::SIG(ref rrsig) = rr.get_rdata() {
                                                rrsig.get_type_covered() == record_type
                                              } else {
                                                false
                                              })
                                              .cloned()
                                              .collect();

      // TODO: support non-IN classes?
      debug!("verifying: {}, record_type: {:?}", name, record_type);
      let rrset = Rrset { name: name, record_type: record_type, record_class: dns_class, records: rrset };
      rrsets.push(verify_rrset(client.clone_with_context(), rrset, rrsigs));
      client.active_validations.borrow_mut().insert(request_key);
      // rrsets.push(VerifyRrsetFuture{ client: client.clone(), name: name, record_type: record_type,
      //             record_class: DNSClass::IN, rrset: rrset, rrsigs: rrsigs });
    }

    // spawn a select_all over this vec, these are the individual RRSet validators
    let rrsets_to_verify = collect(rrsets);

    // return the full Message validator
    VerifyRrsetsFuture{
      client: client,
      message_result: Some(message_result),
      rrsets: rrsets_to_verify,
    }
  }
}


impl Future for VerifyRrsetsFuture {
  type Item = Message;
  type Error = ClientError;

  fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
    if self.message_result.is_none() {
      return Err(ClientErrorKind::Message("message is none").into())
    }

    // TODO: Can we do this in parallel?
    // HINT: use select_all
    // FIXME: strip unvalidated records from the message
    match self.rrsets.poll() {
      Ok(Async::NotReady) => Ok(Async::NotReady),
      // all rrsets verified! woop!
      Ok(Async::Ready(_)) => {
        let message_result = mem::replace(&mut self.message_result, None);
        Ok(Async::Ready(message_result.unwrap())) // validated not none above...
      },
      // TODO, should we return the Message on errors? Allow the consumer to decide what to do
      //       on a validation failure?
      // any error, is an error for all
      Err(e) => Err(e),
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
fn verify_rrset(client: SecureClientHandle,
                rrset: Rrset,
                rrsigs: Vec<Record>,)
                -> Box<Future<Item=Rrset, Error=ClientError>> {
  // Special case for unsigned DNSKEYs, it's valid for a DNSKEY to be bare in the zone if
  //  it's a trust_anchor, though some DNS servers choose to self-sign in this case,
  //  for self-signed KEYS they will drop through to the standard validation logic.
  if rrsigs.is_empty() {
    debug!("unsigned key: {}, {:?}", rrset.name, rrset.record_type);
    if let RecordType::DNSKEY = rrset.record_type {
      return verify_dnskey_rrset(client.clone_with_context(), rrset)
    }
  }

  // standard validation path
  Box::new(verify_default_rrset(client.clone_with_context(), rrset, rrsigs)
        .and_then(|rrset|
          // POST validation
          match rrset.record_type {
            RecordType::NSEC => Box::new(failed(ClientErrorKind::Message("NSEC not implemented").into())),
            RecordType::DNSKEY => verify_dnskey_rrset(client, rrset),
            // RecordType::DS => verify_ds_rrset(client, name, record_type, record_class, rrset, rrsigs),
            _ => Box::new(finished(rrset)),
          }
        )
        .map_err(|e| {
          debug!("rrset failed validation: {}", e);
          e
        })
      )
}

/// Verifies a dnskey rrset
///
/// This first checks to see if the key is in the set of trust_anchors. If so then it's returned
///  as a success. Otherwise, a query is sent to get the DS record, and the DNSKEY is validated
///  against the DS record.
fn verify_dnskey_rrset(
  client: SecureClientHandle,
  rrset: Rrset)
  -> Box<Future<Item=Rrset, Error=ClientError>>
{
  debug!("dnskey validation {}, record_type: {:?}", rrset.name, rrset.record_type);

  // check the DNSKEYS against the trust_anchor, if it's approved allow it.
  {
    let anchored_keys = rrset.records.iter()
      .enumerate()
      .filter(|&(_, rr)| rr.get_rr_type() == RecordType::DNSKEY)
      .filter_map(|(i, rr)| if let &RData::DNSKEY(ref rdata) = rr.get_rdata() {
        Some((i, rdata))
      } else {
        None
      })
      .filter_map(|(i, rdata)| {
        if client.trust_anchor.contains(rdata.get_public_key()) {
          debug!("in trust_anchor");
          Some(i)
        } else {
          debug!("not in trust_anchor");
          None
        }
      })
      .collect::<Vec<usize>>();

    if !anchored_keys.is_empty() {
      let mut rrset = rrset;
      preserve(&mut rrset.records, anchored_keys);

      debug!("validated dnskey with trust_anchor: {}, {}", rrset.name, rrset.records.len());
      return Box::new(finished((rrset)))
    }
  }

  // need to get DS records for each DNSKEY
  let valid_dnskey = client.query(rrset.name.clone(), rrset.record_class, RecordType::DS)
        .and_then(move |ds_message| {
           let valid_keys = rrset.records.iter()
                  .enumerate()
                  .filter(|&(_,rr)| rr.get_rr_type() == RecordType::DNSKEY)
                  .filter_map(|(i,rr)| if let &RData::DNSKEY(ref rdata) = rr.get_rdata() {
                    Some((i, rdata))
                  } else {
                    None
                  })
                  .filter(|&(_, key_rdata)|
                    ds_message.get_answers()
                              .iter()
                              .filter(|ds| ds.get_rr_type() == RecordType::DS)
                              .filter_map(|ds| if let &RData::DS(ref ds_rdata) = ds.get_rdata() {
                                Some(ds_rdata)
                              } else {
                                None
                              })
                              // must be convered by at least one DS record
                              .any(|ds_rdata| is_key_covered_by(&rrset.name, key_rdata, ds_rdata))
                  )
                  .map(|(i, _)| i)
                  .collect::<Vec<usize>>();

          if !valid_keys.is_empty() {
            let mut rrset = rrset;
            preserve(&mut rrset.records, valid_keys);

            debug!("validated dnskey: {}, {}", rrset.name, rrset.records.len());
            Ok(rrset)
          } else {
            Err(ClientErrorKind::Message("Could not validate all DNSKEYs").into())
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
fn preserve<T, I>(vec: &mut Vec<T>, indexes: I) where
  I: IntoIterator<Item=usize>,
  //<I as IntoIterator>::Item: usize,
  <I as IntoIterator>::IntoIter: DoubleEndedIterator
 {
    // this removes all indexes theat were not part of the anchored keys
    let mut indexes_iter = indexes.into_iter().rev();
    let mut i = indexes_iter.next();
    for j in (0..vec.len()).rev() {
        // check the next indext to preserve
        if i.map_or(false, |i| i > j) { i = indexes_iter.next(); }
        // if the key is not in the set of anchored_keys, remove it
        if i.map_or(true, |i| i != j) { vec.remove(j); }
    }
}

#[test]
fn test_preserve() {
    let mut vec = vec![1,2,3];
    let indexes = vec![];
    preserve(&mut vec, indexes);
    assert_eq!(vec, vec![]);

    let mut vec = vec![1,2,3];
    let indexes = vec![0];
    preserve(&mut vec, indexes);
    assert_eq!(vec, vec![1]);

    let mut vec = vec![1,2,3];
    let indexes = vec![1];
    preserve(&mut vec, indexes);
    assert_eq!(vec, vec![2]);

    let mut vec = vec![1,2,3];
    let indexes = vec![2];
    preserve(&mut vec, indexes);
    assert_eq!(vec, vec![3]);

    let mut vec = vec![1,2,3];
    let indexes = vec![0,2];
    preserve(&mut vec, indexes);
    assert_eq!(vec, vec![1,3]);

    let mut vec = vec![1,2,3];
    let indexes = vec![0,1,2];
    preserve(&mut vec, indexes);
    assert_eq!(vec, vec![1,2,3]);
}

/// Validates that a given DNSKEY is covered by the DS record.
///
/// # Return
///
/// true if and only if the DNSKEY is covered by the DS record.
///
/// ```text
/// 5.1.4.  The Digest Field
///
///    The DS record refers to a DNSKEY RR by including a digest of that
///    DNSKEY RR.
///
///    The digest is calculated by concatenating the canonical form of the
///    fully qualified owner name of the DNSKEY RR with the DNSKEY RDATA,
///    and then applying the digest algorithm.
///
///      digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
///
///       "|" denotes concatenation
///
///      DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.
///
///    The size of the digest may vary depending on the digest algorithm and
///    DNSKEY RR size.  As of the time of this writing, the only defined
///    digest algorithm is SHA-1, which produces a 20 octet digest.
/// ```
fn is_key_covered_by(name: &domain::Name, key: &DNSKEY, ds: &DS) -> bool {
  let mut buf: Vec<u8> = Vec::new();
  {
    let mut encoder: BinEncoder = BinEncoder::new(&mut buf);
    encoder.set_canonical_names(true);
    if let Err(e) = name.emit(&mut encoder)
                        .and_then(|_| dnskey::emit(&mut encoder, key)) {
      warn!("error serializing dnskey: {}", e);
      return false
    }
  }

  let hash: Vec<u8> = ds.get_digest_type().hash(&buf);
  if &hash as &[u8] == ds.get_digest() {
      debug!("key is covered by");
      true
  } else {
      false
  }
}

/// Verifies that a given RRSET is validly signed by any of the specified RRSIGs.
///
/// Invalid RRSIGs will be ignored. RRSIGs will only be validated against DNSKEYs which can
///  be validated through a chain back to the `trust_anchor`. As long as one RRSIG is valid,
///  then the RRSET will be valid.
fn verify_default_rrset(
  client: SecureClientHandle,
  rrset: Rrset,
  rrsigs: Vec<Record>,)
  -> Box<Future<Item=Rrset, Error=ClientError>>
{
  // the record set is going to be shared across a bunch of futures, Rc for that.
  let rrset = Rc::new(rrset);
  debug!("default validation {}, record_type: {:?}", rrset.name, rrset.record_type);
  // we can validate with any of the rrsigs...
  //  i.e. the first that validates is good enough
  //  FIXME: could there be a cert downgrade attack here?
  //         we could check for the strongest RRSIG and only use that...
  //         though, since the entire package isn't signed any RRSIG could have been injected,
  //         right? meaning if there is an attack on any of the acceptable algorithms, we'd be
  //         succeptable until that algorithm is removed as an option.
  //  TODO: strip RRSIGS to accepted algorithms and make algorithms configurable.
  let verifications = rrsigs.into_iter()
                            // this filter is technically unnecessary, can probably remove it...
                            .filter(|rrsig| rrsig.get_rr_type() == RecordType::RRSIG)
                            .map(|rrsig|
                              if let RData::SIG(sig) = rrsig.unwrap_rdata() {
                                // setting up the context explicitly.
                                sig
                              } else {
                                panic!("expected a SIG here");
                              }
                            )
                            .map(|sig| {
                              let rrset = rrset.clone();
                              let client = client.clone_with_context();

                              client.query(sig.get_signer_name().clone(), rrset.record_class, RecordType::DNSKEY)
                                    .and_then(move |message|
                                      // FIXME: only use validated DNSKEYs
                                      message.get_answers()
                                             .iter()
                                             .filter(|r| r.get_rr_type() == RecordType::DNSKEY)
                                             .find(|r|
                                               if let &RData::DNSKEY(ref dnskey) = r.get_rdata() {
                                                 verify_rrset_with_dnskey(dnskey, &sig, &rrset)
                                               } else {
                                                 panic!("expected a DNSKEY here: {:?}", r.get_rdata());
                                               }
                                             )
                                             .map(|_| rrset)
                                             .ok_or(ClientErrorKind::Message("validation failed").into())
                                    )
                            })
                            .collect::<Vec<_>>();

  // if there are no available verifications, then we are in a failed state.
  if verifications.is_empty() {
    return Box::new(failed(ClientErrorKind::Msg(format!("no RRSIGs available for validation: {}, {:?}", rrset.name, rrset.record_type)).into()));
  }

  // as long as any of the verifcations is good, then the RRSET is valid.
  let select = select_any(verifications)
                          // getting here means at least one of the rrsigs succeeded...
                          .map(move |(rrset, rest)| {
                              drop(rest); // drop all others, should free up Rc
                              Rc::try_unwrap(rrset).expect("unable to unwrap Rc")
                          });

  Box::new(select)
}

/// Verifies the given SIG of the RRSET with the DNSKEY. 
fn verify_rrset_with_dnskey(dnskey: &DNSKEY,
                            sig: &SIG,
                            rrset: &Rrset) -> bool {
  if dnskey.is_revoke() { debug!("revoked"); return false } // TODO: does this need to be validated? RFC 5011
  if !dnskey.is_zone_key() { return false }
  if *dnskey.get_algorithm() != sig.get_algorithm() { return false }

  let pkey = dnskey.get_algorithm().public_key_from_vec(dnskey.get_public_key());
  if let Err(e) = pkey { debug!("error getting key from vec: {}", e); return false }
  let pkey = pkey.unwrap();
  if !pkey.can(Role::Verify) { debug!("pkey can't verify"); return false }

  let signer: Signer = Signer::new_verifier(*dnskey.get_algorithm(), pkey, sig.get_signer_name().clone());
  let rrset_hash: Vec<u8> = signer.hash_rrset_with_sig(&rrset.name, rrset.record_class, sig, &rrset.records);

  if signer.verify(&rrset_hash, sig.get_sig()) {
      debug!("verified rrset: {}, type: {:?}", rrset.name, rrset.record_type);
      true
  } else {
      false
  }
}

#[cfg(test)]
pub mod test {
  use std::fmt;
  use std::io;
  use std::net::*;

  use chrono::Duration;
  use futures;
  use futures::{Async, Complete, Future, finished, Oneshot, Poll, task};
  use futures::stream::{Fuse, Stream};
  use futures::task::park;
  use openssl::crypto::pkey::{PKey, Role};
  use tokio_core::reactor::{Core, Handle};
  use tokio_core::channel::{channel, Sender, Receiver};

  use ::client::{ClientFuture, BasicClientHandle, ClientHandle, SecureClientHandle, TestClientStream};
  use ::error::*;
  use ::op::{Message, ResponseCode};
  use ::authority::Catalog;
  use ::authority::authority_tests::{create_example, create_secure_example};
  use ::rr::domain;
  use ::rr::{DNSClass, RData, Record, RecordType};
  use ::rr::dnssec::{Algorithm, Signer, TrustAnchor};
  use ::serialize::binary::{BinDecoder, BinEncoder, BinSerializable};
  use ::udp::{UdpClientStream, UdpClientStreamHandle};
  use ::tcp::{TcpClientStream, TcpClientStreamHandle};

  #[test]
  fn test_secure_query_example_nonet() {
    use log::LogLevel;
    use ::logger::TrustDnsLogger;
    TrustDnsLogger::enable_logging(LogLevel::Debug);

    let authority = create_secure_example();

    let public_key = {
      let signers = authority.get_secure_keys();
      signers.first().expect("expected a key in the authority").get_public_key()
    };

    let mut catalog = Catalog::new();
    catalog.upsert(authority.get_origin().clone(), authority);

    let mut trust_anchor = TrustAnchor::new();
    trust_anchor.insert_trust_anchor(public_key);

    let mut io_loop = Core::new().unwrap();
    let (stream, sender) = TestClientStream::new(catalog, io_loop.handle());
    let client = ClientFuture::new(stream, sender, io_loop.handle(), None);
    let secure_client = SecureClientHandle::with_trust_anchor(client, trust_anchor);

    test_secure_query_example(secure_client, io_loop);
  }

  #[test]
  #[ignore]
  fn test_secure_query_example_udp() {
      use log::LogLevel;
      use ::logger::TrustDnsLogger;
      TrustDnsLogger::enable_logging(LogLevel::Debug);

    let mut io_loop = Core::new().unwrap();
    let addr: SocketAddr = ("8.8.8.8",53).to_socket_addrs().unwrap().next().unwrap();
    let (stream, sender) = UdpClientStream::new(addr, io_loop.handle());
    let client = ClientFuture::new(stream, sender, io_loop.handle(), None);
    let secure_client = SecureClientHandle::new(client);

    test_secure_query_example(secure_client, io_loop);
  }

  #[test]
  #[ignore]
  fn test_secure_query_example_tcp() {
      use log::LogLevel;
      use ::logger::TrustDnsLogger;
      TrustDnsLogger::enable_logging(LogLevel::Debug);

    let mut io_loop = Core::new().unwrap();
    let addr: SocketAddr = ("8.8.8.8",53).to_socket_addrs().unwrap().next().unwrap();
    let (stream, sender) = TcpClientStream::new(addr, io_loop.handle());
    let client = ClientFuture::new(stream, sender, io_loop.handle(), None);
    let secure_client = SecureClientHandle::new(client);

    test_secure_query_example(secure_client, io_loop);
  }

  #[cfg(test)]
  fn test_secure_query_example(client: SecureClientHandle, mut io_loop: Core) {
    let name = domain::Name::with_labels(vec!["www".to_string(), "example".to_string(), "com".to_string()]);
    let response = io_loop.run(client.query(name.clone(), DNSClass::IN, RecordType::A)).expect("query failed");

    println!("response records: {:?}", response);
    assert!(response.get_edns().expect("edns not here").is_dnssec_ok());

    let record = &response.get_answers()[0];
    assert_eq!(record.get_name(), &name);
    assert_eq!(record.get_rr_type(), RecordType::A);
    assert_eq!(record.get_dns_class(), DNSClass::IN);

    if let &RData::A(ref address) = record.get_rdata() {
      assert_eq!(address, &Ipv4Addr::new(93,184,216,34))
    } else {
      assert!(false);
    }
  }
}
