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
use ::rr::rdata::{dnskey, DNSKEY, DS, NULL};
use ::tcp::{TcpClientStream, TcpClientStreamHandle};
use ::udp::{UdpClientStream, UdpClientStreamHandle};
use ::serialize::binary::{BinEncoder, BinSerializable};

/// A ClientHandle which will return DNSSec validating futures.
pub struct SecureClientHandle {
  client: BasicClientHandle,
  trust_anchor: Rc<TrustAnchor>,
  request_depth: usize,
  active_validations: Rc<RefCell<HashSet<(domain::Name, RecordType, DNSClass)>>>,
}

impl SecureClientHandle {
  pub fn new(client: BasicClientHandle) -> SecureClientHandle {
    Self::with_trust_anchor(client, TrustAnchor::default())
  }

  pub fn with_trust_anchor(client: BasicClientHandle, trust_anchor: TrustAnchor) -> SecureClientHandle {
    SecureClientHandle {
      client: client,
      trust_anchor: Rc::new(trust_anchor),
      request_depth: 0,
      active_validations: Rc::new(RefCell::new(HashSet::new()))
    }
  }

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
  rrsets: Collect<Vec<Box<Future<Item=(), Error=ClientError>>>>,
}

impl VerifyRrsetsFuture {
  fn new(
    mut client: SecureClientHandle,
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
      rrsets.push(verify_rrset(client.clone_with_context(), name, record_type, dns_class, rrset, rrsigs));
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

fn verify_rrset(client: SecureClientHandle,
                name: domain::Name,
                record_type: RecordType,
                record_class: DNSClass,
                rrset: Vec<Record>,
                rrsigs: Vec<Record>,)
                -> Box<Future<Item=(), Error=ClientError>> {
  match record_type {
    RecordType::DNSKEY => verify_dnskey_rrset(client, name, record_type, record_class, rrset, rrsigs),
    RecordType::DS => verify_ds_rrset(client, name, record_type, record_class, rrset, rrsigs),
    _ => verify_default_rrset(client, name, record_type, record_class, rrset, rrsigs),
  }
}

fn verify_dnskey_rrset(
  client: SecureClientHandle,
  name: domain::Name,
  record_type: RecordType,
  record_class: DNSClass,
  rrset: Vec<Record>,
  rrsigs: Vec<Record>,)
  -> Box<Future<Item=(), Error=ClientError>>
{
  debug!("dnskey validation {}, record_type: {:?}", name, record_type);

  // check the DNSKEYS against the trust_anchor, if it's approved allow it.
  // FIXME: this requires all DNSKEYS in order to succeed, really, any one should be allowed, but
  //        only that one allowed for validating RRSETS.
  // TODO: filter only supported DNSKEY signature types.
  if rrset.iter()
          .filter(|rr| rr.get_rr_type() == RecordType::DNSKEY)
          .filter_map(|rr| if let &RData::DNSKEY(ref rdata) = rr.get_rdata() {
            Some(rdata)
          } else {
            None
          })
          .all(|rdata| client.trust_anchor.contains(rdata.get_public_key())) {
    return Box::new(finished(()))
  }

  // need to get DS records for each DNSKEY
  let valid_dnskey = client.query(name.clone(), record_class, RecordType::DS)
        .and_then(move |ds_message| {
          if rrset.iter()
                  .filter(|rr| rr.get_rr_type() == RecordType::DNSKEY)
                  .filter_map(|rr| if let &RData::DNSKEY(ref rdata) = rr.get_rdata() {
                    Some(rdata)
                  } else {
                    None
                  })
                  .all(|key_rdata|
                    ds_message.get_answers()
                              .iter()
                              .filter(|ds| ds.get_rr_type() == RecordType::DS)
                              .filter_map(|ds| if let &RData::DS(ref ds_rdata) = ds.get_rdata() {
                                Some(ds_rdata)
                              } else {
                                None
                              })
                              .any(|ds_rdata| is_key_covered_by(&name, key_rdata, ds_rdata))
                  ) {
            debug!("validated dnskey: {}", name);
            Ok(())
          } else {
            Err(ClientErrorKind::Message("Could not validate all DNSKEYs").into())
          }
        });

  Box::new(valid_dnskey)
}

fn is_key_covered_by(name: &domain::Name, key: &DNSKEY, ds: &DS) -> bool {
  // 5.1.4.  The Digest Field
  //
  //    The DS record refers to a DNSKEY RR by including a digest of that
  //    DNSKEY RR.
  //
  //    The digest is calculated by concatenating the canonical form of the
  //    fully qualified owner name of the DNSKEY RR with the DNSKEY RDATA,
  //    and then applying the digest algorithm.
  //
  //      digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
  //
  //       "|" denotes concatenation
  //
  //      DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.
  //
  //    The size of the digest may vary depending on the digest algorithm and
  //    DNSKEY RR size.  As of the time of this writing, the only defined
  //    digest algorithm is SHA-1, which produces a 20 octet digest.
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
  &hash as &[u8] == ds.get_digest()
}

fn verify_ds_rrset(
  client: SecureClientHandle,
  name: domain::Name,
  record_type: RecordType,
  record_class: DNSClass,
  rrset: Vec<Record>,
  rrsigs: Vec<Record>,)
  -> Box<Future<Item=(), Error=ClientError>>
{
  debug!("ds validation {}, record_type: {:?}", name, record_type);
  //Box::new(finished(()))
  Box::new(failed(ClientErrorKind::Message("DS unimplemented").into()))
}

fn verify_default_rrset(
  client: SecureClientHandle,
  name: domain::Name,
  record_type: RecordType,
  record_class: DNSClass,
  rrset: Vec<Record>,
  rrsigs: Vec<Record>,)
  -> Box<Future<Item=(), Error=ClientError>>
{
  debug!("default validation {}, record_type: {:?}", name, record_type);
  // we can validate with any of the rrsigs...
  //  i.e. the first that validates is good enough
  //  FIXME: could there be a cert downgrade attack here?
  //         we could check for the strongest RRSIG and only use that...
  //         though, since the entire package isn't signed any RRSIG could have been injected,
  //         right? meaning if there is an attack on any of the acceptable algorithms, we'd be
  //         succeptable until that algorithm is removed as an option.
  //  TODO: strip RRSIGS to accepted algorithms and make algorithms configurable.
  let select = select_any(rrsigs.into_iter().map(|rrsig| {
    if let &RData::SIG(ref sig) = rrsig.get_rdata() {
      // FIXME: split DNSKEY evaluation, such that bad DNSKEYS can be ignored, and others used
      client.query(sig.get_signer_name().clone(), record_class, RecordType::DNSKEY)
            .and_then(|message| failed::<Message, _>(ClientErrorKind::Message("RRSIG unimplemented").into()))
    } else {
      panic!("programmer error, only RRSIG expected here");
    }
  }))
  // getting here means at least one of the rrsigs succeeded...
  .map(|(_,_)| ());
  //.map_err(|e| e);
  //.and_then(|_| failed::<(), _>(ClientErrorKind::Message("RRSIG validation unimplemented").into()));

  Box::new(select)
}

// /// A future for verifying a Rrset
// struct VerifyRrsetSelect {
//   select: SelectAll<Box<Future<Item=(), Error=ClientError>>>
// }
//
// impl Future for VerifyRrsetSelect {
//   type Item = ();
//   type Error = ClientError;
//
//   fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
//     match self.select.poll() {
//       Ok(Async::NotReady) => Ok(Async::NotReady),
//       Ok(Async::Ready((_,_,_))) => Ok(Async::Ready(())),
//       Err((_,_, left)) => {
//         if left.is_empty() { return Err(ClientErrorKind::Message("All RRSIGS failed to validate").into()) }
//
//         debug!("did not validate an RRSIG, will try others");
//         // select all on the next batch
//         mem::replace(&mut self.select, select_all(left));
//         Ok(Async::NotReady)
//       }
//     }
//   }
// }

// pub struct VerifyRrsigFuture {
//   client: ClientHandle,
//   trust_anchor: Rc<TrustAnchor>,
//
//   result: Message,
//   toProveStack: Box<SecureClientFuture>,
// }
//
// impl Future for VerifyRrsigFuture {
//   type Item = Message;
//   type Error = ClientError;
//
//   fn poll(&mut self) -> Poll<Item, Self::Error> {
//     Async::Ready(self.result)
//   }
// }
//
// pub struct VerifyDnsKeyFuture {
//   client: ClientHandle,
//   trust_anchor: TrustAnchor,
//
//   result: Message,
//   toProveStack: Box<SecureClientFuture>,
// }
//
// impl Future for VerifyDnsKeyFuture {
//   type Item = Message;
//   type Error = ClientError;
//
//   fn poll(&mut self) -> Poll<Item, Self::Error> {
//     Async::Ready(self.result)
//   }
// }
//
// pub struct VerifyNsecRrsetsFuture {
//   client: ClientHandle,
//   trust_anchor: AsRef<TrustAnchor>,
//   message_result: Message,
//   rrset_types: HashSet<(domain::Name, RecordType)>,
// }
//
// impl Future for VerifyNsecRrsetsFuture {
//   type Item = Message;
//   type Error = ClientError;
//
//   fn poll(&mut self) -> Poll<Item, Self::Error> {
//     Async::Ready(self.result)
//   }
// }
//
//
// pub struct VerifyNsecFuture {
//
// }
//
// impl Future for VerifyNsecFuture {
//   type Item = Message;
//   type Error = ClientError;
//
//   fn poll(&mut self) -> Poll<Item, Self::Error> {
//     Async::Ready(self.result)
//   }
// }


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
