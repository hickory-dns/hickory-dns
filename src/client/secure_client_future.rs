// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::{HashMap, HashSet};
use std::collections::hash_set::Drain;
use std::sync::Arc;

use chrono::UTC;
use futures;
use futures::{Async, Complete, Future, Oneshot, Poll, task};
use futures::IntoFuture;
use futures::stream::{Peekable, Fuse as StreamFuse, Stream};
use futures::task::park;
use rand::Rng;
use rand;
use tokio_core::reactor::Handle;
use tokio_core::channel::{channel, Sender, Receiver};

use ::client::{BasicClientHandle, ClientHandle};
use ::error::*;
use ::rr::{domain, DNSClass, RData, Record, RecordType};
use ::rr::dnssec::Signer;
use ::rr::rdata::NULL;
use ::op::{Edns, Message, MessageType, OpCode, Query, UpdateMessage};
use ::udp::{UdpClientStream, UdpClientStreamHandle};
use ::rr::dnssec::TrustAnchor;
use ::tcp::{TcpClientStream, TcpClientStreamHandle};

pub struct SecureClientHandle {
  client: BasicClientHandle,
  trust_anchor: Arc<TrustAnchor>,
}

impl SecureClientHandle {
  pub fn new(client: BasicClientHandle) -> SecureClientHandle {
    Self::with_trust_anchor(client, TrustAnchor::default())
  }

  pub fn with_trust_anchor(client: BasicClientHandle, trust_anchor: TrustAnchor) -> SecureClientHandle {
    SecureClientHandle {
      client: client,
      trust_anchor: Arc::new(trust_anchor),
    }
  }
}

// let ds_response = try!(self.inner_query(&name, dnskey.get_dns_class(), RecordType::DS, true));
// let ds_rrset: Vec<&Record> = ds_response.get_answers().iter().filter(|rr| rr.get_rr_type() == RecordType::DS).collect();
// let ds_rrsigs: Vec<&Record> = ds_response.get_answers().iter().filter(|rr| rr.get_rr_type() == RecordType::RRSIG).collect();

impl ClientHandle for SecureClientHandle {
  fn send(&self, message: Message) -> Box<Future<Item=Message, Error=ClientError>> {
    self.client.send(message)
  }

  fn query(&self, name: domain::Name, query_class: DNSClass, query_type: RecordType, dnssec: bool)
    -> Box<Future<Item=Message, Error=ClientError>> {
    let client = self.client.clone();
    let trust_anchor = self.trust_anchor.clone();

    Box::new(self.client.query(name, query_class, query_type, true)
               .and_then(move |message_response|{
                 // group the record sets by name and type
                 //  each rrset type needs to validated independently

                 VerifyRrsetsFuture::new(
                   client,
                   trust_anchor,
                   message_response
                 )
               })
             )
  }
}

pub struct VerifyRrsetsFuture {
  client: BasicClientHandle,
  trust_anchor: Arc<TrustAnchor>,
  message_result: Message,
  rrset_types: Vec<(domain::Name, RecordType)>,
}

//unsafe impl Send for VerifyRrsetsFuture {}

impl VerifyRrsetsFuture {
  fn new(
    client: BasicClientHandle,
    trust_anchor: Arc<TrustAnchor>,
    message_result: Message,
  ) -> VerifyRrsetsFuture {
    let mut rrset_types: HashSet<(domain::Name, RecordType)> = HashSet::new();
    for rrset in message_result.get_answers()
                               .iter()
                               .chain(message_result.get_name_servers())
                               .filter(|rr| rr.get_rr_type() != RecordType::RRSIG)
                               .map(|rr| (rr.get_name().clone(), rr.get_rr_type())) {
      rrset_types.insert(rrset);
    }

    VerifyRrsetsFuture{
      client: client,
      trust_anchor: trust_anchor,
      message_result: message_result,
      rrset_types: rrset_types.into_iter().collect(),
    }
  }
}

impl Future for VerifyRrsetsFuture {
  type Item = Message;
  type Error = ClientError;

  fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
    // TODO: Can we do this in parallel?
    while let Some((name, record_type)) = self.rrset_types.pop() {
      let rrset: Vec<Record> = self.message_result.get_answers()
                                              .iter()
                                              .chain(self.message_result.get_name_servers())
                                              .filter(|rr| rr.get_rr_type() == record_type && rr.get_name() == &name)
                                              .cloned()
                                              .collect();
    }


    // FIXME: make message_result Option so that we can return and not clone.
    Ok(Async::Ready(self.message_result.clone()))
    // Err(ClientErrorKind::Message("unimplemented").into())
  }
}

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
    let response = io_loop.run(client.query(name.clone(), DNSClass::IN, RecordType::A, true)).expect("query failed");

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
