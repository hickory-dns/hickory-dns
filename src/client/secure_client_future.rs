// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::{HashMap, HashSet};
use std::collections::hash_set::Drain;
use std::mem;
use std::sync::Arc;

use chrono::UTC;
use futures;
use futures::{Async, Complete, Future, Oneshot, Poll, task};
use futures::{collect, Collect, IntoFuture};
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

/// A ClientHandle which will return DNSSec validating futures.
#[derive(Clone)]
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

impl ClientHandle for SecureClientHandle {
  fn send(&self, mut message: Message) -> Box<Future<Item=Message, Error=ClientError>> {
    // dnssec only matters on queries.
    if let OpCode::Query = message.get_op_code() {
      let client: SecureClientHandle = self.clone();
      let trust_anchor = self.trust_anchor.clone();

      {
        let edns = message.get_edns_mut();
        edns.set_dnssec_ok(true);
      }

      message.authentic_data(true);
      message.checking_disabled(false);

      return Box::new(
        self.client.send(message)
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

    self.client.send(message)
  }
}

/// A future to verify all RRSets in a returned Message.
pub struct VerifyRrsetsFuture {
  client: SecureClientHandle,
  trust_anchor: Arc<TrustAnchor>,
  message_result: Option<Message>,
  rrsets: Collect<Vec<VerifyRrsetFuture>>,
}

impl VerifyRrsetsFuture {
  fn new(
    client: SecureClientHandle,
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

    // collect all the rrsets to verify
    // TODO: is there a way to get rid of this clone() safely?
    let mut rrsets = Vec::with_capacity(rrset_types.len());
    for (name, record_type) in rrset_types {
      let rrset: Vec<Record> = message_result.get_answers()
                                             .iter()
                                             .chain(message_result.get_name_servers())
                                             .filter(|rr| rr.get_rr_type() == record_type &&
                                                          rr.get_name() == &name)
                                             .cloned()
                                             .collect();

      rrsets.push(VerifyRrsetFuture{ name: name, record_type: record_type, rrset: rrset });
    }

    // spawn a select_all over this vec, these are the individual RRSet validators
    let rrsets_to_verify = collect(rrsets);

    // return the full Message validator
    VerifyRrsetsFuture{
      client: client,
      trust_anchor: trust_anchor,
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

/// A future for verifying a Rrset
struct VerifyRrsetFuture {
  name: domain::Name,
  record_type: RecordType,
  rrset: Vec<Record>,
}

impl Future for VerifyRrsetFuture {
  type Item = ();
  type Error = ClientError;

  fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
    Ok(Async::Ready(()))
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
