// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashSet;
use std::collections::hash_set::Drain;
use std::rc::Rc;

use ::client::ClientHandle;

pub struct SecureClientHandle {
  client: ClientHandle,
  trust_anchor: Rc<TrustAnchor>,

}

// let ds_response = try!(self.inner_query(&name, dnskey.get_dns_class(), RecordType::DS, true));
// let ds_rrset: Vec<&Record> = ds_response.get_answers().iter().filter(|rr| rr.get_rr_type() == RecordType::DS).collect();
// let ds_rrsigs: Vec<&Record> = ds_response.get_answers().iter().filter(|rr| rr.get_rr_type() == RecordType::RRSIG).collect();

impl SecureClientHandle for ClientHandle {
  pub fn query(&self, name: &domain::Name, query_class: DNSClass, query_type: RecordType, dnssec: bool)
    -> Box<Future<Item=Message, Error=ClientError>> {
    self.client.query(name.clone(), query_class.clone(), query_type.clone(), true)
               .and_then(move |message_response|{
                 // group the record sets by name and type
                 //  each rrset type needs to validated independently



                 VerifyRrsetsFuture{ client: self.client.clone(),
                                     trust_anchor: Rc::new(self.trust_anchor),
                                     message_result: message_response,
                                     rrset_types: rrset_types.drain(),
                                   }.fold(Ok(message_response))
               })
  }
}

pub struct VerifyRrsetsFuture {
  client: ClientHandle,
  trust_anchor: Rc<TrustAnchor>,
  message_result: Message,
  rrset_types: Drain<(domain::Name, RecordType)>,
}

impl VerifyRrsetsFuture {
  fn new(
    client: ClientHandle,
    trust_anchor: Rc<TrustAnchor>,
    message_result: Message,
  ) -> Box<Future<Item=Message, Error=ClientError>> {
    let mut rrset_types: HashSet<(domain::Name, RecordType)> = HashSet::new();
    for rrset in message_response.get_answers()
                                 .iter()
                                 .chain(record_response.get_name_servers())
                                 .filter(|rr| rr.get_rr_type() != RecordType::RRSIG)
                                 .map(|rr| (rr.get_name().clone(), rr.get_rr_type())) {
      rrset_types.insert(rrset);
    }

    Box::new(
      VerifyRrsetsFuture{
        client: client,
        trust_anchor: trust_anchor,
        message_result: message_result,
        rrset_types: rrset_types.drain(),
      }
    )
  }
}

impl Future for VerifyRrsetsFuture {
  type Item = Message;
  type Error = ClientError;

  fn poll(&mut self) -> Poll<Option<Item>, Self::Error> {
    // Can we do this in parallel?
    while let Some((name, record_type)) = rrset_types.next() {
      let rrset: Vec<Record> = record_response.get_answers()
                                              .iter()
                                              .chain(record_response.get_name_servers())
                                              .filter(|rr| rr.get_rr_type() == record_type && rr.get_name() == &name)
                                              .cloned()
                                              .collect();
    }

    Async::Ready(self.message_result)
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
