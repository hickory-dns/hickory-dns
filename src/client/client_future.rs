// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashMap;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::fmt;
use std::io;

use futures;
use futures::{Async, BoxFuture, Complete, Future, Map, Oneshot, Poll};
use futures::stream::{Fuse, Stream};
use rand::Rng;
use rand;
use tokio_core;
use tokio_core::{Loop, LoopHandle, Sender, Receiver};
use tokio_core::io::IoFuture;

use ::error::*;
use ::rr::{DNSClass, RecordType, Record, RData};
use ::rr::rdata::NULL;
use ::rr::domain;
use ::rr::dnssec::{Signer, TrustAnchor};
use ::op::{Message, MessageType, OpCode, Query, Edns, ResponseCode, UpdateMessage };
use ::serialize::binary::*;
use ::udp::UdpClient;

pub struct Client {
  udp_client: UdpClient,
  message_sender: Sender<Message>,
  new_receiver: Fuse<Receiver<(Message, Complete<ClientResult<Message>>)>>,
  new_message: Option<(Message, Complete<ClientResult<Message>>)>,
  active_requests: HashMap<u16, Complete<ClientResult<Message>>>,
}

impl Client {
  /// loop over active_requests and remove cancelled requests
  ///  this should free up space if we already had 4096 active requests
  fn drop_cancelled(&mut self) {
    // TODO: should we have a timeout here? or always expect the caller to do this?
    let mut canceled = Vec::new();
    for (&id, req) in self.active_requests.iter_mut() {
      if let Ok(Async::Ready(())) = req.poll_cancel() {
        canceled.push(id);
      }
    }

    // drop all the canceled requests
    for id in canceled {
      self.active_requests.remove(&id);
    }
  }

  /// creates random query_id, validates against all active queries
  fn next_random_query_id(&self) -> Async<u16> {
    let mut rand = rand::thread_rng();

    for attempt in 0..100 {
      let id = rand.gen_range(0_u16, u16::max_value());

      if !self.active_requests.contains_key(&id) {
        return Async::Ready(id)
      }
    }

    warn!("could not get next random query id, delaying");
    Async::NotReady
  }

  fn send(&self, message: Message) -> io::Result<Oneshot<Message>> {
    let (complete, oneshot) = futures::oneshot();
    try!(self.message_sender.send(message));
    Ok(oneshot)
  }
}

impl Future for Client {
  type Item = ();
  type Error = ClientError;

  fn poll(&mut self) -> Poll<(), Self::Error> {
    self.drop_cancelled();

    // loop over new_receiver for all outbound requests
    loop {
      // find a new message, need to split here for mutex reference restricion
      let query_id = if self.new_message.is_some() {
        match self.next_random_query_id() {
          Async::Ready(id) => Some(id),
          Async::NotReady => return Ok(Async::NotReady),
        }
      } else {
        None
      };

      // if there was a new message, send it.
      let activated: Result<(), ClientError> = if let Some((ref mut message, _)) = self.new_message {
        // getting a random query id, this mitigates potential cache poisoning.
        // FIXME: for SIG0 we can't change the message id after signing.
        message.id(query_id.expect("error, query_id should be available from above"));

        match message.to_vec() {
          Ok(buffer) => {
            try!(self.udp_client.send(buffer));
            Ok(())
          },
          Err(err) => {
            Err(err.into())
          },
        }
      } else {
        Ok(())
      };

      // getting here means that the message was sent or atleast processed to an error
      if let Some((message, complete)) = self.new_message.take() {
        match activated {
          Ok(_) => {
            // add to the map -after- the client send b/c we don't want to put it in the map if
            //  we ended up returning from that send.
            self.active_requests.insert(message.get_id(), complete);
          },
          Err(e) => {
            // we don't add to the active_requests map because we failed to send/encode the message
            complete.complete(Err(e))
          },
        }
      }

      //   poll the reciever
      match try!(self.new_receiver.poll()) {
        Async::Ready(Some(message)) => self.new_message = Some(message),
        Async::Ready(None) | Async::NotReady => break,
      }
    }

    // Collect all inbound requests, max 100 at a time for QoS
    //   by having a max we will guarantee that the client can't be DOSed in this loop
    for _ in 0..100 {
      match try!(self.udp_client.poll()) {
        Async::Ready(Some(buffer)) => {
          //   deserialize or log decode_error
          match Message::from_vec(&buffer) {
            Ok(message) => {
              match self.active_requests.remove(&message.get_id()) {
                Some(complete) => complete.complete(Ok(message)),
                None => debug!("unexpected request_id: {}", message.get_id()),
              }
            },
            // TODO: return src address for diagnostics
            Err(e) => debug!("error decoding message: {}", e),
          }
        },
        Async::Ready(None) | Async::NotReady => break,
      }
    }

    // if there are no active requests, we are done...
    if self.active_requests.len() > 0 {
      return Ok(Async::NotReady)
    } else {
      return Ok(Async::Ready(()))
    }
  }
}
