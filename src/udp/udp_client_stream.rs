use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::fmt;
use std::io;

use futures::Poll;
use futures::stream::{Fuse, Stream};
use rand::Rng;
use rand;
use tokio_core;
use tokio_core::{Loop, LoopHandle, Sender, Receiver};
use tokio_core::io::IoFuture;

use ::error::*;
use client::ClientConnection;

pub struct UdpClient {
  name_server: SocketAddr,
  socket: tokio_core::UdpSocket,
  outbound_messages: Fuse<Receiver<Vec<u8>>>,
}

lazy_static!{
  static ref IPV4_ZERO: Ipv4Addr = Ipv4Addr::new(0,0,0,0);
  static ref IPV6_ZERO: Ipv6Addr = Ipv6Addr::new(0,0,0,0,0,0,0,0);
}

impl UdpClient {

  /// it is expected that the resolver wrapper will be responsible for creating and managing
  ///  new UdpClients such that each new client would have a random port (reduce chance of
  ///  poisoning)
  pub fn new(name_server: SocketAddr, loop_handle: LoopHandle) -> ClientResult<Sender<Vec<u8>>> {
    // TODO: allow the bind address to be specified...
    let socket = try!(Self::next_bound_local_address(&name_server));
    let socket: IoFuture<tokio_core::UdpSocket> = tokio_core::UdpSocket::from_socket(socket, loop_handle);

    let (message_sender, outbound_messages): (_, IoFuture<Receiver<Vec<u8>>>) = loop_handle.channel();

    socket.join(outbound_messages).and_then(move |(socket, rx)| {
      UdpClient {
        name_server: name_server,
        socket: socket,
        outbound_messages: rx.fuse(),
      }
    }).forget();

    Ok(message_sender)
  }

  fn next_bound_local_address(name_server: &SocketAddr) -> ClientResult<UdpSocket> {
    let zero_addr: IpAddr = match *name_server {
      SocketAddr::V4(..) => IpAddr::V4(*IPV4_ZERO),
      SocketAddr::V6(..) => IpAddr::V6(*IPV6_ZERO),
    };

    let mut rand = rand::thread_rng();

    // TODO: this value might be too low...
    let mut error = Err(ClientErrorKind::Message("no available port, tried 10 times").into());
    for attempt in 0..10 {
      let zero_addr = SocketAddr::new(zero_addr, rand.gen_range(1025_u16, u16::max_value()));

      match UdpSocket::bind(&zero_addr) {
        Ok(socket) => return Ok(socket),
        Err(err) => debug!("unable to bind port, attempt: {}: {}", attempt, err),
      }
    }

    error
  }
}

impl Stream for UdpClient {
  type Item = Vec<u8>;
  type Error = io::Error;

  fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
    // this will not accept incoming data while there is data to send
    //  makes this self throttling.
    loop {
      match self.outbound_messages.poll() {
        Poll::Ok(Some(ref buffer)) => {
          match self.socket.poll_write() {
            Poll::NotReady => return Poll::NotReady,
            Poll::Err(err) => return Poll::Err(err),
            Poll::Ok(_) => {
              try_nb!(self.socket.send_to(buffer, &self.name_server));
            },
          }
        },
        Poll::Err(err) => return Poll::Err(err),
        Poll::Ok(None) | Poll::NotReady => break,
      }
    }

    // For QoS, this will only accept one message and output that to the sender.
    // recieve all inbound messages

    // TODO: this should match edns settings
    let mut buf = [0u8; 2048];

    // TODO: should we drop this packet if it's not from the same src as dest?
    let (len, src) = try_nb!(self.socket.recv_from(&mut buf));
    if src != self.name_server {
      debug!("{} does not match name_server: {}", src, self.name_server)
    }

    if len > 0 {
      Poll::Ok(Some(buf.to_vec()))
    } else {
      Poll::Ok(None)
    }
  }
}
