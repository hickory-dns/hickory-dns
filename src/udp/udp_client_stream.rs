// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::io;

use futures::{Async, Future, Poll};
use futures::stream::{Fuse, Peekable, Stream};
use futures::task::park;
use rand::Rng;
use rand;
use tokio_core;
use tokio_core::channel::{channel, Sender, Receiver};
use tokio_core::reactor::{Handle};

pub type UdpClientStreamHandle = Sender<Vec<u8>>;

pub struct UdpClientStream {
  // TODO: this shouldn't be stored, it's only necessary for the client to setup Ipv4 or Ipv6
  //   binding
  // destination address for all requests
  name_server: SocketAddr,
  //
  socket: tokio_core::net::UdpSocket,
  outbound_messages: Peekable<Fuse<Receiver<Vec<u8>>>>,
}

lazy_static!{
  static ref IPV4_ZERO: Ipv4Addr = Ipv4Addr::new(0,0,0,0);
  static ref IPV6_ZERO: Ipv6Addr = Ipv6Addr::new(0,0,0,0,0,0,0,0);
}

impl UdpClientStream {
  /// it is expected that the resolver wrapper will be responsible for creating and managing
  ///  new UdpClients such that each new client would have a random port (reduce chance of cache
  ///  poisoning)
  pub fn new(name_server: SocketAddr, loop_handle: Handle) -> (Box<Future<Item=UdpClientStream, Error=io::Error>>, UdpClientStreamHandle) {
    let (message_sender, outbound_messages) = channel(&loop_handle).expect("somethings wrong with the event loop");

    // TODO: allow the bind address to be specified...
    // constructs a future for getting the next randomly bound port to a UdpSocket
    let next_socket = Self::next_bound_local_address(&name_server);

    // This set of futures collapses the next udp socket into a stream which can be used for
    //  sending and receiving udp packets.
    let stream: Box<Future<Item=UdpClientStream, Error=io::Error>> = Box::new(next_socket
      .map(move |socket| { tokio_core::net::UdpSocket::from_socket(socket, &loop_handle).expect("something wrong with the handle?") })
      .map(move |socket| {
        UdpClientStream {
          name_server: name_server,
          socket: socket,
          outbound_messages: outbound_messages.fuse().peekable(),
        }
      }));

    (stream, message_sender)
  }

  /// Creates a future for randomly binding to a local socket address for client connections.
  fn next_bound_local_address(name_server: &SocketAddr) -> NextRandomUdpSocket {
    let zero_addr: IpAddr = match *name_server {
      SocketAddr::V4(..) => IpAddr::V4(*IPV4_ZERO),
      SocketAddr::V6(..) => IpAddr::V6(*IPV6_ZERO),
    };

    NextRandomUdpSocket{ bind_address: zero_addr }
  }
}

impl Stream for UdpClientStream {
  type Item = Vec<u8>;
  type Error = io::Error;

  fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
    // this will not accept incoming data while there is data to send
    //  makes this self throttling.
    loop {
      // first try to send
      match try!(self.outbound_messages.peek()) {
        Async::Ready(Some(buffer)) => {
          match self.socket.poll_write() {
            Async::NotReady => {
              return Ok(Async::NotReady)
            },
            Async::Ready(_) => {
              // will return if the socket will block
              try_nb!(self.socket.send_to(buffer, &self.name_server));
            },
          }
        },
        // all others will drop through to the poll()
        _ => (),
      }

      // now pop the request and check if we should break or continue.
      match try!(self.outbound_messages.poll()) {
        // already handled above, here to make sure the poll() pops the next message
        Async::Ready(Some(_)) => (),
        // now we get to drop through to the receives...
        // TODO: should we also return None if there are no more messages to send?
        Async::NotReady | Async::Ready(None) => break,
      }
    }

    // For QoS, this will only accept one message and output that
    // recieve all inbound messages

    // TODO: this should match edns settings
    let mut buf = [0u8; 2048];

    // TODO: should we drop this packet if it's not from the same src as dest?
    let (len, src) = try_nb!(self.socket.recv_from(&mut buf));
    if src != self.name_server {
      debug!("{} does not match name_server: {}", src, self.name_server)
    }

    Ok(Async::Ready(Some(buf.iter().take(len).cloned().collect())))
  }
}

struct NextRandomUdpSocket {
  bind_address: IpAddr,
}

impl Future for NextRandomUdpSocket {
  type Item = std::net::UdpSocket;
  type Error = io::Error;

  /// polls until there is an available next random UDP port.
  ///
  /// if there is no port available after 10 attempts, returns NotReady
  fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
    let mut rand = rand::thread_rng();

    for attempt in 0..10 {
      let zero_addr = SocketAddr::new(self.bind_address, rand.gen_range(1025_u16, u16::max_value()));

      match std::net::UdpSocket::bind(&zero_addr) {
        Ok(socket) => {
          return Ok(Async::Ready(socket))
        },
        Err(err) => debug!("unable to bind port, attempt: {}: {}", attempt, err),
      }
    }

    warn!("could not get next random port, delaying");

    park().unpark();
    // returning NotReady here, perhaps the next poll there will be some more socket available.
    Ok(Async::NotReady)
  }
}

#[test]
fn test_udp_client_stream_ipv4() {
  udp_client_stream_test(IpAddr::V4(Ipv4Addr::new(127,0,0,1)))
}

#[test]
#[cfg(not(target_os = "linux"))] // ignored until Travis-CI fixes IPv6
fn test_udp_client_stream_ipv6() {
  udp_client_stream_test(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
}

#[cfg(test)]
fn udp_client_stream_test(server_addr: IpAddr) {
  use std::time::Duration;
  use std::thread;

  use tokio_core::reactor::Core;

  use log::LogLevel;
  use ::logger::TrustDnsLogger;
  use std::sync::Arc;
  use std::sync::atomic::{AtomicBool,Ordering};

  TrustDnsLogger::enable_logging(LogLevel::Debug);

  let mut succeeded = Arc::new(AtomicBool::new(false));
  let succeeded_clone = succeeded.clone();
  let test_killer = thread::Builder::new().name("thread_killer".to_string()).spawn(move || {
    let succeeded = succeeded_clone.clone();
    for _ in 0..15 {
      thread::sleep(Duration::from_secs(1));
      if succeeded.load(Ordering::Relaxed) { return }
    }

    println!("timeout");
    std::process::exit(-1)
  });

  let server = std::net::UdpSocket::bind(SocketAddr::new(server_addr, 0)).unwrap();
  server.set_read_timeout(Some(Duration::from_secs(5))).unwrap(); // should recieve something within 5 seconds...
  server.set_write_timeout(Some(Duration::from_secs(5))).unwrap(); // should recieve something within 5 seconds...
  let server_addr = server.local_addr().unwrap();

  let test_bytes: &'static [u8; 8] = b"DEADBEEF";
  let send_recv_times = 4;

  // an in and out server
  let server_handle = thread::Builder::new().name("test_udp_client_stream_ipv4:server".to_string()).spawn(move || {
    let mut buffer = [0_u8; 512];

    for _ in 0..send_recv_times {
      // wait for some bytes...
      let (len, addr) = server.recv_from(&mut buffer).expect("receive failed");

      assert_eq!(&buffer[0..len], test_bytes);

      // bounce them right back...
      assert_eq!(server.send_to(&buffer[0..len], addr).expect("send failed"), len);
    }
  }).unwrap();

  // setup the client, which is going to run on the testing thread...
  let mut io_loop = Core::new().unwrap();

  // the tests should run within 5 seconds... right?
  // TODO: add timeout here, so that test never hangs...
  // let timeout = Timeout::new(Duration::from_secs(5), &io_loop.handle());
  let (stream, sender) = UdpClientStream::new(server_addr, io_loop.handle());
  let mut stream: UdpClientStream = io_loop.run(stream).ok().unwrap();

  for _ in 0..send_recv_times {
    // test once
    sender.send(test_bytes.to_vec()).unwrap();
    let (buffer, stream_tmp) = io_loop.run(stream.into_future()).ok().unwrap();
    stream = stream_tmp;
    assert_eq!(&buffer.expect("no buffer received"), test_bytes);
  }

  server_handle.join().expect("server thread failed");
}
