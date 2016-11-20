// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::SocketAddr;
use std::io;

use futures::{Async, Future, Poll};
use futures::stream::Stream;
use tokio_core::reactor::{Handle};

use ::BufClientStreamHandle;
use ::tcp::TcpStream;
use ::client::ClientStreamHandle;

#[must_use = "futures do nothing unless polled"]
pub struct TcpClientStream {
  tcp_stream: TcpStream,
}

impl TcpClientStream {
  /// it is expected that the resolver wrapper will be responsible for creating and managing
  ///  new TcpClients such that each new client would have a random port (reduce chance of cache
  ///  poisoning)
  pub fn new(name_server: SocketAddr, loop_handle: Handle) -> (Box<Future<Item=TcpClientStream, Error=io::Error>>, Box<ClientStreamHandle>) {
    let (stream_future, sender) = TcpStream::new(name_server, loop_handle);

    let new_future: Box<Future<Item=TcpClientStream, Error=io::Error>> =
      Box::new(stream_future.map(move |tcp_stream| {
        TcpClientStream {
          tcp_stream: tcp_stream,
        }
      }));

    let sender = Box::new(BufClientStreamHandle{ name_server: name_server, sender: sender });

    (new_future, sender)
  }
}

impl Stream for TcpClientStream {
  type Item = Vec<u8>;
  type Error = io::Error;

  fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
    match try_ready!(self.tcp_stream.poll()) {
      Some((buffer, src_addr)) => {
        // this is busted if the tcp connection doesn't have a peer
        let peer = try!(self.tcp_stream.peer_addr());
        if src_addr != peer {
          // FIXME: this should be an error...
          warn!("{} does not match name_server: {}", src_addr, peer)
        }

        Ok(Async::Ready(Some(buffer)))
      }
      None => Ok(Async::Ready(None)),
    }
  }
}



#[cfg(test)] use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
// this fails on linux for some reason. It appears that a buffer somewhere is dirty
//  and subsequent reads of a mesage buffer reads the wrong length. It works for 2 iterations
//  but not 3?
// #[cfg(not(target_os = "linux"))]
fn test_tcp_client_stream_ipv4() {
  tcp_client_stream_test(IpAddr::V4(Ipv4Addr::new(127,0,0,1)))
}

#[test]
#[cfg(not(target_os = "linux"))] // ignored until Travis-CI fixes IPv6
fn test_tcp_client_stream_ipv6() {
  tcp_client_stream_test(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
}

#[cfg(test)]
const TEST_BYTES: &'static [u8; 8] = b"DEADBEEF";
#[cfg(test)]
const TEST_BYTES_LEN: usize = 8;

#[cfg(test)]
fn tcp_client_stream_test(server_addr: IpAddr) {
  use std::io::{Read, Write};
  use tokio_core::reactor::Core;

  use std;
  let succeeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
  let succeeded_clone = succeeded.clone();
  std::thread::Builder::new().name("thread_killer".to_string()).spawn(move || {
    let succeeded = succeeded_clone.clone();
    for _ in 0..15 {
      std::thread::sleep(std::time::Duration::from_secs(1));
      if succeeded.load(std::sync::atomic::Ordering::Relaxed) { return }
    }

    panic!("timeout");
  }).unwrap();

  // TODO: need a timeout on listen
  let server = std::net::TcpListener::bind(SocketAddr::new(server_addr, 0)).unwrap();
  let server_addr = server.local_addr().unwrap();

  let send_recv_times = 4;

  // an in and out server
  let server_handle = std::thread::Builder::new().name("test_tcp_client_stream_ipv4:server".to_string()).spawn(move || {
    let (mut socket, _) = server.accept().expect("accept failed");

    socket.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap(); // should recieve something within 5 seconds...
    socket.set_write_timeout(Some(std::time::Duration::from_secs(5))).unwrap(); // should recieve something within 5 seconds...

    for _ in 0..send_recv_times {
      // wait for some bytes...
      let mut len_bytes = [0_u8; 2];
      socket.read_exact(&mut len_bytes).expect("SERVER: receive failed");
      let length = (len_bytes[0] as u16) << 8 & 0xFF00 | len_bytes[1] as u16 & 0x00FF;
      assert_eq!(length as usize, TEST_BYTES_LEN);

      let mut buffer = [0_u8; TEST_BYTES_LEN];
      socket.read_exact(&mut buffer).unwrap();

      // println!("read bytes iter: {}", i);
      assert_eq!(&buffer, TEST_BYTES);

      // bounce them right back...
      socket.write_all(&len_bytes).expect("SERVER: send length failed");
      socket.write_all(&buffer).expect("SERVER: send buffer failed");
      // println!("wrote bytes iter: {}", i);
      std::thread::yield_now();
    }
  }).unwrap();

  // setup the client, which is going to run on the testing thread...
  let mut io_loop = Core::new().unwrap();

  // the tests should run within 5 seconds... right?
  // TODO: add timeout here, so that test never hangs...
  // let timeout = Timeout::new(Duration::from_secs(5), &io_loop.handle());
  let (stream, sender) = TcpClientStream::new(server_addr, io_loop.handle());

  let mut stream: TcpClientStream = io_loop.run(stream).ok().expect("run failed to get stream");

  for _ in 0..send_recv_times {
    // test once
    sender.send(TEST_BYTES.to_vec()).expect("send failed");
    let (buffer, stream_tmp) = io_loop.run(stream.into_future()).ok().expect("future iteration run failed");
    stream = stream_tmp;
    let buffer = buffer.expect("no buffer received");
    assert_eq!(&buffer, TEST_BYTES);
  }

  succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
  server_handle.join().expect("server thread failed");
}
