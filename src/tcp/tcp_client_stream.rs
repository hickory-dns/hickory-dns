// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::io;
use std::io::Read;

use futures::{AndThen, Async, BoxFuture, Flatten, Future, Poll};
use futures::stream::{Fuse, Peekable, Stream};
use futures::task::park;
use rand::Rng;
use rand;
use tokio_core;
use tokio_core::net::TcpStream as TokioTcpStream;
use tokio_core::channel::{channel, Sender, Receiver};
use tokio_core::io::{read_exact, ReadExact, write_all, WriteAll};
use tokio_core::reactor::{Handle};

pub type TcpClientStreamHandle = Sender<Vec<u8>>;

enum TcpState {
  LenBytes{ pos: usize, bytes: [u8; 2] },
  Bytes{ pos: usize, bytes: Vec<u8> },
}

pub struct TcpClientStream {
  name_server: SocketAddr,
  socket: TokioTcpStream,
  outbound_messages: Peekable<Fuse<Receiver<Vec<u8>>>>,
  // TODO: would be nice to not use box, this would be close to the field without that:
  // sending: Option<AndThen<WriteAll<TokioTcpStream, [u8; 2]>,
  //                         WriteAll<TokioTcpStream, Vec<u8>>,
  //                         (Fn( (TokioTcpStream, Vec<u8>) ) -> WriteAll<TokioTcpStream, Vec<u8>> ) >>,
  // sending: Option<BoxFuture<(TokioTcpStream, Vec<u8>), io::Error>>,
  // receiving: Option<BoxFuture<, io::Error>>,
  state: TcpState,
}

impl TcpClientStream {
  /// it is expected that the resolver wrapper will be responsible for creating and managing
  ///  new TcpClients such that each new client would have a random port (reduce chance of cache
  ///  poisoning)
  pub fn new(name_server: SocketAddr, loop_handle: Handle) -> (Box<Future<Item=TcpClientStream, Error=io::Error>>, TcpClientStreamHandle) {
    let (message_sender, outbound_messages) = channel(&loop_handle).expect("somethings wrong with the event loop");
    let tcp = TokioTcpStream::connect(&name_server, &loop_handle);

    // This set of futures collapses the next tcp socket into a stream which can be used for
    //  sending and receiving tcp packets.
    let stream: Box<Future<Item=TcpClientStream, Error=io::Error>> = Box::new(tcp
      .map(move |tcp_stream| {
        TcpClientStream {
          name_server: name_server,
          socket: tcp_stream,
          outbound_messages: outbound_messages.fuse().peekable(),
          // sending: None,
          // receiving: None,
          state: TcpState::LenBytes { pos: 0, bytes: [0u8; 2] },
        }
      }));

    (stream, message_sender)
  }
}

impl Stream for TcpClientStream {
  type Item = Vec<u8>;
  type Error = io::Error;

  fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
    debug!("being polled");

    // this will not accept incoming data while there is data to send
    //  makes this self throttling.
    // TODO: it might be interesting to try and split the sending and receiving futures.
    loop {
      // then see if there is more to send
      match try!(self.outbound_messages.poll()) {
        // already handled above, here to make sure the poll() pops the next message
        Async::Ready(Some(buffer)) => {
          // will return if the socket will block
          debug!("received buffer, sending");

          // the length is 16 bits
          let len: [u8; 2] = [(buffer.len() >> 8 & 0xFF) as u8,
                              (buffer.len() & 0xFF) as u8];

          let mut sending = write_all(&self.socket, len)
                        .and_then(|(socket, _)| write_all(socket, buffer));

          // loop through the sending of the message
          // TODO: timeout here?
          loop {
            match sending.poll() {
              // message was sent
              Ok(Async::Ready((_, _))) => { debug!("sent"); break },
              // return an error
              Err(e) => return Err(e),
              // yield and loop until everything sent (no other progress will be made)
              Ok(Async::NotReady) => { debug!("not fully sent"); park().unpark() },
            }
          }
        },
        // now we get to drop through to the receives...
        // TODO: should we also return None if there are no more messages to send?
        Async::NotReady | Async::Ready(None) => { debug!("no messages to send"); break},
      }
    }

    debug!("continuing");
    let mut ret_buf: Option<Vec<u8>> = None;

    // this will loop while there is data to read, or the data has been read, or an IO
    //  event would block
    while ret_buf.is_none() {
      self.state = match mem::replace(&mut self.state,
                                      TcpState::LenBytes{ pos: 0, bytes: [0u8; 2] }) {
        TcpState::LenBytes { mut pos, mut bytes } => {
          debug!("reading length {}", bytes.len());
          let read = try_nb!(self.socket.read(&mut bytes[pos..]));
          pos += read;

          if pos < bytes.len() {
            TcpState::LenBytes { pos: pos, bytes: bytes }
          } else {
            let length = (bytes[0] as u16) << 8 & 0xFF00 | bytes[1] as u16 & 0x00FF;
            let mut bytes = Vec::with_capacity(length as usize);
            bytes.resize(length as usize, 0);

            TcpState::Bytes{ pos: 0, bytes: bytes }
          }
        },
        TcpState::Bytes { mut pos, mut bytes } => {
          debug!("reading bytes {}", bytes.len());
          let read = try_nb!(self.socket.read(&mut bytes[pos..]));
          pos += read;

          if pos < bytes.len() {
            TcpState::Bytes { pos: pos, bytes: bytes }
          } else {
            ret_buf = Some(bytes);
            TcpState::LenBytes{ pos: 0, bytes: [0u8; 2] }
          }
        },
      };
    }

    // if the buffer is ready, return it, if not we're NotReady
    if let Some(buffer) = ret_buf {
      debug!("returning buffer");
      return Ok(Async::Ready(Some(buffer)))
    } else {
      debug!("bottomed out");
      // at a minimum the outbound_messages should have been polled,
      //  which will wake this future up later...
      return Ok(Async::NotReady)
    }
  }
}

#[test]
fn test_tcp_client_stream_ipv4() {
  tcp_client_stream_test(IpAddr::V4(Ipv4Addr::new(127,0,0,1)))
}

#[test]
fn test_tcp_client_stream_ipv6() {
  tcp_client_stream_test(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
}

#[cfg(test)]
const test_bytes: &'static [u8; 8] = b"DEADBEEF";
#[cfg(test)]
const test_bytes_len: usize = 8;

#[cfg(test)]
fn tcp_client_stream_test(server_addr: IpAddr) {
  use std::time::Duration;
  use std::thread;
  use std::io::{Read, Write};

  use tokio_core::reactor::Core;

  use log::LogLevel;
  use ::logger::TrustDnsLogger;

  TrustDnsLogger::enable_logging(LogLevel::Debug);

  // TODO: need a timeout on listen
  let server = std::net::TcpListener::bind(SocketAddr::new(server_addr, 0)).unwrap();
  let server_addr = server.local_addr().unwrap();

  let send_recv_times = 3;

  // an in and out server
  let server_handle = thread::Builder::new().name("test_tcp_client_stream_ipv4:server".to_string()).spawn(move || {
    println!("TEST: waiting for connection: {}", server_addr);
    let (mut socket, addr) = server.accept().expect("accept failed");
    println!("TEST: accepted socket: {}", addr);

    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap(); // should recieve something within 5 seconds...
    socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap(); // should recieve something within 5 seconds...

    for i in 0..send_recv_times {
      // wait for some bytes...
      // println!("reading length iter: {}", i);

      // if i > 0 {
      //   thread::sleep(Duration::from_millis(5));
      //   std::process::exit(-1)
      // }

      let mut len_bytes = [0_u8; 2];
      socket.read_exact(&mut len_bytes).expect("SERVER: receive failed");
      let length = (len_bytes[0] as u16) << 8 & 0xFF00 | len_bytes[1] as u16 & 0x00FF;
      assert_eq!(length as usize, test_bytes_len);

      let mut buffer = [0_u8; test_bytes_len];
      socket.read_exact(&mut buffer);

      // println!("read bytes iter: {}", i);
      assert_eq!(&buffer, test_bytes);

      // bounce them right back...
      socket.write_all(&len_bytes).expect("SERVER: send length failed");
      socket.write_all(&buffer).expect("SERVER: send buffer failed");
      // println!("wrote bytes iter: {}", i);
      thread::yield_now();
    }
  }).unwrap();

  // setup the client, which is going to run on the testing thread...
  let mut io_loop = Core::new().unwrap();

  // the tests should run within 5 seconds... right?
  // TODO: add timeout here, so that test never hangs...
  // let timeout = Timeout::new(Duration::from_secs(5), &io_loop.handle());
  let (stream, sender) = TcpClientStream::new(server_addr, io_loop.handle());

  println!("TEST: establishing connection");
  let mut stream: TcpClientStream = io_loop.run(stream).ok().expect("run failed to get stream");

  println!("TEST: starting loop");

  for i in 0..send_recv_times {
    // test once
    println!("TEST: sending iter: {}", i);
    sender.send(test_bytes.to_vec()).expect("send failed");
    let (buffer, stream_tmp) = io_loop.run(stream.into_future()).ok().expect("future iteration run failed");
    stream = stream_tmp;
    let buffer = buffer.expect("no buffer received");
    println!("TEST: received iter: {} length: {}", i, buffer.len());
    assert_eq!(&buffer, test_bytes);
  }

  server_handle.join().expect("server thread failed");
}
