// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::mem;
use std::net::SocketAddr;
use std::io;
use std::io::{Read, Write};

use futures::{Async, Future, Poll};
use futures::stream::{Fuse, Peekable, Stream};
use tokio_core::net::TcpStream as TokioTcpStream;
use tokio_core::channel::{channel, Sender, Receiver};
use tokio_core::reactor::{Handle};

pub type TcpClientStreamHandle = Sender<Vec<u8>>;

enum WriteTcpState {
  LenBytes{ pos: usize, length: [u8; 2], bytes: Vec<u8> },
  Bytes{ pos: usize, bytes: Vec<u8> },
}

enum ReadTcpState {
  LenBytes{ pos: usize, bytes: [u8; 2] },
  Bytes{ pos: usize, bytes: Vec<u8> },
}

#[must_use = "futures do nothing unless polled"]
pub struct TcpClientStream {
  socket: TokioTcpStream,
  outbound_messages: Peekable<Fuse<Receiver<Vec<u8>>>>,
  send_state: Option<WriteTcpState>,
  read_state: ReadTcpState,
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
          socket: tcp_stream,
          outbound_messages: outbound_messages.fuse().peekable(),
          send_state: None,
          read_state: ReadTcpState::LenBytes { pos: 0, bytes: [0u8; 2] },
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
      // in the case we are sending, send it all?
      if self.send_state.is_some() {
        // sending...
        match self.send_state {
          Some(WriteTcpState::LenBytes{ ref mut pos, ref length, .. }) => {
            let wrote = try_nb!(self.socket.write(&length[*pos..]));
            *pos += wrote;
          },
          Some(WriteTcpState::Bytes{ ref mut pos, ref bytes }) => {
            let wrote = try_nb!(self.socket.write(&bytes[*pos..]));
            *pos += wrote;
          },
          _ => (),
        }

        // get current state
        let current_state = mem::replace(&mut self.send_state, None);

        // switch states
        match current_state {
          Some(WriteTcpState::LenBytes{ pos, length, bytes }) => {
            if pos < length.len() {
              mem::replace(&mut self.send_state, Some(WriteTcpState::LenBytes{ pos: pos, length: length, bytes: bytes }));
            } else{
              mem::replace(&mut self.send_state, Some(WriteTcpState::Bytes{ pos: 0, bytes: bytes }));
            }
          },
          Some(WriteTcpState::Bytes{ pos, bytes }) => {
            if pos < bytes.len() {
              mem::replace(&mut self.send_state, Some(WriteTcpState::Bytes{ pos: pos, bytes: bytes }));
            } else {
              mem::replace(&mut self.send_state, None);
            }
          },
          None => (),
        };
      } else {
        // then see if there is more to send
        match try!(self.outbound_messages.poll()) {
          // already handled above, here to make sure the poll() pops the next message
          Async::Ready(Some(buffer)) => {
            // will return if the socket will block
            debug!("received buffer, sending");

            // the length is 16 bits
            let len: [u8; 2] = [(buffer.len() >> 8 & 0xFF) as u8,
                                (buffer.len() & 0xFF) as u8];

            self.send_state = Some(WriteTcpState::LenBytes{ pos: 0, length: len, bytes: buffer });
          },
          // now we get to drop through to the receives...
          // TODO: should we also return None if there are no more messages to send?
          Async::NotReady | Async::Ready(None) => { debug!("no messages to send"); break },
        }
      }
    }

    debug!("continuing to read");
    let mut ret_buf: Option<Vec<u8>> = None;

    // this will loop while there is data to read, or the data has been read, or an IO
    //  event would block
    while ret_buf.is_none() {
      // Evaluates the next state. If None is the result, then no state change occurs,
      //  if Some(_) is returned, then that will be used as the next state.
      let new_state: Option<ReadTcpState> = match self.read_state {
        ReadTcpState::LenBytes { ref mut pos, ref mut bytes } => {
          debug!("in ReadTcpState::LenBytes: {}", pos);

          // debug!("reading length {}", bytes.len());
          let read = try_nb!(self.socket.read(&mut bytes[*pos..]));
          *pos += read;

          if *pos < bytes.len() {
            debug!("remain ReadTcpState::LenBytes: {}", pos);
            None
          } else {
            let length = (bytes[0] as u16) << 8 & 0xFF00 | bytes[1] as u16 & 0x00FF;
            debug!("got length: {}", length);
            let mut bytes = Vec::with_capacity(length as usize);
            bytes.resize(length as usize, 0);

            debug!("move ReadTcpState::Bytes: {}", bytes.len());
            Some(ReadTcpState::Bytes{ pos: 0, bytes: bytes })
          }
        },
        ReadTcpState::Bytes { ref mut pos, ref mut bytes } => {
          debug!("in ReadTcpState::Bytes: {}", bytes.len());
          let read = try_nb!(self.socket.read(&mut bytes[*pos..]));
          *pos += read;

          if *pos < bytes.len() {
            debug!("remain ReadTcpState::Bytes: {}", bytes.len());
            None
          } else {
            debug!("reset ReadTcpState::LenBytes: {}", 0);
            Some(ReadTcpState::LenBytes{ pos: 0, bytes: [0u8; 2] })
          }
        },
      };

      // this will move to the next state,
      //  if it was a completed receipt of bytes, then it will move out the bytes
      if let Some(state) = new_state {
        match mem::replace(&mut self.read_state, state) {
          ReadTcpState::Bytes{ pos, bytes } => {
            debug!("returning bytes");
            assert_eq!(pos, bytes.len());
            ret_buf = Some(bytes);
          },
          _ => (),
        }
      }
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
  use std;
  use std::time::Duration;
  use std::{thread, process};
  use std::io::{Read, Write};
  use std::sync::Arc;
  use std::sync::atomic::{AtomicBool,Ordering};

  use tokio_core::reactor::Core;

  let succeeded = Arc::new(AtomicBool::new(false));
  let succeeded_clone = succeeded.clone();
  thread::Builder::new().name("thread_killer".to_string()).spawn(move || {
    let succeeded = succeeded_clone.clone();
    for _ in 0..5 {
      thread::sleep(Duration::from_secs(1));
      if succeeded.load(Ordering::Relaxed) { return }
    }

    println!("timeout");
    process::exit(-1)
  }).unwrap();

  // TODO: need a timeout on listen
  let server = std::net::TcpListener::bind(SocketAddr::new(server_addr, 0)).unwrap();
  let server_addr = server.local_addr().unwrap();

  let send_recv_times = 4;

  // an in and out server
  let server_handle = thread::Builder::new().name("test_tcp_client_stream_ipv4:server".to_string()).spawn(move || {
    let (mut socket, _) = server.accept().expect("accept failed");

    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap(); // should recieve something within 5 seconds...
    socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap(); // should recieve something within 5 seconds...

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
      thread::yield_now();
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

  succeeded.store(true, Ordering::Relaxed);
  server_handle.join().expect("server thread failed");
}
