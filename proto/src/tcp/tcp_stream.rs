// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! This module contains all the TCP structures for demuxing TCP into streams of DNS packets.

use std::io;
use std::marker::PhantomData;
use std::mem;
use std::net::SocketAddr;
use std::time::Duration;

use futures::{Async, Future, Poll};
use futures::future;
use futures::future::Either;
use futures::stream::{Fuse, Peekable, Stream};
use futures::sync::mpsc::{unbounded, UnboundedReceiver};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_core::net::TcpStream as TokioTcpStream;
use tokio_core::reactor::{Handle, Timeout};

use BufStreamHandle;
use error::*;

/// Current state while writing to the remote of the TCP connection
enum WriteTcpState {
    /// Currently writing the length of bytes to of the buffer.
    LenBytes {
        /// Current position in the length buffer being written
        pos: usize,
        /// Length of the buffer
        length: [u8; 2],
        /// Buffer to write after the length
        bytes: Vec<u8>,
    },
    /// Currently writing the buffer to the remote
    Bytes {
        /// Current position in the buffer written
        pos: usize,
        /// Buffer to write to the remote
        bytes: Vec<u8>,
    },
    /// Currently flushing the bytes to the remote
    Flushing,
}

/// Current state of a TCP stream as it's being read.
pub enum ReadTcpState {
    /// Currently reading the length of the TCP packet
    LenBytes {
        /// Current position in the buffer
        pos: usize,
        /// Buffer of the length to read
        bytes: [u8; 2],
    },
    /// Currently reading the byts of the DNS packet
    Bytes {
        /// Current position while reading the buffer
        pos: usize,
        /// buffer being read into
        bytes: Vec<u8>,
    },
}


/// A Stream used for sending data to and from a remote DNS endpoint (client or server).
#[must_use = "futures do nothing unless polled"]
pub struct TcpStream<S> {
    socket: S,
    outbound_messages: Peekable<Fuse<UnboundedReceiver<(Vec<u8>, SocketAddr)>>>,
    send_state: Option<WriteTcpState>,
    read_state: ReadTcpState,
    peer_addr: SocketAddr,
}

impl<S> TcpStream<S> {
    /// Returns the address of the peer connection.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

impl TcpStream<TokioTcpStream> {
    /// Creates a new future of the eventually establish a IO stream connection or fail trying.
    ///
    /// Defaults to a 5 second timeout
    ///
    /// # Arguments
    ///
    /// * `name_server` - the IP and Port of the DNS server to connect to
    /// * `loop_handle` - reference to the takio_core::Core for future based IO
    pub fn new<E>(
        name_server: SocketAddr,
        loop_handle: &Handle,
    ) -> (
        Box<Future<Item = TcpStream<TokioTcpStream>, Error = io::Error>>,
        BufStreamHandle<E>,
    )
    where
        E: FromProtoError,
    {
        Self::with_timeout(name_server, loop_handle, Duration::from_secs(5))
    }

    /// Creates a new future of the eventually establish a IO stream connection or fail trying
    ///
    /// # Arguments
    ///
    /// * `name_server` - the IP and Port of the DNS server to connect to
    /// * `loop_handle` - reference to the takio_core::Core for future based IO
    /// * `timeout` - connection timeout
    pub fn with_timeout<E>(
        name_server: SocketAddr,
        loop_handle: &Handle,
        timeout: Duration,
    ) -> (
        Box<Future<Item = TcpStream<TokioTcpStream>, Error = io::Error>>,
        BufStreamHandle<E>,
    )
    where
        E: FromProtoError,
    {
        let (message_sender, outbound_messages) = unbounded();
        let message_sender = BufStreamHandle::<E>::new(message_sender);
        let timeout = match Timeout::new(timeout, loop_handle) {
            Ok(timeout) => timeout,
            Err(e) => return (Box::new(future::err(e)), message_sender),
        };


        let tcp = TokioTcpStream::connect(&name_server, loop_handle);

        // This set of futures collapses the next tcp socket into a stream which can be used for
        //  sending and receiving tcp packets.
        let stream: Box<Future<Item = TcpStream<TokioTcpStream>, Error = io::Error>> = Box::new(
            timeout
                .select2(tcp)
                .then(move |res| match res {
                    Ok(Either::A((_, _))) => future::err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("timed out connecting to: {}", name_server),
                    )),
                    Ok(Either::B((tcp_stream, _))) => future::ok((tcp_stream, name_server)),
                    Err(Either::A((timeout_err, _))) => future::err(timeout_err),
                    Err(Either::B((tcp_err, _))) => future::err(tcp_err),
                })
                .map(move |(tcp_stream, name_server)| {
                    TcpStream {
                        socket: tcp_stream,
                        outbound_messages: outbound_messages.fuse().peekable(),
                        send_state: None,
                        read_state: ReadTcpState::LenBytes {
                            pos: 0,
                            bytes: [0u8; 2],
                        },
                        peer_addr: name_server,
                    }
                }),
        );

        (stream, message_sender)
    }
}

impl<S: AsyncRead + AsyncWrite> TcpStream<S> {
    /// Initializes a TcpStream with an existing tokio_core::net::TcpStream.
    ///
    /// This is intended for use with a TcpListener and Incoming.
    ///
    /// # Arguments
    ///
    /// * `stream` - the established IO stream for communication
    /// * `peer_addr` - sources address of the stream
    pub fn from_stream<E>(stream: S, peer_addr: SocketAddr) -> (Self, BufStreamHandle<E>)
    where
        E: FromProtoError,
    {
        let (message_sender, outbound_messages) = unbounded();
        let message_sender = BufStreamHandle::<E> {
            sender: message_sender,
            phantom: PhantomData::<E>,
        };

        let stream = Self::from_stream_with_receiver(stream, peer_addr, outbound_messages);

        (stream, message_sender)
    }

    /// Wrapps a stream where a sender and receiver have already been established
    pub fn from_stream_with_receiver(
        stream: S,
        peer_addr: SocketAddr,
        receiver: UnboundedReceiver<(Vec<u8>, SocketAddr)>,
    ) -> Self {
        TcpStream {
            socket: stream,
            outbound_messages: receiver.fuse().peekable(),
            send_state: None,
            read_state: ReadTcpState::LenBytes {
                pos: 0,
                bytes: [0u8; 2],
            },
            peer_addr: peer_addr,
        }
    }
}

impl<S: AsyncRead + AsyncWrite> Stream for TcpStream<S> {
    type Item = (Vec<u8>, SocketAddr);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        // this will not accept incoming data while there is data to send
        //  makes this self throttling.
        // TODO: it might be interesting to try and split the sending and receiving futures.
        loop {
            // in the case we are sending, send it all?
            if self.send_state.is_some() {
                // sending...
                match self.send_state {
                    Some(WriteTcpState::LenBytes {
                        ref mut pos,
                        ref length,
                        ..
                    }) => {
                        let wrote = try_nb!(self.socket.write(&length[*pos..]));
                        *pos += wrote;
                    }
                    Some(WriteTcpState::Bytes {
                        ref mut pos,
                        ref bytes,
                    }) => {
                        let wrote = try_nb!(self.socket.write(&bytes[*pos..]));
                        *pos += wrote;
                    }
                    Some(WriteTcpState::Flushing) => {
                        try_nb!(self.socket.flush());
                    }
                    _ => (),
                }

                // get current state
                let current_state = mem::replace(&mut self.send_state, None);

                // switch states
                match current_state {
                    Some(WriteTcpState::LenBytes { pos, length, bytes }) => if pos < length.len() {
                        mem::replace(
                            &mut self.send_state,
                            Some(WriteTcpState::LenBytes {
                                pos: pos,
                                length: length,
                                bytes: bytes,
                            }),
                        );
                    } else {
                        mem::replace(
                            &mut self.send_state,
                            Some(WriteTcpState::Bytes {
                                pos: 0,
                                bytes: bytes,
                            }),
                        );
                    },
                    Some(WriteTcpState::Bytes { pos, bytes }) => {
                        if pos < bytes.len() {
                            mem::replace(
                                &mut self.send_state,
                                Some(WriteTcpState::Bytes {
                                    pos: pos,
                                    bytes: bytes,
                                }),
                            );
                        } else {
                            // At this point we successfully delivered the entire message.
                            //  flush
                            mem::replace(&mut self.send_state, Some(WriteTcpState::Flushing));
                        }
                    }
                    Some(WriteTcpState::Flushing) => {
                        // At this point we successfully delivered the entire message.
                        mem::replace(&mut self.send_state, None);
                    }
                    None => (),
                };
            } else {
                // then see if there is more to send
                match self.outbound_messages
                    .poll()
                    .map_err(|()| io::Error::new(io::ErrorKind::Other, "unknown"))?
                {
                    // already handled above, here to make sure the poll() pops the next message
                    Async::Ready(Some((buffer, dst))) => {
                        // if there is no peer, this connection should die...
                        let peer = self.peer_addr;

                        // This is an error if the destination is not our peer (this is TCP after all)
                        //  This will kill the connection...
                        if peer != dst {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("mismatched peer: {} and dst: {}", peer, dst),
                            ));
                        }

                        // will return if the socket will block
                        // the length is 16 bits
                        let len: [u8; 2] = [
                            (buffer.len() >> 8 & 0xFF) as u8,
                            (buffer.len() & 0xFF) as u8,
                        ];

                        debug!("sending message len: {} to: {}", buffer.len(), dst);
                        self.send_state = Some(WriteTcpState::LenBytes {
                            pos: 0,
                            length: len,
                            bytes: buffer,
                        });
                    }
                    // now we get to drop through to the receives...
                    // TODO: should we also return None if there are no more messages to send?
                    Async::NotReady => break,
                    Async::Ready(None) => {
                        debug!("no messages to send");
                        break;
                    }
                }
            }
        }

        let mut ret_buf: Option<Vec<u8>> = None;

        // this will loop while there is data to read, or the data has been read, or an IO
        //  event would block
        while ret_buf.is_none() {
            // Evaluates the next state. If None is the result, then no state change occurs,
            //  if Some(_) is returned, then that will be used as the next state.
            let new_state: Option<ReadTcpState> = match self.read_state {
                ReadTcpState::LenBytes {
                    ref mut pos,
                    ref mut bytes,
                } => {
                    // debug!("reading length {}", bytes.len());
                    let read = try_nb!(self.socket.read(&mut bytes[*pos..]));
                    if read == 0 {
                        // the Stream was closed!
                        debug!("zero bytes read, stream closed?");
                        //try!(self.socket.shutdown(Shutdown::Both)); // FIXME: add generic shutdown function

                        if *pos == 0 {
                            // Since this is the start of the next message, we have a clean end
                            return Ok(Async::Ready(None));
                        } else {
                            return Err(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "closed while reading length",
                            ));
                        }
                    }
                    debug!("in ReadTcpState::LenBytes: {}", pos);
                    *pos += read;

                    if *pos < bytes.len() {
                        debug!("remain ReadTcpState::LenBytes: {}", pos);
                        None
                    } else {
                        let length =
                            u16::from(bytes[0]) << 8 & 0xFF00 | u16::from(bytes[1]) & 0x00FF;
                        debug!("got length: {}", length);
                        let mut bytes = Vec::with_capacity(length as usize);
                        bytes.resize(length as usize, 0);

                        debug!("move ReadTcpState::Bytes: {}", bytes.len());
                        Some(ReadTcpState::Bytes {
                            pos: 0,
                            bytes: bytes,
                        })
                    }
                }
                ReadTcpState::Bytes {
                    ref mut pos,
                    ref mut bytes,
                } => {
                    let read = try_nb!(self.socket.read(&mut bytes[*pos..]));
                    if read == 0 {
                        // the Stream was closed!
                        debug!("zero bytes read for message, stream closed?");

                        // Since this is the start of the next message, we have a clean end
                        // try!(self.socket.shutdown(Shutdown::Both));  // FIXME: add generic shutdown function
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "closed while reading message",
                        ));
                    }

                    debug!("in ReadTcpState::Bytes: {}", bytes.len());
                    *pos += read;

                    if *pos < bytes.len() {
                        debug!("remain ReadTcpState::Bytes: {}", bytes.len());
                        None
                    } else {
                        debug!("reset ReadTcpState::LenBytes: {}", 0);
                        Some(ReadTcpState::LenBytes {
                            pos: 0,
                            bytes: [0u8; 2],
                        })
                    }
                }
            };

            // this will move to the next state,
            //  if it was a completed receipt of bytes, then it will move out the bytes
            if let Some(state) = new_state {
                if let ReadTcpState::Bytes { pos, bytes } =
                    mem::replace(&mut self.read_state, state)
                {
                    debug!("returning bytes");
                    assert_eq!(pos, bytes.len());
                    ret_buf = Some(bytes);
                }
            }
        }

        // if the buffer is ready, return it, if not we're NotReady
        if let Some(buffer) = ret_buf {
            debug!("returning buffer");
            let src_addr = self.peer_addr;
            return Ok(Async::Ready(Some((buffer, src_addr))));
        } else {
            debug!("bottomed out");
            // at a minimum the outbound_messages should have been polled,
            //  which will wake this future up later...
            return Ok(Async::NotReady);
        }
    }
}

#[cfg(test)]
use std::net::{IpAddr, Ipv4Addr};
#[cfg(not(target_os = "linux"))]
#[cfg(test)]
use std::net::Ipv6Addr;

#[test]
// this fails on linux for some reason. It appears that a buffer somewhere is dirty
//  and subsequent reads of a mesage buffer reads the wrong length. It works for 2 iterations
//  but not 3?
// #[cfg(not(target_os = "linux"))]
fn test_tcp_client_stream_ipv4() {
    tcp_client_stream_test(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
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
    std::thread::Builder::new()
        .name("thread_killer".to_string())
        .spawn(move || {
            let succeeded = succeeded_clone.clone();
            for _ in 0..15 {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if succeeded.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
            }

            panic!("timeout");
        })
        .unwrap();

    // TODO: need a timeout on listen
    let server = std::net::TcpListener::bind(SocketAddr::new(server_addr, 0)).unwrap();
    let server_addr = server.local_addr().unwrap();

    let send_recv_times = 4;

    // an in and out server
    let server_handle = std::thread::Builder::new()
        .name("test_tcp_client_stream:server".to_string())
        .spawn(move || {
            let (mut socket, _) = server.accept().expect("accept failed");

            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap(); // should recieve something within 5 seconds...
            socket
                .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap(); // should recieve something within 5 seconds...

            for _ in 0..send_recv_times {
                // wait for some bytes...
                let mut len_bytes = [0_u8; 2];
                socket
                    .read_exact(&mut len_bytes)
                    .expect("SERVER: receive failed");
                let length = (len_bytes[0] as u16) << 8 & 0xFF00 | len_bytes[1] as u16 & 0x00FF;
                assert_eq!(length as usize, TEST_BYTES_LEN);

                let mut buffer = [0_u8; TEST_BYTES_LEN];
                socket.read_exact(&mut buffer).unwrap();

                // println!("read bytes iter: {}", i);
                assert_eq!(&buffer, TEST_BYTES);

                // bounce them right back...
                socket
                    .write_all(&len_bytes)
                    .expect("SERVER: send length failed");
                socket
                    .write_all(&buffer)
                    .expect("SERVER: send buffer failed");
                // println!("wrote bytes iter: {}", i);
                std::thread::yield_now();
            }
        })
        .unwrap();

    // setup the client, which is going to run on the testing thread...
    let mut io_loop = Core::new().unwrap();

    // the tests should run within 5 seconds... right?
    // TODO: add timeout here, so that test never hangs...
    // let timeout = Timeout::new(Duration::from_secs(5), &io_loop.handle());
    let (stream, sender) = TcpStream::new::<ProtoError>(server_addr, &io_loop.handle());

    let mut stream = io_loop.run(stream).ok().expect("run failed to get stream");

    for _ in 0..send_recv_times {
        // test once
        sender
            .sender
            .unbounded_send((TEST_BYTES.to_vec(), server_addr))
            .expect("send failed");
        let (buffer, stream_tmp) = io_loop
            .run(stream.into_future())
            .ok()
            .expect("future iteration run failed");
        stream = stream_tmp;
        let (buffer, _) = buffer.expect("no buffer received");
        assert_eq!(&buffer, TEST_BYTES);
    }

    succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
    server_handle.join().expect("server thread failed");
}
