// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! This module contains all the TCP structures for demuxing TCP into streams of DNS packets.

use std::io;
use std::mem;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use futures::channel::mpsc::{unbounded, UnboundedReceiver};
use futures::stream::{Fuse, Peekable, Stream, StreamExt};
use futures::{self, ready, Future, FutureExt};
use log::debug;

use crate::error::*;
use crate::xfer::{BufStreamHandle, SerialMessage};
use crate::Time;

/// Trait for TCP connection
#[async_trait]
pub trait Connect
where
    Self: Sized,
{
    /// TcpSteam
    type Transport: futures::io::AsyncRead + futures::io::AsyncWrite + Send + Unpin;

    /// connect to tcp
    async fn connect(addr: SocketAddr) -> io::Result<Self::Transport>;
}

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
    /// Currently reading the bytes of the DNS packet
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
    outbound_messages: Peekable<Fuse<UnboundedReceiver<SerialMessage>>>,
    send_state: Option<WriteTcpState>,
    read_state: ReadTcpState,
    peer_addr: SocketAddr,
}

impl<S> TcpStream<S> {
    /// Returns the address of the peer connection.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    fn pollable_split(
        &mut self,
    ) -> (
        &mut S,
        &mut Peekable<Fuse<UnboundedReceiver<SerialMessage>>>,
        &mut Option<WriteTcpState>,
        &mut ReadTcpState,
    ) {
        (
            &mut self.socket,
            &mut self.outbound_messages,
            &mut self.send_state,
            &mut self.read_state,
        )
    }
}

impl<S: Connect + 'static> TcpStream<S> {
    /// Creates a new future of the eventually establish a IO stream connection or fail trying.
    ///
    /// Defaults to a 5 second timeout
    ///
    /// # Arguments
    ///
    /// * `name_server` - the IP and Port of the DNS server to connect to
    #[allow(clippy::new_ret_no_self, clippy::type_complexity)]
    pub fn new<E, TE>(
        name_server: SocketAddr,
    ) -> (
        impl Future<Output = Result<TcpStream<S::Transport>, io::Error>> + Send,
        BufStreamHandle,
    )
    where
        E: FromProtoError,
        TE: Time,
    {
        Self::with_timeout::<TE>(name_server, Duration::from_secs(5))
    }

    /// Creates a new future of the eventually establish a IO stream connection or fail trying
    ///
    /// # Arguments
    ///
    /// * `name_server` - the IP and Port of the DNS server to connect to
    /// * `timeout` - connection timeout
    #[allow(clippy::type_complexity)]
    pub fn with_timeout<TE: Time>(
        name_server: SocketAddr,
        timeout: Duration,
    ) -> (
        impl Future<Output = Result<TcpStream<S::Transport>, io::Error>> + Send,
        BufStreamHandle,
    ) {
        let (message_sender, outbound_messages) = unbounded();
        let message_sender = BufStreamHandle::new(message_sender);
        // This set of futures collapses the next tcp socket into a stream which can be used for
        //  sending and receiving tcp packets.
        let stream_fut = Self::connect::<TE>(name_server, timeout, outbound_messages);

        (stream_fut, message_sender)
    }

    async fn connect<TE: Time>(
        name_server: SocketAddr,
        timeout: Duration,
        outbound_messages: UnboundedReceiver<SerialMessage>,
    ) -> Result<TcpStream<S::Transport>, io::Error> {
        let tcp = S::connect(name_server);
        TE::timeout(timeout, tcp)
            .map(
                move |tcp_stream: Result<Result<S::Transport, io::Error>, _>| {
                    tcp_stream
                        .and_then(|tcp_stream| tcp_stream)
                        .map(|tcp_stream| {
                            debug!("TCP connection established to: {}", name_server);
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
                        })
                },
            )
            .await
    }
}

impl<S: futures::io::AsyncRead + futures::io::AsyncWrite> TcpStream<S> {
    /// Initializes a TcpStream.
    ///
    /// This is intended for use with a TcpListener and Incoming.
    ///
    /// # Arguments
    ///
    /// * `stream` - the established IO stream for communication
    /// * `peer_addr` - sources address of the stream
    pub fn from_stream(stream: S, peer_addr: SocketAddr) -> (Self, BufStreamHandle) {
        let (message_sender, outbound_messages) = unbounded();
        let message_sender = BufStreamHandle::new(message_sender);

        let stream = Self::from_stream_with_receiver(stream, peer_addr, outbound_messages);

        (stream, message_sender)
    }

    /// Wraps a stream where a sender and receiver have already been established
    pub fn from_stream_with_receiver(
        stream: S,
        peer_addr: SocketAddr,
        receiver: UnboundedReceiver<SerialMessage>,
    ) -> Self {
        TcpStream {
            socket: stream,
            outbound_messages: receiver.fuse().peekable(),
            send_state: None,
            read_state: ReadTcpState::LenBytes {
                pos: 0,
                bytes: [0u8; 2],
            },
            peer_addr,
        }
    }
}

impl<S: futures::io::AsyncRead + futures::io::AsyncWrite + Unpin> Stream for TcpStream<S> {
    type Item = io::Result<SerialMessage>;

    #[allow(clippy::cognitive_complexity)]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let peer = self.peer_addr;
        let (socket, outbound_messages, send_state, read_state) = self.pollable_split();
        let mut socket = Pin::new(socket);
        let mut outbound_messages = Pin::new(outbound_messages);

        // this will not accept incoming data while there is data to send
        //  makes this self throttling.
        // TODO: it might be interesting to try and split the sending and receiving futures.
        loop {
            // in the case we are sending, send it all?
            if send_state.is_some() {
                // sending...
                match send_state {
                    Some(WriteTcpState::LenBytes {
                        ref mut pos,
                        ref length,
                        ..
                    }) => {
                        let wrote = ready!(socket.as_mut().poll_write(cx, &length[*pos..]))?;
                        *pos += wrote;
                    }
                    Some(WriteTcpState::Bytes {
                        ref mut pos,
                        ref bytes,
                    }) => {
                        let wrote = ready!(socket.as_mut().poll_write(cx, &bytes[*pos..]))?;
                        *pos += wrote;
                    }
                    Some(WriteTcpState::Flushing) => {
                        ready!(socket.as_mut().poll_flush(cx))?;
                    }
                    _ => (),
                }

                // get current state
                let current_state = send_state.take();

                // switch states
                match current_state {
                    Some(WriteTcpState::LenBytes { pos, length, bytes }) => {
                        if pos < length.len() {
                            mem::replace(
                                send_state,
                                Some(WriteTcpState::LenBytes { pos, length, bytes }),
                            );
                        } else {
                            mem::replace(send_state, Some(WriteTcpState::Bytes { pos: 0, bytes }));
                        }
                    }
                    Some(WriteTcpState::Bytes { pos, bytes }) => {
                        if pos < bytes.len() {
                            mem::replace(send_state, Some(WriteTcpState::Bytes { pos, bytes }));
                        } else {
                            // At this point we successfully delivered the entire message.
                            //  flush
                            mem::replace(send_state, Some(WriteTcpState::Flushing));
                        }
                    }
                    Some(WriteTcpState::Flushing) => {
                        // At this point we successfully delivered the entire message.
                        send_state.take();
                    }
                    None => (),
                };
            } else {
                // then see if there is more to send
                match outbound_messages.as_mut().poll_next(cx)
                    // .map_err(|()| io::Error::new(io::ErrorKind::Other, "unknown"))?
                {
                    // already handled above, here to make sure the poll() pops the next message
                    Poll::Ready(Some(message)) => {
                        // if there is no peer, this connection should die...
                        let (buffer, dst) = message.unwrap();

                        // This is an error if the destination is not our peer (this is TCP after all)
                        //  This will kill the connection...
                        if peer != dst {
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("mismatched peer: {} and dst: {}", peer, dst),
                            ))));
                        }

                        // will return if the socket will block
                        // the length is 16 bits
                        let len: [u8; 2] = [
                            (buffer.len() >> 8 & 0xFF) as u8,
                            (buffer.len() & 0xFF) as u8,
                        ];

                        debug!("sending message len: {} to: {}", buffer.len(), dst);
                        *send_state = Some(WriteTcpState::LenBytes {
                            pos: 0,
                            length: len,
                            bytes: buffer,
                        });
                    }
                    // now we get to drop through to the receives...
                    // TODO: should we also return None if there are no more messages to send?
                    Poll::Pending => break,
                    Poll::Ready(None) => {
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
            let new_state: Option<ReadTcpState> = match read_state {
                ReadTcpState::LenBytes {
                    ref mut pos,
                    ref mut bytes,
                } => {
                    // debug!("reading length {}", bytes.len());
                    let read = ready!(socket.as_mut().poll_read(cx, &mut bytes[*pos..]))?;
                    if read == 0 {
                        // the Stream was closed!
                        debug!("zero bytes read, stream closed?");
                        //try!(self.socket.shutdown(Shutdown::Both)); // TODO: add generic shutdown function

                        if *pos == 0 {
                            // Since this is the start of the next message, we have a clean end
                            return Poll::Ready(None);
                        } else {
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "closed while reading length",
                            ))));
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
                        let mut bytes = vec![0; length as usize];
                        bytes.resize(length as usize, 0);

                        debug!("move ReadTcpState::Bytes: {}", bytes.len());
                        Some(ReadTcpState::Bytes { pos: 0, bytes })
                    }
                }
                ReadTcpState::Bytes {
                    ref mut pos,
                    ref mut bytes,
                } => {
                    let read = ready!(socket.as_mut().poll_read(cx, &mut bytes[*pos..]))?;
                    if read == 0 {
                        // the Stream was closed!
                        debug!("zero bytes read for message, stream closed?");

                        // Since this is the start of the next message, we have a clean end
                        // try!(self.socket.shutdown(Shutdown::Both));  // TODO: add generic shutdown function
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "closed while reading message",
                        ))));
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
                if let ReadTcpState::Bytes { pos, bytes } = mem::replace(read_state, state) {
                    debug!("returning bytes");
                    assert_eq!(pos, bytes.len());
                    ret_buf = Some(bytes);
                }
            }
        }

        // if the buffer is ready, return it, if not we're Pending
        if let Some(buffer) = ret_buf {
            debug!("returning buffer");
            let src_addr = self.peer_addr;
            Poll::Ready(Some(Ok(SerialMessage::new(buffer, src_addr))))
        } else {
            debug!("bottomed out");
            // at a minimum the outbound_messages should have been polled,
            //  which will wake this future up later...
            Poll::Pending
        }
    }
}

#[cfg(test)]
#[cfg(feature = "tokio-runtime")]
mod tests {
    #[cfg(not(target_os = "linux"))]
    use std::net::Ipv6Addr;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::net::TcpStream as TokioTcpStream;
    use tokio::runtime::Runtime;

    use crate::iocompat::AsyncIo02As03;
    use crate::TokioTime;

    use crate::tests::tcp_stream_test;
    #[test]
    fn test_tcp_stream_ipv4() {
        let io_loop = Runtime::new().expect("failed to create tokio runtime");
        tcp_stream_test::<AsyncIo02As03<TokioTcpStream>, Runtime, TokioTime>(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            io_loop,
        )
    }

    #[test]
    #[cfg(not(target_os = "linux"))] // ignored until Travis-CI fixes IPv6
    fn test_tcp_stream_ipv6() {
        let io_loop = Runtime::new().expect("failed to create tokio runtime");
        tcp_stream_test::<AsyncIo02As03<TokioTcpStream>, Runtime, TokioTime>(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            io_loop,
        )
    }
}
