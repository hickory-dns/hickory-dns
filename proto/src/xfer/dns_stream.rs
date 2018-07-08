// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! This module contains all the types for demuxing DNS oriented streams.

use std::io;
use std::net::SocketAddr;

use futures::stream::{Peekable, Stream};
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::{Async, AsyncSink, Future, Poll, Sink};

use error::*;
use xfer::{SerialMessage, SerialMessageSender, SerialMessageStreamHandle};

/// TODO: move non-tcp stuff to another type called DNSStream
/// A Stream used for sending data to and from a remote DNS endpoint (client or server).
#[must_use = "futures do nothing unless polled"]
pub struct DnsStream<S, R>
where
    S: SerialMessageSender<SerialResponse = R>,
    R: Future<Item = SerialMessage, Error = io::Error> + Send,
{
    io_stream: S,
    outbound_messages: Peekable<UnboundedReceiver<SerialMessage>>,
    peer_addr: SocketAddr,
    // TODO: this should just return the future to the requester...
    requests: Vec<R>,
}

impl<S, R> DnsStream<S, R>
where
    S: SerialMessageSender<SerialResponse = R>,
    R: Future<Item = SerialMessage, Error = io::Error> + Send,
{
    /// Initializes a TcpStream with an existing tokio_tcp::TcpStream.
    ///
    /// This is intended for use with a TcpListener and Incoming.
    ///
    /// # Arguments
    ///
    /// * `stream` - the established IO stream for communication
    /// * `peer_addr` - sources address of the stream
    pub fn from_stream<E>(stream: S, peer_addr: SocketAddr) -> (Self, SerialMessageStreamHandle<E>)
    where
        E: FromProtoError,
    {
        let (message_sender, outbound_messages) = unbounded();
        let message_sender = SerialMessageStreamHandle::<E>::new(message_sender);

        let stream = Self::from_stream_with_receiver(stream, peer_addr, outbound_messages);

        (stream, message_sender)
    }

    /// Wrapps a stream where a sender and receiver have already been established
    pub fn from_stream_with_receiver(
        stream: S,
        peer_addr: SocketAddr,
        receiver: UnboundedReceiver<SerialMessage>,
    ) -> Self {
        DnsStream {
            io_stream: stream,
            outbound_messages: receiver.peekable(),
            peer_addr: peer_addr,
            requests: vec![],
            // to_send: None,
            // is_sending: false,
        }
    }

    /// Returns a future, which itself wraps a future which is awaiting connection.
    ///
    /// The connect_future shoudl be lazy.
    pub fn connect<F, E>(
        connect_future: F,
        peer_addr: SocketAddr,
    ) -> (DnsStreamConnect<F, S, R>, SerialMessageStreamHandle<E>)
    where
        F: Future<Item = S, Error = io::Error>,
        E: FromProtoError,
    {
        let (message_sender, outbound_messages) = unbounded();
        (
            DnsStreamConnect {
                connect_future,
                peer_addr,
                outbound_messages: Some(outbound_messages),
            },
            SerialMessageStreamHandle::<E>::new(message_sender),
        )
    }
}

impl<S, R> Stream for DnsStream<S, R>
where
    S: SerialMessageSender<SerialResponse = R>,
    R: Future<Item = SerialMessage, Error = io::Error> + Send,
{
    type Item = SerialMessage;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        // this will not accept incoming data while there is data to send
        //  makes this self throttling.
        // TODO: it might be interesting to try and split the sending and receiving futures.
        loop {
            // Now we look for incoming messages
            // TODO: we need to change all IO streams to return the future directly for each request, poll is the wrong interface
            let mut ready: Option<(SerialMessage, usize)> = None;

            for (idx, message_future) in self.requests.iter_mut().enumerate() {
                match message_future.poll() {
                    Ok(Async::Ready(message)) => {
                        ready = Some((message, idx));
                        break;
                    }
                    // check if any others are ready...
                    Ok(Async::NotReady) => continue,
                    // This should only happen if there is an error with the underlying protocol
                    Err(err) => return Err(err),
                }
            }

            // we have a Ready, return it, but first remove from our future list...
            if let Some((ready, ready_idx)) = ready {
                self.requests.remove(ready_idx);
                return Ok(Async::Ready(Some(ready)));
            }

            // then see if there is more to send
            match self
                .outbound_messages
                .poll()
                .map_err(|()| io::Error::new(io::ErrorKind::Other, "unknown"))?
            {
                // already handled above, here to make sure the poll() pops the next message
                Async::Ready(Some(serial_message)) => {
                    // if there is no peer, this connection should die...
                    let peer = self.peer_addr;
                    let dst = serial_message.addr();

                    // This is an error if the destination is not our peer (this is TCP after all)
                    //  This will kill the connection...
                    if peer != dst {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("mismatched peer: {} and dst: {}", peer, dst),
                        ));
                    }

                    debug!(
                        "sending message len: {} to: {}",
                        serial_message.bytes().len(),
                        serial_message.addr()
                    );

                    self.requests
                        .push(self.io_stream.send_message(serial_message));

                    // we will continue to the send operation...
                    continue;
                }
                // On not ready, this is our time to return...
                Async::NotReady => return Ok(Async::NotReady),
                Async::Ready(None) => {
                    // if there is nothing that can use this connection to send messages, then this is done...
                    return Ok(Async::Ready(None));
                }
            }

            // else we loop to poll on the outbound_messages
        }
    }
}

/// A wrapper for a future DnsStream connection
pub struct DnsStreamConnect<F, S, R>
where
    F: Future<Item = S, Error = io::Error>,
    S: SerialMessageSender<SerialResponse = R>,
    R: Future<Item = SerialMessage, Error = io::Error> + Send,
{
    connect_future: F,
    peer_addr: SocketAddr,
    outbound_messages: Option<UnboundedReceiver<SerialMessage>>,
}

impl<F, S, R> Future for DnsStreamConnect<F, S, R>
where
    F: Future<Item = S, Error = io::Error>,
    S: SerialMessageSender<SerialResponse = R>,
    R: Future<Item = SerialMessage, Error = io::Error> + Send,
{
    type Item = DnsStream<S, R>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let stream: S = try_ready!(self.connect_future.poll());

        Ok(Async::Ready(DnsStream::from_stream_with_receiver(
            stream,
            self.peer_addr,
            self.outbound_messages
                .take()
                .expect("cannot poll once complete"),
        )))
    }
}
