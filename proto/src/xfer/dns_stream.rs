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
use futures::sync::mpsc::{unbounded, UnboundedReceiver};
use futures::{Async, AsyncSink, Future, Poll, Sink};

use error::*;
use xfer::{SerialMessage, SerialMessageStreamHandle};

/// TODO: move non-tcp stuff to another type called DNSStream
/// A Stream used for sending data to and from a remote DNS endpoint (client or server).
#[must_use = "futures do nothing unless polled"]
pub struct DnsStream<S> {
    io_stream: S,
    outbound_messages: Peekable<UnboundedReceiver<SerialMessage>>,
    peer_addr: SocketAddr,
    to_send: Option<SerialMessage>,
    is_sending: bool,
}

impl<S> DnsStream<S> {
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
            to_send: None,
            is_sending: false,
        }
    }
}

impl<S> Stream for DnsStream<S>
where
    S: Stream<Item = SerialMessage, Error = io::Error>,
    S: Sink<SinkItem = SerialMessage, SinkError = io::Error>,
{
    type Item = SerialMessage;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        // this will not accept incoming data while there is data to send
        //  makes this self throttling.
        // TODO: it might be interesting to try and split the sending and receiving futures.
        loop {
            // make sure the underlying Sink completes any existing send in progress
            if self.is_sending {
                try_ready!(self.io_stream.poll_complete());
                self.is_sending = false;
            }

            // ok, no message is currently in transit
            //   now is there one to start sending...
            if let Some(serial_message) = self.to_send.take() {
                let dst = serial_message.addr();

                // start sending the message
                match self.io_stream.start_send(serial_message).map_err(|s| {
                    warn!("failure to send: {}", s);
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("failed to send message to: {}", dst),
                    )
                }) {
                    Ok(AsyncSink::Ready) => {
                        self.is_sending = true;
                    }
                    Ok(AsyncSink::NotReady(serial_message)) => {
                        // the Sink is not ready to send this message
                        //   we return because our contract is to not receive new messages unless we can
                        //   send them out...
                        self.to_send = Some(serial_message);
                        return Ok(Async::NotReady);
                    }
                    // TODO: we should pass the original message back on the error
                    Err(err) => return Err(err),
                };
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

                    self.to_send = Some(serial_message);

                    // we will continue to the send operation...
                    continue;
                }
                // now we get to drop through to the receives...
                Async::NotReady => break,
                Async::Ready(None) => {
                    // if there is nothing that can use this connection to send messages, then this is done...
                    return Ok(Async::Ready(None));
                }
            }
        }

        // Now we look for incoming messages
        self.io_stream.poll()
    }
}
