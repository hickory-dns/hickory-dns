// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! This module contains all the types for demuxing DNS oriented streams.

use std::net::SocketAddr;

use futures::stream::{Peekable, Stream};
use futures::sync::mpsc::{unbounded, UnboundedReceiver};
use futures::{Async, Future, Poll};

use error::*;
use xfer::{
    DnsResponse, OneshotSerialRequest, SerialMessage, SerialMessageSender,
    SerialMessageStreamHandle,
};

// TODO: rename this to MultiplexedAsyncDns
/// A Stream used for sending data to and from a remote DNS endpoint (client or server).
#[must_use = "futures do nothing unless polled"]
pub struct DnsStream<S, R>
where
    S: SerialMessageSender<SerialResponse = R>,
    R: Future<Item = DnsResponse, Error = ProtoError> + Send,
{
    io_stream: S,
    outbound_messages: Peekable<UnboundedReceiver<OneshotSerialRequest<R>>>,
    peer_addr: SocketAddr,
}

impl<S, R> DnsStream<S, R>
where
    S: SerialMessageSender<SerialResponse = R>,
    R: Future<Item = DnsResponse, Error = ProtoError> + Send,
{
    /// Initializes a TcpStream with an existing tokio_tcp::TcpStream.
    ///
    /// This is intended for use with a TcpListener and Incoming.
    ///
    /// # Arguments
    ///
    /// * `stream` - the established IO stream for communication
    /// * `peer_addr` - sources address of the stream
    pub fn from_stream<E>(stream: S, peer_addr: SocketAddr) -> (Self, SerialMessageStreamHandle<R>)
    where
        E: FromProtoError,
    {
        let (message_sender, outbound_messages) = unbounded();
        let message_sender = SerialMessageStreamHandle::<R>::new(message_sender);

        let stream = Self::from_stream_with_receiver(stream, peer_addr, outbound_messages);

        (stream, message_sender)
    }

    /// Wrapps a stream where a sender and receiver have already been established
    pub fn from_stream_with_receiver(
        stream: S,
        peer_addr: SocketAddr,
        receiver: UnboundedReceiver<OneshotSerialRequest<R>>,
    ) -> Self {
        DnsStream {
            io_stream: stream,
            outbound_messages: receiver.peekable(),
            peer_addr: peer_addr,
            // to_send: None,
            // is_sending: false,
        }
    }

    /// Returns a future, which itself wraps a future which is awaiting connection.
    ///
    /// The connect_future shoudl be lazy.
    pub fn connect<F>(
        connect_future: F,
        peer_addr: SocketAddr,
    ) -> (DnsStreamConnect<F, S, R>, SerialMessageStreamHandle<R>)
    where
        F: Future<Item = S, Error = ProtoError>,
    {
        let (message_sender, outbound_messages) = unbounded();
        (
            DnsStreamConnect {
                connect_future,
                peer_addr,
                outbound_messages: Some(outbound_messages),
            },
            // FIXME: change the SerialMessageStreamHandle to use OneshotSerialRequest
            SerialMessageStreamHandle::<R>::new(message_sender),
        )
    }
}

impl<S, R> Future for DnsStream<S, R>
where
    S: SerialMessageSender<SerialResponse = R>,
    R: Future<Item = DnsResponse, Error = ProtoError> + Send,
{
    type Item = ();
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // this will not accept incoming data while there is data to send
        //  makes this self throttling.
        loop {
            // then see if there is more to send
            match self
                .outbound_messages
                .poll()
                .map_err(|()| ProtoError::from("unknown from outbound_message receiver"))?
            {
                // already handled above, here to make sure the poll() pops the next message
                Async::Ready(Some(serial_message)) => {
                    // if there is no peer, this connection should die...
                    let (serial_message, serial_response): (SerialMessage, _) =
                        serial_message.unwrap();
                    let peer = self.peer_addr;
                    let dst = serial_message.addr();

                    // This is an error if the destination is not our peer (this is TCP after all)
                    //  This will kill the connection...
                    if peer != dst {
                        return Err(ProtoError::from(format!(
                            "mismatched peer: {} and dst: {}",
                            peer, dst
                        )));
                    }

                    debug!(
                        "sending message len: {} to: {}",
                        serial_message.bytes().len(),
                        serial_message.addr()
                    );

                    match serial_response.send_response(self.io_stream.send_message(serial_message))
                    {
                        Ok(()) => (),
                        Err(_) => {
                            warn!("failed to associate send_message response to the sender");
                            return Err(
                                "failed to associate send_message response to the sender".into()
                            );
                        }
                    }
                }
                // On not ready, this is our time to return...
                Async::NotReady => return Ok(Async::NotReady),
                Async::Ready(None) => {
                    debug!("all handles closed, shutting down: {}", self.peer_addr);
                    // if there is nothing that can use this connection to send messages, then this is done...
                    return Ok(Async::Ready(()));
                }
            }

            // else we loop to poll on the outbound_messages
        }
    }
}

/// A wrapper for a future DnsStream connection
pub struct DnsStreamConnect<F, S, R>
where
    F: Future<Item = S, Error = ProtoError>,
    S: SerialMessageSender<SerialResponse = R>,
    R: Future<Item = DnsResponse, Error = ProtoError> + Send,
{
    connect_future: F,
    peer_addr: SocketAddr,
    outbound_messages: Option<UnboundedReceiver<OneshotSerialRequest<R>>>,
}

impl<F, S, R> Future for DnsStreamConnect<F, S, R>
where
    F: Future<Item = S, Error = ProtoError>,
    S: SerialMessageSender<SerialResponse = R>,
    R: Future<Item = DnsResponse, Error = ProtoError> + Send,
{
    type Item = DnsStream<S, R>;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let stream: S = try_ready!(self.connect_future.poll());

        debug!("connection established: {}", self.peer_addr);
        Ok(Async::Ready(DnsStream::from_stream_with_receiver(
            stream,
            self.peer_addr,
            self.outbound_messages
                .take()
                .expect("cannot poll once complete"),
        )))
    }
}
