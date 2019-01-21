// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! This module contains all the types for demuxing DNS oriented streams.

use futures::stream::{Peekable, Stream};
use futures::sync::mpsc::{unbounded, UnboundedReceiver};
use futures::{Async, Future, Poll};

use error::*;
use xfer::{DnsRequest, DnsRequestSender, DnsRequestStreamHandle, DnsResponse, OneshotDnsRequest};

/// This is a generic Exchange implemented over multiplexed DNS connection providers.
///
/// The underlying `DnsRequestSender` is expected to multiplex any I/O connections. DnsExchange assumes that the underlying stream is responsible for this.
#[must_use = "futures do nothing unless polled"]
pub struct DnsExchange<S, R>
where
    S: DnsRequestSender<DnsResponseFuture = R>,
    R: Future<Item = DnsResponse, Error = ProtoError> + 'static + Send,
{
    io_stream: S,
    outbound_messages: Peekable<UnboundedReceiver<OneshotDnsRequest<R>>>,
}

impl<S, R> DnsExchange<S, R>
where
    S: DnsRequestSender<DnsResponseFuture = R>,
    R: Future<Item = DnsResponse, Error = ProtoError> + 'static + Send,
{
    /// Initializes a TcpStream with an existing tokio_tcp::TcpStream.
    ///
    /// This is intended for use with a TcpListener and Incoming.
    ///
    /// # Arguments
    ///
    /// * `stream` - the established IO stream for communication
    pub fn from_stream(stream: S) -> (Self, DnsRequestStreamHandle<R>) {
        let (message_sender, outbound_messages) = unbounded();
        let message_sender = DnsRequestStreamHandle::<R>::new(message_sender);

        let stream = Self::from_stream_with_receiver(stream, outbound_messages);

        (stream, message_sender)
    }

    /// Wrapps a stream where a sender and receiver have already been established
    pub fn from_stream_with_receiver(
        stream: S,
        receiver: UnboundedReceiver<OneshotDnsRequest<R>>,
    ) -> Self {
        DnsExchange {
            io_stream: stream,
            outbound_messages: receiver.peekable(),
        }
    }

    /// Returns a future, which itself wraps a future which is awaiting connection.
    ///
    /// The connect_future should be lazy.
    pub fn connect<F>(connect_future: F) -> (DnsExchangeConnect<F, S, R>, DnsRequestStreamHandle<R>)
    where
        F: Future<Item = S, Error = ProtoError> + 'static + Send,
    {
        let (message_sender, outbound_messages) = unbounded();
        (
            DnsExchangeConnect::connect(connect_future, outbound_messages),
            DnsRequestStreamHandle::<R>::new(message_sender),
        )
    }
}

impl<S, R> Future for DnsExchange<S, R>
where
    S: DnsRequestSender<DnsResponseFuture = R>,
    R: Future<Item = DnsResponse, Error = ProtoError> + 'static + Send,
{
    type Item = ();
    type Error = ProtoError;

    #[allow(clippy::unused_unit)]
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // this will not accept incoming data while there is data to send
        //  makes this self throttling.
        loop {
            // poll the underlying stream, to drive it...
            match self.io_stream.poll() {
                // The stream is ready
                Ok(Async::Ready(Some(()))) => (),
                Ok(Async::NotReady) => {
                    if self.io_stream.is_shutdown() {
                        // the io_stream is in a shutdown state, we are only waiting for final results...
                        return Ok(Async::NotReady);
                    }

                    // NotReady and not shutdown, see if there are more messages to send
                    ()
                } // underlying stream is complete.
                Ok(Async::Ready(None)) => {
                    debug!("io_stream is done, shutting down");
                    // TODO: return shutdown error to anything in the stream?

                    return Ok(Async::Ready(()));
                }
                Err(err) => return Err(err),
            }

            // then see if there is more to send
            match self
                .outbound_messages
                .poll()
                .map_err(|()| ProtoError::from("unknown from outbound_message receiver"))?
            {
                // already handled above, here to make sure the poll() pops the next message
                Async::Ready(Some(dns_request)) => {
                    // if there is no peer, this connection should die...
                    let (dns_request, serial_response): (DnsRequest, _) = dns_request.unwrap();

                    debug!("sending message via: {}", self.io_stream);

                    match serial_response.send_response(self.io_stream.send_message(dns_request)) {
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
                    debug!("all handles closed, shutting down: {}", self.io_stream);
                    // if there is nothing that can use this connection to send messages, then this is done...
                    self.io_stream.shutdown();

                    // now we'll await the stream to shutdown... see io_stream poll above
                }
            }

            // else we loop to poll on the outbound_messages
        }
    }
}

/// A wrapper for a future DnsExchange connection
pub struct DnsExchangeConnect<F, S, R>(DnsExchangeConnectInner<F, S, R>)
where
    F: Future<Item = S, Error = ProtoError> + 'static + Send,
    S: DnsRequestSender<DnsResponseFuture = R>,
    R: Future<Item = DnsResponse, Error = ProtoError> + 'static + Send;

impl<F, S, R> DnsExchangeConnect<F, S, R>
where
    F: Future<Item = S, Error = ProtoError> + 'static + Send,
    S: DnsRequestSender<DnsResponseFuture = R>,
    R: Future<Item = DnsResponse, Error = ProtoError> + 'static + Send,
{
    fn connect(
        connect_future: F,
        outbound_messages: UnboundedReceiver<OneshotDnsRequest<R>>,
    ) -> Self {
        DnsExchangeConnect(DnsExchangeConnectInner::Connecting {
            connect_future,
            outbound_messages: Some(outbound_messages),
        })
    }
}

impl<F, S, R> Future for DnsExchangeConnect<F, S, R>
where
    F: Future<Item = S, Error = ProtoError> + 'static + Send,
    S: DnsRequestSender<DnsResponseFuture = R>,
    R: Future<Item = DnsResponse, Error = ProtoError> + 'static + Send,
{
    type Item = DnsExchange<S, R>;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

enum DnsExchangeConnectInner<F, S, R>
where
    F: Future<Item = S, Error = ProtoError> + 'static + Send,
    S: DnsRequestSender<DnsResponseFuture = R>,
    R: Future<Item = DnsResponse, Error = ProtoError> + 'static + Send,
{
    Connecting {
        connect_future: F,
        outbound_messages: Option<UnboundedReceiver<OneshotDnsRequest<R>>>,
    },
    FailAll {
        error: ProtoError,
        outbound_messages: UnboundedReceiver<OneshotDnsRequest<R>>,
    },
}

impl<F, S, R> Future for DnsExchangeConnectInner<F, S, R>
where
    F: Future<Item = S, Error = ProtoError> + 'static + Send,
    S: DnsRequestSender<DnsResponseFuture = R>,
    R: Future<Item = DnsResponse, Error = ProtoError> + 'static + Send,
{
    type Item = DnsExchange<S, R>;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            let next;
            match self {
                DnsExchangeConnectInner::Connecting {
                    ref mut connect_future,
                    ref mut outbound_messages,
                } => {
                    match connect_future.poll() {
                        Ok(Async::Ready(stream)) => {
                            debug!("connection established: {}", stream);
                            return Ok(Async::Ready(DnsExchange::from_stream_with_receiver(
                                stream,
                                outbound_messages
                                    .take()
                                    .expect("cannot poll after complete"),
                            )));
                        }
                        Ok(Async::NotReady) => return Ok(Async::NotReady),
                        Err(error) => {
                            debug!("stream errored while connecting: {:?}", error);
                            next = DnsExchangeConnectInner::FailAll {
                                error,
                                outbound_messages: outbound_messages
                                    .take()
                                    .expect("cannot poll after complete"),
                            }
                        }
                    };
                }
                DnsExchangeConnectInner::FailAll {
                    error,
                    ref mut outbound_messages,
                } => {
                    while let Some(outbound_message) = match outbound_messages.poll() {
                        Ok(Async::Ready(opt)) => opt,
                        Ok(Async::NotReady) => return Ok(Async::NotReady),
                        Err(_) => None,
                    } {
                        let response = S::error_response(error.clone());
                        // ignoring errors... best effort send...
                        outbound_message.unwrap().1.send_response(response).ok();
                    }

                    return Err(error.clone());
                }
            }

            *self = next;
        }
    }
}
