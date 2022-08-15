// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! This module contains all the types for demuxing DNS oriented streams.

use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_channel::mpsc;
use futures_util::future::{Future, FutureExt};
use futures_util::stream::{Peekable, Stream, StreamExt};
use tracing::{debug, warn};

use crate::error::*;
use crate::xfer::dns_handle::DnsHandle;
use crate::xfer::DnsResponseReceiver;
use crate::xfer::{
    BufDnsRequestStreamHandle, DnsRequest, DnsRequestSender, DnsResponse, OneshotDnsRequest,
    CHANNEL_BUFFER_SIZE,
};
use crate::Time;

/// This is a generic Exchange implemented over multiplexed DNS connection providers.
///
/// The underlying `DnsRequestSender` is expected to multiplex any I/O connections. DnsExchange assumes that the underlying stream is responsible for this.
#[must_use = "futures do nothing unless polled"]
pub struct DnsExchange {
    sender: BufDnsRequestStreamHandle,
}

impl DnsExchange {
    /// Initializes a TcpStream with an existing tcp::TcpStream.
    ///
    /// This is intended for use with a TcpListener and Incoming.
    ///
    /// # Arguments
    ///
    /// * `stream` - the established IO stream for communication
    pub fn from_stream<S, TE>(stream: S) -> (Self, DnsExchangeBackground<S, TE>)
    where
        S: DnsRequestSender + 'static + Send + Unpin,
    {
        let (sender, outbound_messages) = mpsc::channel(CHANNEL_BUFFER_SIZE);
        let message_sender = BufDnsRequestStreamHandle { sender };

        Self::from_stream_with_receiver(stream, outbound_messages, message_sender)
    }

    /// Wraps a stream where a sender and receiver have already been established
    pub fn from_stream_with_receiver<S, TE>(
        stream: S,
        receiver: mpsc::Receiver<OneshotDnsRequest>,
        sender: BufDnsRequestStreamHandle,
    ) -> (Self, DnsExchangeBackground<S, TE>)
    where
        S: DnsRequestSender + 'static + Send + Unpin,
    {
        let background = DnsExchangeBackground {
            io_stream: stream,
            outbound_messages: receiver.peekable(),
            marker: PhantomData,
        };

        (Self { sender }, background)
    }

    /// Returns a future, which itself wraps a future which is awaiting connection.
    ///
    /// The connect_future should be lazy.
    pub fn connect<F, S, TE>(connect_future: F) -> DnsExchangeConnect<F, S, TE>
    where
        F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
        S: DnsRequestSender + 'static + Send + Unpin,
        TE: Time + Unpin,
    {
        let (sender, outbound_messages) = mpsc::channel(CHANNEL_BUFFER_SIZE);
        let message_sender = BufDnsRequestStreamHandle { sender };

        DnsExchangeConnect::connect(connect_future, outbound_messages, message_sender)
    }
}

impl Clone for DnsExchange {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl DnsHandle for DnsExchange {
    type Response = DnsExchangeSend;
    type Error = ProtoError;

    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&mut self, request: R) -> Self::Response {
        DnsExchangeSend {
            result: self.sender.send(request),
            _sender: self.sender.clone(), // TODO: this shouldn't be necessary, currently the presence of Senders is what allows the background to track current users, it generally is dropped right after send, this makes sure that there is at least one active after send
        }
    }
}

/// A Stream that will resolve to Responses after sending the request
#[must_use = "futures do nothing unless polled"]
pub struct DnsExchangeSend {
    result: DnsResponseReceiver,
    _sender: BufDnsRequestStreamHandle,
}

impl Stream for DnsExchangeSend {
    type Item = Result<DnsResponse, ProtoError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // as long as there is no result, poll the exchange
        self.result.poll_next_unpin(cx)
    }
}

/// This background future is responsible for driving all network operations for the DNS protocol.
///
/// It must be spawned before any DNS messages are sent.
#[must_use = "futures do nothing unless polled"]
pub struct DnsExchangeBackground<S, TE>
where
    S: DnsRequestSender + 'static + Send + Unpin,
{
    io_stream: S,
    outbound_messages: Peekable<mpsc::Receiver<OneshotDnsRequest>>,
    marker: PhantomData<TE>,
}

impl<S, TE> DnsExchangeBackground<S, TE>
where
    S: DnsRequestSender + 'static + Send + Unpin,
{
    fn pollable_split(&mut self) -> (&mut S, &mut Peekable<mpsc::Receiver<OneshotDnsRequest>>) {
        (&mut self.io_stream, &mut self.outbound_messages)
    }
}

impl<S, TE> Future for DnsExchangeBackground<S, TE>
where
    S: DnsRequestSender + 'static + Send + Unpin,
    TE: Time + Unpin,
{
    type Output = Result<(), ProtoError>;

    #[allow(clippy::unused_unit)]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let (io_stream, outbound_messages) = self.pollable_split();
        let mut io_stream = Pin::new(io_stream);
        let mut outbound_messages = Pin::new(outbound_messages);

        // this will not accept incoming data while there is data to send
        //  makes this self throttling.
        loop {
            // poll the underlying stream, to drive it...
            match io_stream.as_mut().poll_next(cx) {
                // The stream is ready
                Poll::Ready(Some(Ok(()))) => (),
                Poll::Pending => {
                    if io_stream.is_shutdown() {
                        // the io_stream is in a shutdown state, we are only waiting for final results...
                        return Poll::Pending;
                    }

                    // NotReady and not shutdown, see if there are more messages to send
                    ()
                } // underlying stream is complete.
                Poll::Ready(None) => {
                    debug!("io_stream is done, shutting down");
                    // TODO: return shutdown error to anything in the stream?

                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Err(err))) => {
                    warn!("io_stream hit an error, shutting down: {}", err);

                    return Poll::Ready(Err(err));
                }
            }

            // then see if there is more to send
            match outbound_messages.as_mut().poll_next(cx) {
                // already handled above, here to make sure the poll() pops the next message
                Poll::Ready(Some(dns_request)) => {
                    // if there is no peer, this connection should die...
                    let (dns_request, serial_response): (DnsRequest, _) = dns_request.into_parts();

                    // Try to forward the `DnsResponseStream` to the requesting task. If we fail,
                    // it must be because the requesting task has gone away / is no longer
                    // interested. In that case, we can just log a warning, but there's no need
                    // to take any more serious measures (such as shutting down this task).
                    match serial_response.send_response(io_stream.send_message(dns_request)) {
                        Ok(()) => (),
                        Err(_) => {
                            warn!("failed to associate send_message response to the sender");
                        }
                    }
                }
                // On not ready, this is our time to return...
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    // if there is nothing that can use this connection to send messages, then this is done...
                    io_stream.shutdown();

                    // now we'll await the stream to shutdown... see io_stream poll above
                }
            }

            // else we loop to poll on the outbound_messages
        }
    }
}

/// A wrapper for a future DnsExchange connection.
///
/// DnsExchangeConnect is clonable, making it possible to share this if the connection
///  will be shared across threads.
///
/// The future will return a tuple of the DnsExchange (for sending messages) and a background
///  for running the background tasks. The background is optional as only one thread should run
///  the background. If returned, it must be spawned before any dns requests will function.
pub struct DnsExchangeConnect<F, S, TE>(DnsExchangeConnectInner<F, S, TE>)
where
    F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    S: DnsRequestSender + 'static,
    TE: Time + Unpin;

impl<F, S, TE> DnsExchangeConnect<F, S, TE>
where
    F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    S: DnsRequestSender + 'static,
    TE: Time + Unpin,
{
    fn connect(
        connect_future: F,
        outbound_messages: mpsc::Receiver<OneshotDnsRequest>,
        sender: BufDnsRequestStreamHandle,
    ) -> Self {
        Self(DnsExchangeConnectInner::Connecting {
            connect_future,
            outbound_messages: Some(outbound_messages),
            sender: Some(sender),
        })
    }
}

#[allow(clippy::type_complexity)]
impl<F, S, TE> Future for DnsExchangeConnect<F, S, TE>
where
    F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    S: DnsRequestSender + 'static + Send + Unpin,
    TE: Time + Unpin,
{
    type Output = Result<(DnsExchange, DnsExchangeBackground<S, TE>), ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.poll_unpin(cx)
    }
}

enum DnsExchangeConnectInner<F, S, TE>
where
    F: Future<Output = Result<S, ProtoError>> + 'static + Send,
    S: DnsRequestSender + 'static + Send,
    TE: Time + Unpin,
{
    Connecting {
        connect_future: F,
        outbound_messages: Option<mpsc::Receiver<OneshotDnsRequest>>,
        sender: Option<BufDnsRequestStreamHandle>,
    },
    Connected {
        exchange: DnsExchange,
        background: Option<DnsExchangeBackground<S, TE>>,
    },
    FailAll {
        error: ProtoError,
        outbound_messages: mpsc::Receiver<OneshotDnsRequest>,
    },
}

#[allow(clippy::type_complexity)]
impl<F, S, TE> Future for DnsExchangeConnectInner<F, S, TE>
where
    F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    S: DnsRequestSender + 'static + Send + Unpin,
    TE: Time + Unpin,
{
    type Output = Result<(DnsExchange, DnsExchangeBackground<S, TE>), ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let next;
            match *self {
                Self::Connecting {
                    ref mut connect_future,
                    ref mut outbound_messages,
                    ref mut sender,
                } => {
                    let connect_future = Pin::new(connect_future);
                    match connect_future.poll(cx) {
                        Poll::Ready(Ok(stream)) => {
                            //debug!("connection established: {}", stream);

                            let (exchange, background) = DnsExchange::from_stream_with_receiver(
                                stream,
                                outbound_messages
                                    .take()
                                    .expect("cannot poll after complete"),
                                sender.take().expect("cannot poll after complete"),
                            );

                            next = Self::Connected {
                                exchange,
                                background: Some(background),
                            };
                        }
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => {
                            debug!("stream errored while connecting: {:?}", error);
                            next = Self::FailAll {
                                error,
                                outbound_messages: outbound_messages
                                    .take()
                                    .expect("cannot poll after complete"),
                            }
                        }
                    };
                }
                Self::Connected {
                    ref exchange,
                    ref mut background,
                } => {
                    let exchange = exchange.clone();
                    let background = background.take().expect("cannot poll after complete");

                    return Poll::Ready(Ok((exchange, background)));
                }
                Self::FailAll {
                    ref error,
                    ref mut outbound_messages,
                } => {
                    while let Some(outbound_message) = match outbound_messages.poll_next_unpin(cx) {
                        Poll::Ready(opt) => opt,
                        Poll::Pending => return Poll::Pending,
                    } {
                        // ignoring errors... best effort send...
                        outbound_message
                            .into_parts()
                            .1
                            .send_response(error.clone().into())
                            .ok();
                    }

                    return Poll::Ready(Err(error.clone()));
                }
            }

            *self = next;
        }
    }
}
