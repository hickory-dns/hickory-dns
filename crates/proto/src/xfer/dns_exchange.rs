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

use futures::channel::mpsc::{unbounded, UnboundedReceiver};
use futures::stream::{Peekable, Stream, StreamExt};
use futures::{Future, FutureExt};
use log::{debug, warn};

use crate::error::*;
use crate::xfer::dns_handle::DnsHandle;
use crate::xfer::OneshotDnsResponseReceiver;
use crate::xfer::{
    BufDnsRequestStreamHandle, DnsRequest, DnsRequestSender, DnsRequestStreamHandle, DnsResponse,
    OneshotDnsRequest,
};
use crate::Time;

/// This is a generic Exchange implemented over multiplexed DNS connection providers.
///
/// The underlying `DnsRequestSender` is expected to multiplex any I/O connections. DnsExchange assumes that the underlying stream is responsible for this.
#[must_use = "futures do nothing unless polled"]
pub struct DnsExchange<R>
where
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    sender: BufDnsRequestStreamHandle<R>,
}

impl<R> DnsExchange<R>
where
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    /// Initializes a TcpStream with an existing tcp::TcpStream.
    ///
    /// This is intended for use with a TcpListener and Incoming.
    ///
    /// # Arguments
    ///
    /// * `stream` - the established IO stream for communication
    pub fn from_stream<S, TE>(stream: S) -> (Self, DnsExchangeBackground<S, R, TE>)
    where
        S: DnsRequestSender<DnsResponseFuture = R> + 'static + Send + Unpin,
    {
        let (message_sender, outbound_messages) = unbounded();
        let message_sender = DnsRequestStreamHandle::<R>::new(message_sender);

        Self::from_stream_with_receiver(stream, outbound_messages, message_sender)
    }

    /// Wraps a stream where a sender and receiver have already been established
    pub fn from_stream_with_receiver<S, TE>(
        stream: S,
        receiver: UnboundedReceiver<OneshotDnsRequest<R>>,
        sender: DnsRequestStreamHandle<R>,
    ) -> (Self, DnsExchangeBackground<S, R, TE>)
    where
        S: DnsRequestSender<DnsResponseFuture = R> + 'static + Send + Unpin,
    {
        let background = DnsExchangeBackground {
            io_stream: stream,
            outbound_messages: receiver.peekable(),
            marker: PhantomData,
        };

        let sender = BufDnsRequestStreamHandle::new(sender);

        (Self { sender }, background)
    }

    /// Returns a future, which itself wraps a future which is awaiting connection.
    ///
    /// The connect_future should be lazy.
    pub fn connect<F, S, TE>(connect_future: F) -> DnsExchangeConnect<F, S, R, TE>
    where
        F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
        S: DnsRequestSender<DnsResponseFuture = R> + 'static + Send + Unpin,
        TE: Time + Unpin,
    {
        let (message_sender, outbound_messages) = unbounded();
        let message_sender = DnsRequestStreamHandle::<R>::new(message_sender);

        DnsExchangeConnect::connect(connect_future, outbound_messages, message_sender)
    }
}

impl<R> Clone for DnsExchange<R>
where
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<Resp> DnsHandle for DnsExchange<Resp>
where
    Resp: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    type Response = DnsExchangeSend<Resp>;

    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&mut self, request: R) -> Self::Response {
        DnsExchangeSend {
            result: self.sender.send(request),
            _sender: self.sender.clone(), // TODO: this shouldn't be necessary, currently the presence of Senders is what allows the background to track current users, it generally is dropped right after send, this makes sure that there is at least one active after send
        }
    }
}

/// A Future that will resolve to a Response after sending the request
#[must_use = "futures do nothing unless polled"]
pub struct DnsExchangeSend<R>
where
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    result: OneshotDnsResponseReceiver<R>,
    _sender: BufDnsRequestStreamHandle<R>,
}

impl<R> Future for DnsExchangeSend<R>
where
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    type Output = Result<DnsResponse, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        // as long as there is no result, poll the exchange
        self.result.poll_unpin(cx)
    }
}

/// This background future is responsible for driving all network operations for the DNS protocol.
///
/// It must be spawned before any DNS messages are sent.
#[must_use = "futures do nothing unless polled"]
pub struct DnsExchangeBackground<S, R, TE>
where
    S: DnsRequestSender<DnsResponseFuture = R> + 'static + Send + Unpin,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    io_stream: S,
    outbound_messages: Peekable<UnboundedReceiver<OneshotDnsRequest<R>>>,
    marker: PhantomData<TE>,
}

impl<S, R, TE> DnsExchangeBackground<S, R, TE>
where
    S: DnsRequestSender<DnsResponseFuture = R> + 'static + Send + Unpin,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    fn pollable_split(
        &mut self,
    ) -> (
        &mut S,
        &mut Peekable<UnboundedReceiver<OneshotDnsRequest<R>>>,
    ) {
        (&mut self.io_stream, &mut self.outbound_messages)
    }
}

impl<S, R, TE> Future for DnsExchangeBackground<S, R, TE>
where
    S: DnsRequestSender<DnsResponseFuture = R> + 'static + Send + Unpin,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
    TE: Time + Unpin,
{
    type Output = Result<(), ProtoError>;

    #[allow(clippy::unused_unit)]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
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
                    let (dns_request, serial_response): (DnsRequest, _) = dns_request.unwrap();

                    match serial_response
                        .send_response(io_stream.send_message::<TE>(dns_request, cx))
                    {
                        Ok(()) => (),
                        Err(_) => {
                            warn!("failed to associate send_message response to the sender");

                            return Poll::Ready(Err(
                                "failed to associate send_message response to the sender".into(),
                            ));
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
pub struct DnsExchangeConnect<F, S, R, TE>(DnsExchangeConnectInner<F, S, R, TE>)
where
    F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    S: DnsRequestSender<DnsResponseFuture = R> + 'static,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
    TE: Time + Unpin;

impl<F, S, R, TE> DnsExchangeConnect<F, S, R, TE>
where
    F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    S: DnsRequestSender<DnsResponseFuture = R> + 'static,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
    TE: Time + Unpin,
{
    fn connect(
        connect_future: F,
        outbound_messages: UnboundedReceiver<OneshotDnsRequest<R>>,
        sender: DnsRequestStreamHandle<R>,
    ) -> Self {
        DnsExchangeConnect(DnsExchangeConnectInner::Connecting {
            connect_future,
            outbound_messages: Some(outbound_messages),
            sender: Some(sender),
        })
    }
}

#[allow(clippy::type_complexity)]
impl<F, S, R, TE> Future for DnsExchangeConnect<F, S, R, TE>
where
    F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    S: DnsRequestSender<DnsResponseFuture = R> + 'static + Send + Unpin,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
    TE: Time + Unpin,
{
    type Output = Result<(DnsExchange<R>, DnsExchangeBackground<S, R, TE>), ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.0.poll_unpin(cx)
    }
}

enum DnsExchangeConnectInner<F, S, R, TE>
where
    F: Future<Output = Result<S, ProtoError>> + 'static + Send,
    S: DnsRequestSender<DnsResponseFuture = R> + 'static + Send,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
    TE: Time + Unpin,
{
    Connecting {
        connect_future: F,
        outbound_messages: Option<UnboundedReceiver<OneshotDnsRequest<R>>>,
        sender: Option<DnsRequestStreamHandle<R>>,
    },
    Connected {
        exchange: DnsExchange<R>,
        background: Option<DnsExchangeBackground<S, R, TE>>,
    },
    FailAll {
        error: ProtoError,
        outbound_messages: UnboundedReceiver<OneshotDnsRequest<R>>,
    },
}

#[allow(clippy::type_complexity)]
impl<F, S, R, TE> Future for DnsExchangeConnectInner<F, S, R, TE>
where
    F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    S: DnsRequestSender<DnsResponseFuture = R> + 'static + Send + Unpin,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
    TE: Time + Unpin,
{
    type Output = Result<(DnsExchange<R>, DnsExchangeBackground<S, R, TE>), ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            let next;
            match *self {
                DnsExchangeConnectInner::Connecting {
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

                            next = DnsExchangeConnectInner::Connected {
                                exchange,
                                background: Some(background),
                            };
                        }
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => {
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
                DnsExchangeConnectInner::Connected {
                    ref exchange,
                    ref mut background,
                } => {
                    let exchange = exchange.clone();
                    let background = background.take().expect("cannot poll after complete");

                    return Poll::Ready(Ok((exchange, background)));
                }
                DnsExchangeConnectInner::FailAll {
                    ref error,
                    ref mut outbound_messages,
                } => {
                    while let Some(outbound_message) = match outbound_messages.poll_next_unpin(cx) {
                        Poll::Ready(opt) => opt,
                        Poll::Pending => return Poll::Pending,
                    } {
                        let response = S::error_response::<TE>(error.clone());
                        // ignoring errors... best effort send...
                        outbound_message.unwrap().1.send_response(response).ok();
                    }

                    return Poll::Ready(Err(error.clone()));
                }
            }

            *self = next;
        }
    }
}
