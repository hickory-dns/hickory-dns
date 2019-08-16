// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! This module contains all the types for demuxing DNS oriented streams.

use std::pin::Pin;
use std::task::Context;

use futures::stream::{Peekable, Stream, StreamExt};
use futures::{Future, FutureExt, Poll};
use futures::channel::mpsc::{unbounded, UnboundedReceiver};

use crate::error::*;
use crate::xfer::{DnsRequest, DnsRequestSender, DnsRequestStreamHandle, DnsResponse, OneshotDnsRequest};

/// This is a generic Exchange implemented over multiplexed DNS connection providers.
///
/// The underlying `DnsRequestSender` is expected to multiplex any I/O connections. DnsExchange assumes that the underlying stream is responsible for this.
#[must_use = "futures do nothing unless polled"]
pub struct DnsExchange<S, R>
where
    S: DnsRequestSender<DnsResponseFuture = R>,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send,
{
    io_stream: S,
    outbound_messages: Peekable<UnboundedReceiver<OneshotDnsRequest<R>>>,
}

impl<S, R> DnsExchange<S, R>
where
    S: DnsRequestSender<DnsResponseFuture = R>,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send,
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

    /// Wraps a stream where a sender and receiver have already been established
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
        F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    {
        let (message_sender, outbound_messages) = unbounded();
        (
            DnsExchangeConnect::connect(connect_future, outbound_messages),
            DnsRequestStreamHandle::<R>::new(message_sender),
        )
    }

    fn pollable_split(&mut self) -> (&mut S, &mut Peekable<UnboundedReceiver<OneshotDnsRequest<R>>>) {
        (&mut self.io_stream, &mut self.outbound_messages)
    }
}

impl<S, R> Future for DnsExchange<S, R>
where
    S: DnsRequestSender<DnsResponseFuture = R>,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send,
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
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(err)),
            }

            // then see if there is more to send
            match outbound_messages.as_mut().poll_next(cx)
            {
                // already handled above, here to make sure the poll() pops the next message
                Poll::Ready(Some(dns_request)) => {
                    // if there is no peer, this connection should die...
                    let (dns_request, serial_response): (DnsRequest, _) = dns_request.unwrap();

                    debug!("sending message via: {}", io_stream);

                    match serial_response.send_response(io_stream.send_message(dns_request)) {
                        Ok(()) => (),
                        Err(_) => {
                            warn!("failed to associate send_message response to the sender");
                            return Poll::Ready(Err(
                                "failed to associate send_message response to the sender".into()
                            ));
                        }
                    }
                }
                // On not ready, this is our time to return...
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    debug!("all handles closed, shutting down: {}", io_stream);
                    // if there is nothing that can use this connection to send messages, then this is done...
                    io_stream.shutdown();

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
    F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    S: DnsRequestSender<DnsResponseFuture = R>,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send;

impl<F, S, R> DnsExchangeConnect<F, S, R>
where
    F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    S: DnsRequestSender<DnsResponseFuture = R>,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send,
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
    F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    S: DnsRequestSender<DnsResponseFuture = R>,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send,
{
    type Output = Result<DnsExchange<S, R>, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.0.poll_unpin(cx)
    }
}

enum DnsExchangeConnectInner<F, S, R>
where
    F: Future<Output = Result<S, ProtoError>> + 'static + Send,
    S: DnsRequestSender<DnsResponseFuture = R>,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send,
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
    F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    S: DnsRequestSender<DnsResponseFuture = R>,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send,
{
    type Output = Result<DnsExchange<S, R>, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            let next;
            match *self {
                DnsExchangeConnectInner::Connecting {
                    ref mut connect_future,
                    ref mut outbound_messages,
                } => {
                    let connect_future = Pin::new(connect_future);
                    match connect_future.poll(cx) {
                        Poll::Ready(Ok(stream)) => {
                            debug!("connection established: {}", stream);
                            return Poll::Ready(Ok(DnsExchange::from_stream_with_receiver(
                                stream,
                                outbound_messages
                                    .take()
                                    .expect("cannot poll after complete"),
                            )));
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
                DnsExchangeConnectInner::FailAll {
                    ref error,
                    ref mut outbound_messages,
                } => {
                    while let Some(outbound_message) = match outbound_messages.poll_next_unpin(cx) {
                        Poll::Ready(opt) => opt,
                        Poll::Pending => return Poll::Pending,
                    } {
                        let response = S::error_response(error.clone());
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
