// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! This module contains all the types for demuxing DNS oriented streams.

use alloc::string::ToString;
use core::future::Future;
use core::marker::PhantomData;
use core::mem;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::io;

use futures_channel::mpsc;
use futures_util::{
    future::{BoxFuture, FutureExt},
    stream::{Peekable, Stream, StreamExt},
};
use tracing::debug;

#[cfg(all(feature = "__https", feature = "tokio"))]
use crate::h2::{HttpsClientConnect, HttpsClientStream};
#[cfg(all(feature = "__h3", feature = "tokio"))]
use crate::h3::{H3ClientConnect, H3ClientStream};
use crate::op::{DnsRequest, DnsResponse};
#[cfg(all(feature = "__quic", feature = "tokio"))]
use crate::quic::{QuicClientConnect, QuicClientStream};
use crate::runtime::RuntimeProvider;
#[cfg(feature = "std")]
use crate::runtime::Time;
#[cfg(feature = "__tls")]
use crate::rustls::TlsClientStream;
use crate::tcp::TcpClientStream;
use crate::udp::{UdpClientConnect, UdpClientStream};
#[cfg(any(feature = "std", feature = "no-std-rand"))]
use crate::xfer::dns_handle::DnsHandle;
use crate::xfer::{
    BufDnsRequestStreamHandle, CHANNEL_BUFFER_SIZE, DnsRequestSender, OneshotDnsRequest,
};
use crate::xfer::{DnsMultiplexerConnect, DnsResponseReceiver};
use crate::{DnsMultiplexer, error::*};

/// The variants of all supported connections for a `DnsExchange`.
#[allow(missing_docs, clippy::large_enum_variant, clippy::type_complexity)]
#[non_exhaustive]
pub enum Connecting<P: RuntimeProvider> {
    Udp(DnsExchangeConnect<UdpClientConnect<P>, UdpClientStream<P>, P>),
    Tcp(
        DnsExchangeConnect<
            DnsMultiplexerConnect<
                BoxFuture<'static, Result<TcpClientStream<P::Tcp>, io::Error>>,
                TcpClientStream<<P as RuntimeProvider>::Tcp>,
            >,
            DnsMultiplexer<TcpClientStream<<P as RuntimeProvider>::Tcp>>,
            P,
        >,
    ),
    #[cfg(feature = "__tls")]
    Tls(
        DnsExchangeConnect<
            DnsMultiplexerConnect<
                BoxFuture<'static, Result<TlsClientStream<<P as RuntimeProvider>::Tcp>, io::Error>>,
                TlsClientStream<<P as RuntimeProvider>::Tcp>,
            >,
            DnsMultiplexer<TlsClientStream<<P as RuntimeProvider>::Tcp>>,
            P,
        >,
    ),
    #[cfg(all(feature = "__https", feature = "tokio"))]
    Https(DnsExchangeConnect<HttpsClientConnect<P>, HttpsClientStream, P>),
    #[cfg(all(feature = "__quic", feature = "tokio"))]
    Quic(DnsExchangeConnect<QuicClientConnect, QuicClientStream, P>),
    #[cfg(all(feature = "__h3", feature = "tokio"))]
    H3(DnsExchangeConnect<H3ClientConnect, H3ClientStream, P>),
}

/// This is a generic Exchange implemented over multiplexed DNS connection providers.
///
/// The underlying `DnsRequestSender` is expected to multiplex any I/O connections. DnsExchange assumes that the underlying stream is responsible for this.
#[must_use = "futures do nothing unless polled"]
pub struct DnsExchange<P> {
    sender: BufDnsRequestStreamHandle<P>,
}

impl<P: RuntimeProvider> DnsExchange<P> {
    /// Initializes a TcpStream with an existing tcp::TcpStream.
    ///
    /// This is intended for use with a TcpListener and Incoming.
    ///
    /// # Arguments
    ///
    /// * `stream` - the established IO stream for communication
    pub fn from_stream<S>(stream: S) -> (Self, DnsExchangeBackground<S, P::Timer>)
    where
        S: DnsRequestSender + 'static + Send + Unpin,
    {
        let (sender, outbound_messages) = mpsc::channel(CHANNEL_BUFFER_SIZE);
        let message_sender = BufDnsRequestStreamHandle {
            sender,
            _phantom: PhantomData,
        };

        Self::from_stream_with_receiver(stream, outbound_messages, message_sender)
    }

    /// Wraps a stream where a sender and receiver have already been established
    pub fn from_stream_with_receiver<S>(
        stream: S,
        receiver: mpsc::Receiver<OneshotDnsRequest>,
        sender: BufDnsRequestStreamHandle<P>,
    ) -> (Self, DnsExchangeBackground<S, P::Timer>)
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
    #[cfg(feature = "std")]
    pub fn connect<F, S>(connect_future: F) -> DnsExchangeConnect<F, S, P>
    where
        F: Future<Output = Result<S, io::Error>> + 'static + Send + Unpin,
        S: DnsRequestSender + 'static + Send + Unpin,
    {
        let (sender, outbound_messages) = mpsc::channel(CHANNEL_BUFFER_SIZE);
        let message_sender = BufDnsRequestStreamHandle {
            sender,
            _phantom: PhantomData,
        };

        DnsExchangeConnect::connect(connect_future, outbound_messages, message_sender)
    }

    /// Returns a future that returns an error immediately.
    pub fn error<F, S>(error: io::Error) -> DnsExchangeConnect<F, S, P>
    where
        F: Future<Output = Result<S, io::Error>> + 'static + Send + Unpin,
        S: DnsRequestSender + 'static + Send + Unpin,
    {
        DnsExchangeConnect(DnsExchangeConnectInner::Error(error))
    }
}

impl<P: Clone> Clone for DnsExchange<P> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

#[cfg(any(feature = "std", feature = "no-std-rand"))]
impl<P: RuntimeProvider> DnsHandle for DnsExchange<P> {
    type Response = DnsExchangeSend<P>;
    type Runtime = P;

    fn send(&self, request: DnsRequest) -> Self::Response {
        DnsExchangeSend {
            result: self.sender.send(request),
            _sender: self.sender.clone(), // TODO: this shouldn't be necessary, currently the presence of Senders is what allows the background to track current users, it generally is dropped right after send, this makes sure that there is at least one active after send
        }
    }
}

/// A Stream that will resolve to Responses after sending the request
#[must_use = "futures do nothing unless polled"]
pub struct DnsExchangeSend<P> {
    result: DnsResponseReceiver,
    _sender: BufDnsRequestStreamHandle<P>,
}

impl<P: Unpin> Stream for DnsExchangeSend<P> {
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
                Poll::Ready(Some(Err(error))) => {
                    debug!(
                        %error,
                        "io_stream hit an error, shutting down"
                    );

                    return Poll::Ready(Err(error));
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
                            debug!("failed to associate send_message response to the sender");
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
/// DnsExchangeConnect is cloneable, making it possible to share this if the connection
///  will be shared across threads.
///
/// The future will return a tuple of the DnsExchange (for sending messages) and a background
///  for running the background tasks. The background is optional as only one thread should run
///  the background. If returned, it must be spawned before any dns requests will function.
pub struct DnsExchangeConnect<F, S, P>(DnsExchangeConnectInner<F, S, P>)
where
    F: Future<Output = Result<S, io::Error>> + 'static + Send + Unpin,
    S: DnsRequestSender + 'static,
    P: RuntimeProvider;

impl<F, S, P> DnsExchangeConnect<F, S, P>
where
    F: Future<Output = Result<S, io::Error>> + 'static + Send + Unpin,
    S: DnsRequestSender + 'static,
    P: RuntimeProvider,
{
    fn connect(
        connect_future: F,
        outbound_messages: mpsc::Receiver<OneshotDnsRequest>,
        sender: BufDnsRequestStreamHandle<P>,
    ) -> Self {
        Self(DnsExchangeConnectInner::Connecting {
            connect_future,
            outbound_messages: Some(outbound_messages),
            sender: Some(sender),
        })
    }
}

impl<F, S, P> Future for DnsExchangeConnect<F, S, P>
where
    F: Future<Output = Result<S, io::Error>> + 'static + Send + Unpin,
    S: DnsRequestSender + 'static + Send + Unpin,
    P: RuntimeProvider,
{
    type Output = Result<(DnsExchange<P>, DnsExchangeBackground<S, P::Timer>), io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.poll_unpin(cx)
    }
}

#[allow(clippy::large_enum_variant)]
enum DnsExchangeConnectInner<F, S, P>
where
    F: Future<Output = Result<S, io::Error>> + 'static + Send,
    S: DnsRequestSender + 'static + Send,
    P: RuntimeProvider,
{
    Connecting {
        connect_future: F,
        outbound_messages: Option<mpsc::Receiver<OneshotDnsRequest>>,
        sender: Option<BufDnsRequestStreamHandle<P>>,
    },
    Connected {
        exchange: DnsExchange<P>,
        background: Option<DnsExchangeBackground<S, P::Timer>>,
    },
    FailAll {
        error: io::Error,
        outbound_messages: mpsc::Receiver<OneshotDnsRequest>,
    },
    Error(io::Error),
}

impl<F, S, P> Future for DnsExchangeConnectInner<F, S, P>
where
    F: Future<Output = Result<S, io::Error>> + 'static + Send + Unpin,
    S: DnsRequestSender + 'static + Send + Unpin,
    P: RuntimeProvider,
{
    type Output = Result<(DnsExchange<P>, DnsExchangeBackground<S, P::Timer>), io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let next;
            match &mut *self {
                Self::Connecting {
                    connect_future,
                    outbound_messages,
                    sender,
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
                            debug!(%error, "stream errored while connecting");
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
                    exchange,
                    background,
                } => {
                    let exchange = exchange.clone();
                    let background = background.take().expect("cannot poll after complete");

                    return Poll::Ready(Ok((exchange, background)));
                }
                Self::FailAll {
                    error,
                    outbound_messages,
                } => {
                    while let Some(outbound_message) = match outbound_messages.poll_next_unpin(cx) {
                        Poll::Ready(opt) => opt,
                        Poll::Pending => return Poll::Pending,
                    } {
                        // ignoring errors... best effort send...
                        let error =
                            ProtoError::from(io::Error::new(error.kind(), error.to_string()));
                        let _ = outbound_message
                            .into_parts()
                            .1
                            .send_response(error.clone().into());
                    }

                    return Poll::Ready(Err(mem::replace(error, io::Error::other("taken"))));
                }
                Self::Error(error) => {
                    return Poll::Ready(Err(mem::replace(error, io::Error::other("taken"))));
                }
            }

            *self = next;
        }
    }
}
