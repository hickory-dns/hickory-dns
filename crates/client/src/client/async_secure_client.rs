// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#![cfg(feature = "dnssec")]

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, Future, FutureExt};

use crate::client::{AsyncClient, AsyncClientConnect};
use crate::proto::error::ProtoError;
use crate::proto::rr::dnssec::TrustAnchor;
use crate::proto::xfer::{
    DnsExchangeBackground, DnsHandle, DnsRequest, DnsRequestSender, DnsResponse,
};
use crate::proto::SecureDnsHandle;

// FIXME: rename to AsyncDnsSecClient
/// A DNSSEC Client implemented over futures-rs.
///
/// This Client is generic and capable of wrapping UDP, TCP, and other underlying DNS protocol
///  implementations.
pub struct AsyncSecureClient<R>
where
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
    // FIXME: add memoizer here, to reduce # of requests
{
    client: SecureDnsHandle<AsyncClient<R>>,
}

impl<R> AsyncSecureClient<R>
where
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    /// Returns a DNSSEC verifying client with a TrustAnchor that can be replaced
    pub fn builder<F, S>(connect_future: F) -> AsyncSecureClientBuilder<F, S, R>
    where
        F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
        S: DnsRequestSender<DnsResponseFuture = R> + 'static,
    {
        let client_connect = AsyncClient::connect(connect_future);
        AsyncSecureClientBuilder {
            client_connect,
            trust_anchor: None,
        }
    }

    /// Returns a DNSSEC verifying client with the default TrustAnchor
    pub fn connect<F, S>(connect_future: F) -> AsyncSecureClientConnect<F, S, R>
    where
        F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
        S: DnsRequestSender<DnsResponseFuture = R> + 'static,
    {
        Self::builder(connect_future).build()
    }

    fn from_client(client: AsyncClient<R>, trust_anchor: TrustAnchor) -> Self {
        Self {
            client: SecureDnsHandle::with_trust_anchor(client, trust_anchor),
        }
    }
}

impl<R> Clone for AsyncSecureClient<R>
where
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    fn clone(&self) -> Self {
        AsyncSecureClient {
            client: self.client.clone(),
        }
    }
}

impl<Resp> DnsHandle for AsyncSecureClient<Resp>
where
    Resp: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    type Response =
        Pin<Box<(dyn Future<Output = Result<DnsResponse, ProtoError>> + Send + 'static)>>;

    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&mut self, request: R) -> Self::Response {
        self.client.send(request)
    }
}

/// A builder to allow a custom trust to be used for validating all signed records
#[cfg(feature = "dnssec")]
pub struct AsyncSecureClientBuilder<F, S, R>
where
    F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    S: DnsRequestSender<DnsResponseFuture = R> + 'static,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    client_connect: AsyncClientConnect<F, S, R>,
    trust_anchor: Option<TrustAnchor>,
}

#[cfg(feature = "dnssec")]
impl<F, S, R> AsyncSecureClientBuilder<F, S, R>
where
    F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    S: DnsRequestSender<DnsResponseFuture = R> + 'static,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    /// This variant allows for the trust_anchor to be replaced
    ///
    /// # Arguments
    ///
    /// * `trust_anchor` - the set of trusted DNSKEY public_keys, by default this only contains the
    ///                    root public_key.
    pub fn trust_anchor(mut self, trust_anchor: TrustAnchor) -> Self {
        self.trust_anchor = Some(trust_anchor);
        self
    }

    /// Construct the new client connect
    pub fn build(mut self) -> AsyncSecureClientConnect<F, S, R> {
        let trust_anchor = if let Some(trust_anchor) = self.trust_anchor.take() {
            trust_anchor
        } else {
            TrustAnchor::default()
        };

        AsyncSecureClientConnect {
            client_connect: self.client_connect,
            trust_anchor: Some(trust_anchor),
        }
    }
}

/// A future which will resolve to a AsyncSecureClient
#[must_use = "futures do nothing unless polled"]
pub struct AsyncSecureClientConnect<F, S, R>
where
    F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    S: DnsRequestSender<DnsResponseFuture = R> + 'static,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    client_connect: AsyncClientConnect<F, S, R>,
    trust_anchor: Option<TrustAnchor>,
}

#[allow(clippy::type_complexity)]
impl<F, S, R> Future for AsyncSecureClientConnect<F, S, R>
where
    F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    S: DnsRequestSender<DnsResponseFuture = R> + 'static + Send + Unpin,
    R: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
{
    type Output = Result<(AsyncSecureClient<R>, Option<DnsExchangeBackground<S, R>>), ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let result = ready!(self.client_connect.poll_unpin(cx));
        let trust_anchor = self
            .trust_anchor
            .take()
            .expect("TrustAnchor is None, was the future already complete?");

        let client_background =
            result.map(|(client, bg)| (AsyncSecureClient::from_client(client, trust_anchor), bg));
        Poll::Ready(client_background)
    }
}
