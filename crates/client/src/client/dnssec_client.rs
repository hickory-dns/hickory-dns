// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use futures_util::stream::Stream;

use crate::client::Client;
use crate::proto::ProtoError;
use crate::proto::dnssec::DnssecDnsHandle;
use crate::proto::dnssec::TrustAnchors;
use crate::proto::op::{DnsRequest, DnsResponse};
use crate::proto::runtime::{TokioRuntimeProvider, TokioTime};
use crate::proto::xfer::{DnsExchangeBackground, DnsHandle, DnsRequestSender};

/// A DNSSEC Client implemented over futures-rs.
///
/// This Client is generic and capable of wrapping UDP, TCP, and other underlying DNS protocol
///  implementations.
pub struct DnssecClient {
    client: DnssecDnsHandle<Client<TokioRuntimeProvider>>,
}

impl DnssecClient {
    /// Returns a DNSSEC verifying client with a TrustAnchor that can be replaced
    pub fn builder<F, S>(connect_future: F) -> AsyncSecureClientBuilder<F>
    where
        F: Future<Output = Result<S, io::Error>> + 'static + Send + Unpin,
        S: DnsRequestSender + 'static,
    {
        AsyncSecureClientBuilder {
            connect_future,
            trust_anchor: None,
        }
    }

    /// Returns a DNSSEC verifying client with the default TrustAnchor
    pub async fn connect<F, S>(
        connect_future: F,
    ) -> Result<(Self, DnsExchangeBackground<S, TokioTime>), io::Error>
    where
        S: DnsRequestSender,
        F: Future<Output = Result<S, io::Error>> + 'static + Send + Unpin,
    {
        Self::builder(connect_future).build().await
    }

    fn from_client(client: Client<TokioRuntimeProvider>, trust_anchor: Arc<TrustAnchors>) -> Self {
        Self {
            client: DnssecDnsHandle::with_trust_anchor(client, trust_anchor),
        }
    }
}

impl Clone for DnssecClient {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
        }
    }
}

impl DnsHandle for DnssecClient {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send + 'static>>;
    type Runtime = TokioRuntimeProvider;

    fn send(&self, request: DnsRequest) -> Self::Response {
        self.client.send(request)
    }
}

/// A builder to allow a custom trust to be used for validating all signed records
pub struct AsyncSecureClientBuilder<F> {
    connect_future: F,
    trust_anchor: Option<TrustAnchors>,
}

impl<F, S> AsyncSecureClientBuilder<F>
where
    F: Future<Output = Result<S, io::Error>> + 'static + Send + Unpin,
    S: DnsRequestSender + 'static,
{
    /// This variant allows for the trust_anchor to be replaced
    ///
    /// # Arguments
    ///
    /// * `trust_anchor` - the set of trusted DNSKEY public_keys, by default this only contains the
    ///   root public_key.
    pub fn trust_anchor(mut self, trust_anchor: TrustAnchors) -> Self {
        self.trust_anchor = Some(trust_anchor);
        self
    }

    /// Construct the new client
    pub async fn build(
        mut self,
    ) -> Result<(DnssecClient, DnsExchangeBackground<S, TokioTime>), io::Error> {
        let trust_anchor = Arc::new(self.trust_anchor.take().unwrap_or_default());
        let result = Client::connect(self.connect_future).await;

        result.map(|(client, bg)| (DnssecClient::from_client(client, trust_anchor), bg))
    }
}
