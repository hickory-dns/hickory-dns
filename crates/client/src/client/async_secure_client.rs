// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use futures_util::stream::Stream;

use crate::client::AsyncClient;
use crate::proto::error::ProtoError;
use crate::proto::rr::dnssec::TrustAnchor;
use crate::proto::xfer::{
    DnsExchangeBackground, DnsHandle, DnsRequest, DnsRequestSender, DnsResponse,
};
use crate::proto::DnssecDnsHandle;
use crate::proto::TokioTime;

/// A DNSSEC Client implemented over futures-rs.
///
/// This Client is generic and capable of wrapping UDP, TCP, and other underlying DNS protocol
///  implementations.
pub struct AsyncDnssecClient {
    client: DnssecDnsHandle<AsyncClient>,
}

impl AsyncDnssecClient {
    /// Returns a DNSSEC verifying client with a TrustAnchor that can be replaced
    pub fn builder<F, S>(connect_future: F) -> AsyncSecureClientBuilder<F, S>
    where
        F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
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
    ) -> Result<(Self, DnsExchangeBackground<S, TokioTime>), ProtoError>
    where
        S: DnsRequestSender,
        F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    {
        Self::builder(connect_future).build().await
    }

    fn from_client(client: AsyncClient, trust_anchor: Arc<TrustAnchor>) -> Self {
        Self {
            client: DnssecDnsHandle::with_trust_anchor(client, trust_anchor),
        }
    }
}

impl Clone for AsyncDnssecClient {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
        }
    }
}

impl DnsHandle for AsyncDnssecClient {
    type Response = Pin<Box<(dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send + 'static)>>;

    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&self, request: R) -> Self::Response {
        self.client.send(request)
    }
}

/// A builder to allow a custom trust to be used for validating all signed records
#[cfg(feature = "dnssec")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
pub struct AsyncSecureClientBuilder<F, S>
where
    F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    S: DnsRequestSender + 'static,
{
    connect_future: F,
    trust_anchor: Option<TrustAnchor>,
}

#[cfg(feature = "dnssec")]
impl<F, S> AsyncSecureClientBuilder<F, S>
where
    F: Future<Output = Result<S, ProtoError>> + 'static + Send + Unpin,
    S: DnsRequestSender + 'static,
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

    /// Construct the new client
    pub async fn build(
        mut self,
    ) -> Result<(AsyncDnssecClient, DnsExchangeBackground<S, TokioTime>), ProtoError> {
        let trust_anchor = Arc::new(self.trust_anchor.take().unwrap_or_default());
        let result = AsyncClient::connect(self.connect_future).await;

        result.map(|(client, bg)| (AsyncDnssecClient::from_client(client, trust_anchor), bg))
    }
}
