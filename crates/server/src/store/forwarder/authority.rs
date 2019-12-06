// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{Future, FutureExt};

use trust_dns_client::op::LowerQuery;
use trust_dns_client::op::ResponseCode;
use trust_dns_client::rr::dnssec::SupportedAlgorithms;
use trust_dns_client::rr::{LowerName, Name, Record, RecordType};
use trust_dns_resolver::config::ResolverConfig;
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::lookup::Lookup as ResolverLookup;
use trust_dns_resolver::AsyncResolver;

use crate::authority::{
    Authority, LookupError, LookupObject, MessageRequest, UpdateResult, ZoneType,
};
use crate::store::forwarder::ForwardConfig;

/// An authority that will forward resolutions to upstream resolvers.
///
/// This uses the trust-dns-resolver for resolving requests.
pub struct ForwardAuthority {
    origin: LowerName,
    resolver: AsyncResolver,
}

impl ForwardAuthority {
    /// TODO: change this name to create or something
    #[allow(clippy::new_without_default)]
    #[doc(hidden)]
    pub async fn new() -> Result<Self, String> {
        let resolver = AsyncResolver::from_system_conf()
            .await
            .map_err(|e| format!("error constructing new Resolver: {}", e))?;

        Ok(ForwardAuthority {
            origin: Name::root().into(),
            resolver,
        })
    }

    /// Read the Authority for the origin from the specified configuration
    pub async fn try_from_config(
        origin: Name,
        _zone_type: ZoneType,
        config: &ForwardConfig,
    ) -> Result<Self, String> {
        info!("loading forwarder config: {}", origin);

        let name_servers = config.name_servers.clone();
        let options = config.options.unwrap_or_default();
        let config = ResolverConfig::from_parts(None, vec![], name_servers);

        let resolver = AsyncResolver::new(config, options)
            .await
            .map_err(|e| format!("error constructing new Resolver: {}", e))?;

        info!("forward resolver configured: {}: ", origin);

        // TODO: this might be infallible?
        Ok(ForwardAuthority {
            origin: origin.into(),
            resolver,
        })
    }
}

impl Authority for ForwardAuthority {
    type Lookup = ForwardLookup;
    type LookupFuture = Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>>;

    /// Always Forward
    fn zone_type(&self) -> ZoneType {
        ZoneType::Forward
    }

    /// Always false for Forward zones
    fn is_axfr_allowed(&self) -> bool {
        false
    }

    fn update(&mut self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    ///
    /// In the context of a forwarder, this is either a zone which this forwarder is associated,
    ///   or `.`, the root zone for all zones. If this is not the root zone, then it will only forward
    ///   for lookups which match the given zone name.
    fn origin(&self) -> &LowerName {
        &self.origin
    }

    /// Forwards a lookup given the resolver configuration for this Forwarded zone
    fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _is_secure: bool,
        _supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        // TODO: make this an error?
        assert!(self.origin.zone_of(name));

        info!("forwarding lookup: {} {}", name, rtype);
        let name: LowerName = name.clone();
        Box::pin(ForwardLookupFuture(self.resolver.lookup(
            name,
            rtype,
            Default::default(),
        )))
    }

    fn search(
        &self,
        query: &LowerQuery,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        Box::pin(self.lookup(
            query.name(),
            query.query_type(),
            is_secure,
            supported_algorithms,
        ))
    }

    #[allow(clippy::unimplemented)] // FIXME: this should return an error
    fn get_nsec_records(
        &self,
        _name: &LowerName,
        _is_secure: bool,
        _supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        unimplemented!()
    }
}

pub struct ForwardLookup(ResolverLookup);

impl LookupObject for ForwardLookup {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Record> + Send + 'a> {
        Box::new(self.0.record_iter())
    }

    fn take_additionals(&mut self) -> Option<Box<dyn LookupObject>> {
        None
    }
}

pub struct ForwardLookupFuture<
    F: Future<Output = Result<ResolverLookup, ResolveError>> + Send + Unpin + 'static,
>(F);

impl<F: Future<Output = Result<ResolverLookup, ResolveError>> + Send + Unpin> Future
    for ForwardLookupFuture<F>
{
    type Output = Result<ForwardLookup, LookupError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match self.0.poll_unpin(cx) {
            Poll::Ready(Ok(f)) => Poll::Ready(Ok(ForwardLookup(f))),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
        }
    }
}
