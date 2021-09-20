// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io;

use log::{debug, info};

use crate::{
    authority::{
        Authority, LookupError, LookupObject, LookupOptions, MessageRequest, UpdateResult, ZoneType,
    },
    client::{
        op::{LowerQuery, ResponseCode},
        rr::{LowerName, Name, Record, RecordType},
    },
    resolver::{
        config::ResolverConfig, lookup::Lookup as ResolverLookup, TokioAsyncResolver, TokioHandle,
    },
    store::forwarder::ForwardConfig,
};

/// An authority that will forward resolutions to upstream resolvers.
///
/// This uses the trust-dns-resolver for resolving requests.
pub struct ForwardAuthority {
    origin: LowerName,
    resolver: TokioAsyncResolver,
}

impl ForwardAuthority {
    /// TODO: change this name to create or something
    #[allow(clippy::new_without_default)]
    #[doc(hidden)]
    pub async fn new(runtime: TokioHandle) -> Result<Self, String> {
        let resolver = TokioAsyncResolver::from_system_conf(runtime)
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

        let resolver = TokioAsyncResolver::new(config, options, TokioHandle)
            .map_err(|e| format!("error constructing new Resolver: {}", e))?;

        info!("forward resolver configured: {}: ", origin);

        // TODO: this might be infallible?
        Ok(ForwardAuthority {
            origin: origin.into(),
            resolver,
        })
    }
}

#[async_trait::async_trait]
impl Authority for ForwardAuthority {
    type Lookup = ForwardLookup;

    /// Always Forward
    fn zone_type(&self) -> ZoneType {
        ZoneType::Forward
    }

    /// Always false for Forward zones
    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
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
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        // TODO: make this an error?
        debug_assert!(self.origin.zone_of(name));

        debug!("forwarding lookup: {} {}", name, rtype);
        let name: LowerName = name.clone();
        let resolve = self.resolver.lookup(name, rtype, Default::default()).await;

        resolve.map(ForwardLookup).map_err(LookupError::from)
    }

    async fn search(
        &self,
        query: &LowerQuery,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        self.lookup(query.name(), query.query_type(), lookup_options)
            .await
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        Err(LookupError::from(io::Error::new(
            io::ErrorKind::Other,
            "Getting NSEC records is unimplemented for the forwarder",
        )))
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
