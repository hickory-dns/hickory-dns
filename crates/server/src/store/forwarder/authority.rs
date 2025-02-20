// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io;

use hickory_resolver::{
    config::ResolveHosts,
    name_server::{ConnectionProvider, TokioConnectionProvider},
};
use tracing::{debug, info};

#[cfg(feature = "__dnssec")]
use crate::{authority::Nsec3QueryInfo, dnssec::NxProofKind};
use crate::{
    authority::{
        Authority, LookupControlFlow, LookupError, LookupObject, LookupOptions, MessageRequest,
        UpdateResult, ZoneType,
    },
    proto::{
        op::ResponseCode,
        rr::{LowerName, Name, Record, RecordType},
    },
    resolver::{Resolver, config::ResolverConfig, lookup::Lookup as ResolverLookup},
    server::RequestInfo,
    store::forwarder::ForwardConfig,
};

/// An authority that will forward resolutions to upstream resolvers.
///
/// This uses the hickory-resolver crate for resolving requests.
pub struct ForwardAuthority<P: ConnectionProvider = TokioConnectionProvider> {
    origin: LowerName,
    resolver: Resolver<P>,
}

impl<P: ConnectionProvider> ForwardAuthority<P> {
    #[doc(hidden)]
    pub fn new(runtime: P) -> Result<Self, String> {
        let resolver = Resolver::from_system_conf(runtime)
            .map_err(|e| format!("error constructing new Resolver: {e}"))?;

        Ok(Self {
            origin: Name::root().into(),
            resolver,
        })
    }

    /// Read the Authority for the origin from the specified configuration
    pub fn try_from_runtime(
        origin: Name,
        _zone_type: ZoneType,
        config: &ForwardConfig,
        runtime: P,
    ) -> Result<Self, String> {
        info!("loading forwarder config: {}", origin);

        let name_servers = config.name_servers.clone();
        let mut options = config.options.clone().unwrap_or_default();

        // See RFC 1034, Section 4.3.2:
        // "If the data at the node is a CNAME, and QTYPE doesn't match
        // CNAME, copy the CNAME RR into the answer section of the response,
        // change QNAME to the canonical name in the CNAME RR, and go
        // back to step 1."
        //
        // Essentially, it's saying that servers (including forwarders)
        // should emit any found CNAMEs in a response ("copy the CNAME
        // RR into the answer section"). This is the behavior that
        // preserve_intermediates enables when set to true, and disables
        // when set to false. So we set it to true.
        if !options.preserve_intermediates {
            tracing::warn!(
                "preserve_intermediates set to false, which is invalid \
                for a forwarder; switching to true"
            );
            options.preserve_intermediates = true;
        }

        // Require people to explicitly request for /etc/hosts usage in forwarder
        // configs
        if options.use_hosts_file == ResolveHosts::Auto {
            options.use_hosts_file = ResolveHosts::Never;
        }

        let config = ResolverConfig::from_parts(None, vec![], name_servers);

        let resolver = Resolver::new(config, options, runtime);

        info!("forward resolver configured: {}: ", origin);

        // TODO: this might be infallible?
        Ok(Self {
            origin: origin.into(),
            resolver,
        })
    }
}

impl ForwardAuthority<TokioConnectionProvider> {
    /// Read the Authority for the origin from the specified configuration
    pub fn try_from_config(
        origin: Name,
        zone_type: ZoneType,
        config: &ForwardConfig,
    ) -> Result<Self, String> {
        Self::try_from_runtime(
            origin,
            zone_type,
            config,
            TokioConnectionProvider::default(),
        )
    }
}

#[async_trait::async_trait]
impl<P: ConnectionProvider> Authority for ForwardAuthority<P> {
    type Lookup = ForwardLookup;

    /// Always External
    fn zone_type(&self) -> ZoneType {
        ZoneType::External
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
    ) -> LookupControlFlow<Self::Lookup> {
        // TODO: make this an error?
        debug_assert!(self.origin.zone_of(name));

        debug!("forwarding lookup: {} {}", name, rtype);

        // Ignore FQDN when we forward DNS queries. Without this we can't look
        // up addresses from system hosts file.
        let mut name: Name = name.clone().into();
        name.set_fqdn(false);

        use LookupControlFlow::*;
        match self.resolver.lookup(name, rtype).await {
            Ok(lookup) => Continue(Ok(ForwardLookup(lookup))),
            Err(e) => Continue(Err(LookupError::from(e))),
        }
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        self.lookup(
            request_info.query.name(),
            request_info.query.query_type(),
            lookup_options,
        )
        .await
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        LookupControlFlow::Continue(Err(LookupError::from(io::Error::new(
            io::ErrorKind::Other,
            "Getting NSEC records is unimplemented for the forwarder",
        ))))
    }

    #[cfg(feature = "__dnssec")]
    async fn get_nsec3_records(
        &self,
        _info: Nsec3QueryInfo<'_>,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        LookupControlFlow::Continue(Err(LookupError::from(io::Error::new(
            io::ErrorKind::Other,
            "getting NSEC3 records is unimplemented for the forwarder",
        ))))
    }

    #[cfg(feature = "__dnssec")]
    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        None
    }
}

/// A structure that holds the results of a forwarding lookup.
///
/// This exposes an iterator interface for consumption downstream.
pub struct ForwardLookup(pub ResolverLookup);

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
