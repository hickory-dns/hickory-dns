// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(feature = "resolver")]

//! Forwarding resolver related types

use std::io;
#[cfg(feature = "__dnssec")]
use std::sync::Arc;

use serde::Deserialize;
use tracing::{debug, info};

#[cfg(feature = "metrics")]
use crate::store::metrics::QueryStoreMetrics;
#[cfg(feature = "__dnssec")]
use crate::{authority::Nsec3QueryInfo, dnssec::NxProofKind, proto::dnssec::TrustAnchors};
use crate::{
    authority::{
        Authority, LookupControlFlow, LookupError, LookupObject, LookupOptions, MessageRequest,
        UpdateResult, ZoneType,
    },
    proto::{
        op::ResponseCode,
        rr::{LowerName, Name, Record, RecordType},
    },
    resolver::{
        Resolver,
        config::{NameServerConfigGroup, ResolveHosts, ResolverConfig, ResolverOpts},
        lookup::Lookup as ResolverLookup,
        name_server::{ConnectionProvider, TokioConnectionProvider},
    },
    server::RequestInfo,
};

/// A builder to construct a [`ForwardAuthority`].
///
/// Created by [`ForwardAuthority::builder`].
pub struct ForwardAuthorityBuilder<P: ConnectionProvider> {
    origin: Name,
    config: ForwardConfig,
    domain: Option<Name>,
    search: Vec<Name>,
    runtime: P,

    #[cfg(feature = "__dnssec")]
    trust_anchor: Option<Arc<TrustAnchors>>,
}

impl<P: ConnectionProvider> ForwardAuthorityBuilder<P> {
    /// Set the origin of the authority.
    pub fn with_origin(mut self, origin: Name) -> Self {
        self.origin = origin;
        self
    }

    /// Enables DNSSEC validation, and sets the DNSSEC trust anchors to be used by the forward
    /// authority.
    ///
    /// This overrides the trust anchor path in the `ResolverOpts`.
    #[cfg(feature = "__dnssec")]
    pub fn with_trust_anchor(mut self, trust_anchor: Arc<TrustAnchors>) -> Self {
        self.trust_anchor = Some(trust_anchor);
        self
    }

    /// Returns a mutable reference to the [`ResolverOpts`].
    pub fn options_mut(&mut self) -> &mut ResolverOpts {
        self.config
            .options
            .get_or_insert_with(ResolverOpts::default)
    }

    /// Set the system domain name.
    pub fn with_domain(mut self, domain: Name) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Set the search domains.
    pub fn with_search(mut self, search: Vec<Name>) -> Self {
        self.search = search;
        self
    }

    /// Construct the authority.
    pub fn build(self) -> Result<ForwardAuthority<P>, String> {
        let Self {
            origin,
            config,
            domain,
            search,
            runtime,
            #[cfg(feature = "__dnssec")]
            trust_anchor,
        } = self;
        info!(%origin, "loading forwarder config");

        let name_servers = config.name_servers;
        let mut options = config.options.unwrap_or_default();

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

        let config = ResolverConfig::from_parts(domain, search, name_servers);

        let mut resolver_builder = Resolver::builder_with_config(config, runtime);

        #[cfg(feature = "__dnssec")]
        match (trust_anchor, &options.trust_anchor) {
            (Some(trust_anchor), _) => {
                resolver_builder = resolver_builder.with_trust_anchor(trust_anchor);
                options.validate = true;
            }
            (None, Some(path)) => {
                let trust_anchor = TrustAnchors::from_file(path).map_err(|err| err.to_string())?;
                resolver_builder = resolver_builder.with_trust_anchor(Arc::new(trust_anchor));
                options.validate = true;
            }
            (None, None) => {}
        }

        *resolver_builder.options_mut() = options;
        let resolver = resolver_builder.build();

        info!(%origin, "forward resolver configured");

        Ok(ForwardAuthority {
            origin: origin.into(),
            resolver,
            #[cfg(feature = "metrics")]
            metrics: QueryStoreMetrics::new("forwarder"),
        })
    }
}

/// An authority that will forward resolutions to upstream resolvers.
///
/// This uses the hickory-resolver crate for resolving requests.
pub struct ForwardAuthority<P: ConnectionProvider = TokioConnectionProvider> {
    origin: LowerName,
    resolver: Resolver<P>,
    #[cfg(feature = "metrics")]
    metrics: QueryStoreMetrics,
}

impl<P: ConnectionProvider> ForwardAuthority<P> {
    /// Construct a new [`ForwardAuthority`] via [`ForwardAuthorityBuilder`], using the operating
    /// system's resolver configuration.
    pub fn builder(runtime: P) -> Result<ForwardAuthorityBuilder<P>, String> {
        let (resolver_config, options) = hickory_resolver::system_conf::read_system_conf()
            .map_err(|e| format!("error reading system configuration: {e}"))?;
        let forward_config = ForwardConfig {
            name_servers: resolver_config.name_servers().to_vec().into(),
            options: Some(options),
        };
        let mut builder = Self::builder_with_config(forward_config, runtime);
        if let Some(domain) = resolver_config.domain() {
            builder = builder.with_domain(domain.clone());
        }
        builder = builder.with_search(resolver_config.search().to_vec());
        Ok(builder)
    }

    /// Construct a new [`ForwardAuthority`] via [`ForwardAuthorityBuilder`] with the provided configuration.
    pub fn builder_with_config(config: ForwardConfig, runtime: P) -> ForwardAuthorityBuilder<P> {
        ForwardAuthorityBuilder {
            origin: Name::root(),
            config,
            domain: None,
            search: vec![],
            runtime,
            #[cfg(feature = "__dnssec")]
            trust_anchor: None,
        }
    }
}

impl ForwardAuthority<TokioConnectionProvider> {
    /// Construct a new [`ForwardAuthority`] via [`ForwardAuthorityBuilder`] with the provided configuration.
    pub fn builder_tokio(
        config: ForwardConfig,
    ) -> ForwardAuthorityBuilder<TokioConnectionProvider> {
        Self::builder_with_config(config, TokioConnectionProvider::default())
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

    /// Whether the authority can perform DNSSEC validation
    fn can_validate_dnssec(&self) -> bool {
        self.resolver.options().validate
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
        let lookup = match self.resolver.lookup(name, rtype).await {
            Ok(lookup) => Continue(Ok(ForwardLookup(lookup))),
            Err(e) => Continue(Err(LookupError::from(e))),
        };

        #[cfg(feature = "metrics")]
        self.metrics.increment_lookup(&lookup);

        lookup
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

/// Configuration for file based zones
#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ForwardConfig {
    /// upstream name_server configurations
    pub name_servers: NameServerConfigGroup,
    /// Resolver options
    pub options: Option<ResolverOpts>,
}
