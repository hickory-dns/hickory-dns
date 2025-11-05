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

#[cfg(feature = "__dnssec")]
use crate::{dnssec::NxProofKind, proto::dnssec::TrustAnchors, zone_handler::Nsec3QueryInfo};
use crate::{
    proto::{
        op::ResponseSigner,
        rr::{LowerName, Name, RecordType},
        runtime::TokioRuntimeProvider,
    },
    resolver::{
        ConnectionProvider, Resolver,
        config::{NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts},
    },
    server::{Request, RequestInfo},
    zone_handler::{
        AuthLookup, AxfrPolicy, LookupControlFlow, LookupError, LookupOptions, ZoneHandler,
        ZoneType,
    },
};

/// A builder to construct a [`ForwardZoneHandler`].
///
/// Created by [`ForwardZoneHandler::builder`].
pub struct ForwardZoneHandlerBuilder<P: ConnectionProvider> {
    origin: Name,
    config: ForwardConfig,
    domain: Option<Name>,
    search: Vec<Name>,
    runtime: P,

    #[cfg(feature = "__dnssec")]
    trust_anchor: Option<Arc<TrustAnchors>>,
}

impl<P: ConnectionProvider> ForwardZoneHandlerBuilder<P> {
    /// Set the origin of the zone handler.
    pub fn with_origin(mut self, origin: Name) -> Self {
        self.origin = origin;
        self
    }

    /// Enables DNSSEC validation, and sets the DNSSEC trust anchors to be used by the forward
    /// zone handler.
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

    /// Construct the zone handler.
    pub fn build(self) -> Result<ForwardZoneHandler<P>, String> {
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
            }
            (None, Some(path)) => {
                let trust_anchor = TrustAnchors::from_file(path).map_err(|err| err.to_string())?;
                resolver_builder = resolver_builder.with_trust_anchor(Arc::new(trust_anchor));
            }
            (None, None) => {}
        }

        *resolver_builder.options_mut() = options;
        let resolver = resolver_builder.build().map_err(|err| err.to_string())?;

        info!(%origin, "forward resolver configured");

        Ok(ForwardZoneHandler {
            origin: origin.into(),
            resolver,
        })
    }
}

/// A zone handler that will forward resolutions to upstream resolvers.
///
/// This uses the hickory-resolver crate for resolving requests.
pub struct ForwardZoneHandler<P: ConnectionProvider = TokioRuntimeProvider> {
    origin: LowerName,
    resolver: Resolver<P>,
}

impl<P: ConnectionProvider> ForwardZoneHandler<P> {
    /// Construct a new [`ForwardZoneHandler`] via [`ForwardZoneHandlerBuilder`], using the operating
    /// system's resolver configuration.
    pub fn builder(runtime: P) -> Result<ForwardZoneHandlerBuilder<P>, String> {
        let (resolver_config, options) = hickory_resolver::system_conf::read_system_conf()
            .map_err(|e| format!("error reading system configuration: {e}"))?;
        let forward_config = ForwardConfig {
            name_servers: resolver_config.name_servers().to_owned(),
            options: Some(options),
        };
        let mut builder = Self::builder_with_config(forward_config, runtime);
        if let Some(domain) = resolver_config.domain() {
            builder = builder.with_domain(domain.clone());
        }
        builder = builder.with_search(resolver_config.search().to_vec());
        Ok(builder)
    }

    /// Construct a new [`ForwardZoneHandler`] via [`ForwardZoneHandlerBuilder`] with the provided configuration.
    pub fn builder_with_config(config: ForwardConfig, runtime: P) -> ForwardZoneHandlerBuilder<P> {
        ForwardZoneHandlerBuilder {
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

impl ForwardZoneHandler<TokioRuntimeProvider> {
    /// Construct a new [`ForwardZoneHandler`] via [`ForwardZoneHandlerBuilder`] with the provided configuration.
    pub fn builder_tokio(config: ForwardConfig) -> ForwardZoneHandlerBuilder<TokioRuntimeProvider> {
        Self::builder_with_config(config, TokioRuntimeProvider::default())
    }
}

#[async_trait::async_trait]
impl<P: ConnectionProvider> ZoneHandler for ForwardZoneHandler<P> {
    /// Always External
    fn zone_type(&self) -> ZoneType {
        ZoneType::External
    }

    /// AXFR requests are always denied for Forward zones
    fn axfr_policy(&self) -> AxfrPolicy {
        AxfrPolicy::Deny
    }

    /// Whether the zone handler can perform DNSSEC validation
    fn can_validate_dnssec(&self) -> bool {
        #[cfg(feature = "__dnssec")]
        {
            self.resolver.options().validate
        }
        #[cfg(not(feature = "__dnssec"))]
        {
            false
        }
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
        _request_info: Option<&RequestInfo<'_>>,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        // TODO: make this an error?
        debug_assert!(self.origin.zone_of(name));

        debug!("forwarding lookup: {} {}", name, rtype);

        // Ignore FQDN when we forward DNS queries. Without this we can't look
        // up addresses from system hosts file.
        let mut name: Name = name.clone().into();
        name.set_fqdn(false);

        use LookupControlFlow::*;
        match self.resolver.lookup(name, rtype).await {
            Ok(lookup) => Continue(Ok(AuthLookup::from(lookup))),
            Err(e) => Continue(Err(LookupError::from(e))),
        }
    }

    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (
        LookupControlFlow<AuthLookup>,
        Option<Box<dyn ResponseSigner>>,
    ) {
        let request_info = match request.request_info() {
            Ok(info) => info,
            Err(e) => return (LookupControlFlow::Break(Err(e)), None),
        };
        (
            self.lookup(
                request_info.query.name(),
                request_info.query.query_type(),
                Some(&request_info),
                lookup_options,
            )
            .await,
            None,
        )
    }

    async fn nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        LookupControlFlow::Continue(Err(LookupError::from(io::Error::other(
            "Getting NSEC records is unimplemented for the forwarder",
        ))))
    }

    #[cfg(feature = "__dnssec")]
    async fn nsec3_records(
        &self,
        _info: Nsec3QueryInfo<'_>,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        LookupControlFlow::Continue(Err(LookupError::from(io::Error::other(
            "getting NSEC3 records is unimplemented for the forwarder",
        ))))
    }

    #[cfg(feature = "__dnssec")]
    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        None
    }

    #[cfg(feature = "metrics")]
    fn metrics_label(&self) -> &'static str {
        "forwarder"
    }
}

/// Configuration for forwarder zones
#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ForwardConfig {
    /// upstream name_server configurations
    pub name_servers: Vec<NameServerConfig>,
    /// Resolver options
    pub options: Option<ResolverOpts>,
}
