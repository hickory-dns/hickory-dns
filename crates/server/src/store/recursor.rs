// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(feature = "recursor")]

//! Recursive resolver related types

use std::{io, path::Path, time::Instant};

use hickory_resolver::recursor::RecursiveConfig;
use tracing::{debug, info};

#[cfg(all(feature = "toml", any(feature = "__tls", feature = "__quic")))]
use crate::resolver::OpportunisticEncryptionStatePersistTask;
#[cfg(feature = "__dnssec")]
use crate::{dnssec::NxProofKind, zone_handler::Nsec3QueryInfo};
use crate::{
    net::runtime::RuntimeProvider,
    proto::{
        op::Query,
        op::ResponseSigner,
        rr::{LowerName, Name, RecordType},
    },
    resolver::{config::OpportunisticEncryption, recursor::Recursor},
    server::{Request, RequestInfo},
    zone_handler::{
        AuthLookup, AxfrPolicy, LookupControlFlow, LookupError, LookupOptions, ZoneHandler,
        ZoneType,
    },
};

/// A zone handler that performs recursive resolutions.
///
/// This uses the hickory-recursor crate for resolving requests.
pub struct RecursiveZoneHandler<P: RuntimeProvider> {
    origin: LowerName,
    recursor: Recursor<P>,
    #[allow(dead_code)] // Handle is retained to Drop along with RecursiveZoneHandler.
    opportunistic_encryption_persistence_task: Option<P::Handle>,
}

impl<P: RuntimeProvider> RecursiveZoneHandler<P> {
    /// Read the ZoneHandler for the origin from the specified configuration
    pub async fn try_from_config(
        origin: Name,
        _zone_type: ZoneType,
        config: &RecursiveConfig,
        root_dir: Option<&Path>,
        conn_provider: P,
    ) -> Result<Self, String> {
        info!("loading recursor config: {}", origin);

        let recursor = Recursor::from_config(config, root_dir, conn_provider.clone())
            .map_err(|e| format!("failed to build recursor for zone {origin}: {e}"))?;

        Ok(Self {
            origin: origin.into(),
            // Once the recursor is built, potentially use the recursor's pool context to spawn a
            // background save task, holding the task handle (if created) so it drops with the zone handler.
            #[cfg(all(feature = "toml", any(feature = "__tls", feature = "__quic")))]
            opportunistic_encryption_persistence_task: match &config
                .options
                .opportunistic_encryption
            {
                OpportunisticEncryption::Enabled { config } => {
                    OpportunisticEncryptionStatePersistTask::<P::Timer>::start(
                        config,
                        recursor.pool_context(),
                        conn_provider.clone(),
                    )
                    .await?
                }
                _ => None,
            },
            #[cfg(not(all(feature = "toml", any(feature = "__tls", feature = "__quic"))))]
            opportunistic_encryption_persistence_task: None,
            recursor,
        })
    }
}

#[async_trait::async_trait]
impl<P: RuntimeProvider> ZoneHandler for RecursiveZoneHandler<P> {
    /// Always External
    fn zone_type(&self) -> ZoneType {
        ZoneType::External
    }

    /// Always deny for Forward zones
    fn axfr_policy(&self) -> AxfrPolicy {
        AxfrPolicy::Deny
    }

    fn can_validate_dnssec(&self) -> bool {
        self.recursor.is_validating()
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
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        debug!("recursive lookup: {} {}", name, rtype);

        let query = Query::query(name.into(), rtype);
        let now = Instant::now();

        let result = self
            .recursor
            .resolve(query.clone(), now, lookup_options.dnssec_ok)
            .await;

        let response = match result {
            Ok(response) => response,
            Err(error) => return LookupControlFlow::Continue(Err(LookupError::from(error))),
        };
        LookupControlFlow::Continue(Ok(AuthLookup::Response(response)))
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
            "Getting NSEC records is unimplemented for the recursor",
        ))))
    }

    #[cfg(feature = "__dnssec")]
    async fn nsec3_records(
        &self,
        _info: Nsec3QueryInfo<'_>,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        LookupControlFlow::Continue(Err(LookupError::from(io::Error::other(
            "getting NSEC3 records is unimplemented for the recursor",
        ))))
    }

    #[cfg(feature = "__dnssec")]
    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        None
    }

    #[cfg(feature = "metrics")]
    fn metrics_label(&self) -> &'static str {
        "recursive"
    }
}
