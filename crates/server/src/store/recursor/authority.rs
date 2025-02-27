// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{io, path::Path, time::Instant};

use tracing::{debug, info};

use crate::{
    authority::{
        Authority, LookupControlFlow, LookupError, LookupObject, LookupOptions, MessageRequest,
        UpdateResult, ZoneType,
    },
    proto::{
        op::{Query, ResponseCode},
        rr::{LowerName, Name, Record, RecordType},
        xfer::Protocol,
    },
    recursor::Recursor,
    resolver::{
        config::{NameServerConfig, NameServerConfigGroup},
        lookup::Lookup,
    },
    server::RequestInfo,
    store::recursor::RecursiveConfig,
};
#[cfg(feature = "__dnssec")]
use crate::{
    authority::{DnssecSummary, Nsec3QueryInfo},
    dnssec::NxProofKind,
    proto::dnssec::Proof,
};

/// An authority that performs recursive resolutions.
///
/// This uses the hickory-recursor crate for resolving requests.
pub struct RecursiveAuthority {
    origin: LowerName,
    recursor: Recursor,
}

impl RecursiveAuthority {
    /// Read the Authority for the origin from the specified configuration
    pub async fn try_from_config(
        origin: Name,
        _zone_type: ZoneType,
        config: &RecursiveConfig,
        root_dir: Option<&Path>,
    ) -> Result<Self, String> {
        info!("loading recursor config: {}", origin);

        // read the roots
        let root_addrs = config
            .read_roots(root_dir)
            .map_err(|e| format!("failed to read roots {}: {}", config.roots.display(), e))?;

        // Configure all the name servers
        let mut roots = NameServerConfigGroup::new();
        for socket_addr in root_addrs {
            roots.push(NameServerConfig {
                socket_addr,
                protocol: Protocol::Tcp,
                tls_dns_name: None,
                http_endpoint: None,
                trust_negative_responses: false,
                bind_addr: None, // TODO: need to support bind addresses
            });

            roots.push(NameServerConfig {
                socket_addr,
                protocol: Protocol::Udp,
                tls_dns_name: None,
                http_endpoint: None,
                trust_negative_responses: false,
                bind_addr: None,
            });
        }

        let mut builder = Recursor::builder();
        if let Some(ns_cache_size) = config.ns_cache_size {
            builder = builder.ns_cache_size(ns_cache_size);
        }
        if let Some(record_cache_size) = config.record_cache_size {
            builder = builder.record_cache_size(record_cache_size);
        }

        let recursor = builder
            .dnssec_policy(config.dnssec_policy.load()?)
            .nameserver_filter(config.allow_server.iter(), config.deny_server.iter())
            .recursion_limit(match config.recursion_limit {
                0 => None,
                limit => Some(limit),
            })
            .ns_recursion_limit(match config.ns_recursion_limit {
                0 => None,
                limit => Some(limit),
            })
            .avoid_local_udp_ports(config.avoid_local_udp_ports.clone())
            .ttl_config(config.cache_policy.clone())
            .case_randomization(config.case_randomization)
            .build(roots)
            .map_err(|e| format!("failed to initialize recursor: {e}"))?;

        Ok(Self {
            origin: origin.into(),
            recursor,
        })
    }
}

#[async_trait::async_trait]
impl Authority for RecursiveAuthority {
    type Lookup = RecursiveLookup;

    /// Always External
    fn zone_type(&self) -> ZoneType {
        ZoneType::External
    }

    /// Always false for Forward zones
    fn is_axfr_allowed(&self) -> bool {
        false
    }

    fn can_validate_dnssec(&self) -> bool {
        self.recursor.is_validating()
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
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        debug!("recursive lookup: {} {}", name, rtype);

        let query = Query::query(name.into(), rtype);
        let now = Instant::now();

        let result = self
            .recursor
            .resolve(query, now, lookup_options.dnssec_ok())
            .await;

        use LookupControlFlow::*;
        match result {
            Ok(lookup) => Continue(Ok(RecursiveLookup(lookup))),
            Err(error) => Continue(Err(LookupError::from(error))),
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
            "Getting NSEC records is unimplemented for the recursor",
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
            "getting NSEC3 records is unimplemented for the recursor",
        ))))
    }

    #[cfg(feature = "__dnssec")]
    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        None
    }
}

pub struct RecursiveLookup(Lookup);

impl LookupObject for RecursiveLookup {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Record> + Send + 'a> {
        Box::new(self.0.record_iter())
    }

    fn take_additionals(&mut self) -> Option<Box<dyn LookupObject>> {
        None
    }

    #[cfg(feature = "__dnssec")]
    fn dnssec_summary(&self) -> DnssecSummary {
        let mut all_secure = None;
        for record in self.0.records().iter() {
            match record.proof() {
                Proof::Secure => {
                    all_secure.get_or_insert(true);
                }
                Proof::Bogus => return DnssecSummary::Bogus,
                _ => all_secure = Some(false),
            }
        }

        if all_secure.unwrap_or(false) {
            DnssecSummary::Secure
        } else {
            DnssecSummary::Insecure
        }
    }
}
