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
        Authority, LookupError, LookupObject, LookupOptions, MessageRequest, UpdateResult, ZoneType,
    },
    proto::{
        op::{Query, ResponseCode},
        rr::{LowerName, Name, Record, RecordType},
    },
    recursor::Recursor,
    resolver::{
        config::{NameServerConfig, NameServerConfigGroup, Protocol},
        lookup::Lookup,
    },
    server::RequestInfo,
    store::recursor::RecursiveConfig,
};

/// An authority that will forward resolutions to upstream resolvers.
///
/// This uses the hickory-resolver for resolving requests.
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
                trust_negative_responses: false,
                #[cfg(feature = "dns-over-rustls")]
                tls_config: None,
                bind_addr: None, // TODO: need to support bind addresses
            });

            roots.push(NameServerConfig {
                socket_addr,
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: false,
                #[cfg(feature = "dns-over-rustls")]
                tls_config: None,
                bind_addr: None,
            });
        }

        let recursor = Recursor::new(roots, config.ns_cache_size, config.record_cache_size)
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

    /// Always Recursive
    fn zone_type(&self) -> ZoneType {
        ZoneType::Hint
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
    ) -> Result<Option<Self::Lookup>, LookupError> {
        debug!("recursive lookup: {} {}", name, rtype);

        let query = Query::query(name.into(), rtype);
        let now = Instant::now();

        self.recursor
            .resolve(query, now)
            .await
            .map(RecursiveLookup)
            .map(Some)
            .map_err(Into::into)
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Option<Self::Lookup>, LookupError> {
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
    ) -> Result<Self::Lookup, LookupError> {
        Err(LookupError::from(io::Error::new(
            io::ErrorKind::Other,
            "Getting NSEC records is unimplemented for the recursor",
        )))
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
}
