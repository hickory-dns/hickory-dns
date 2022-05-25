// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io;

use tracing::{debug, info};

use crate::{
    authority::{
        Authority, LookupError, LookupObject, LookupOptions, MessageRequest, UpdateResult, ZoneType,
    },
    client::{
        op::ResponseCode,
        rr::{LowerName, Name, Record, RecordType},
    },
    recursor::Recursor,
    resolver::config::{NameServerConfig, NameServerConfigGroup, Protocol},
    server::RequestInfo,
    store::recursor::RecursiveConfig,
};

/// An authority that will forward resolutions to upstream resolvers.
///
/// This uses the trust-dns-resolver for resolving requests.
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
    ) -> Result<Self, String> {
        info!("loading recursor config: {}", origin);

        // read the hints
        let hint_addrs = config
            .read_hints()
            .map_err(|e| format!("failed to read hints file: {}", e))?;

        // Configure all the name servers
        let mut hints = NameServerConfigGroup::new();
        for socket_addr in hint_addrs {
            hints.push(NameServerConfig {
                socket_addr,
                protocol: Protocol::Tcp,
                tls_dns_name: None,
                trust_nx_responses: false,
                #[cfg(feature = "dns-over-rustls")]
                tls_config: None,
                bind_addr: None, // TODO: need to support bind addresses
            });

            hints.push(NameServerConfig {
                socket_addr,
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_nx_responses: false,
                #[cfg(feature = "dns-over-rustls")]
                tls_config: None,
                bind_addr: None,
            });
        }

        let recursor =
            Recursor::new(hints).map_err(|e| format!("failed to initialize recursor: {}", e))?;

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
    ) -> Result<Self::Lookup, LookupError> {
        debug!("recursive lookup: {} {}", name, rtype);

        todo!();
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
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

pub struct RecursiveLookup();

impl LookupObject for RecursiveLookup {
    fn is_empty(&self) -> bool {
        todo!()
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Record> + Send + 'a> {
        todo!()
    }

    fn take_additionals(&mut self) -> Option<Box<dyn LookupObject>> {
        todo!()
    }
}
