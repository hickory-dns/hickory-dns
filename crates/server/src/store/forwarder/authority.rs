// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::borrow::Borrow;

use trust_dns::op::LowerQuery;
use trust_dns::op::ResponseCode;
use trust_dns::rr::dnssec::{DnsSecResult, Signer, SupportedAlgorithms};
use trust_dns::rr::{LowerName, Name, Record, RecordType};
use trust_dns_resolver::lookup::Lookup as ResolverLookup;
use trust_dns_resolver::Resolver;

use authority::{Authority, LookupObject, LookupResult, MessageRequest, UpdateResult, ZoneType};

pub struct ForwardAuthority {
    origin: LowerName,
    /// FIXME: need to change Authority to be Async
    resolver: Resolver,
}

impl ForwardAuthority {
    // FIXME: read from configuration
    pub fn new() -> Self {
        ForwardAuthority {
            origin: Name::root().into(),
            resolver: Resolver::from_system_conf().unwrap(),
        }
    }
}

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
    ) -> LookupResult<Self::Lookup> {
        // FIXME: make this an error
        assert!(self.origin.zone_of(name));

        Ok(ForwardLookup(
            self.resolver
                .lookup(&Borrow::<Name>::borrow(name).to_utf8(), rtype)
                .unwrap(),
        ))
    }

    fn search(
        &self,
        query: &LowerQuery,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> LookupResult<Self::Lookup> {
        self.lookup(
            query.name(),
            query.query_type(),
            is_secure,
            supported_algorithms,
        )
    }

    fn get_nsec_records(
        &self,
        _name: &LowerName,
        _is_secure: bool,
        _supported_algorithms: SupportedAlgorithms,
    ) -> LookupResult<Self::Lookup> {
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
}
