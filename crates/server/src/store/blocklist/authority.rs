// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{io, path::Path};

use tracing::{debug, info, trace};

use crate::{
    authority::{
        Authority, LookupError, LookupObject, LookupOptions, MessageRequest, UpdateResult, ZoneType,
    },
    proto::{
        op::{Query, ResponseCode},
        rr::{rdata::A, LowerName, Name, RData, Record, RecordType},
    },
    server::RequestInfo,
    store::blocklist::BlocklistConfig,
};

use crate::resolver::lookup::Lookup;

use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::str::FromStr;

/// A conditional authority that will resolve queries against one or more block lists.  The typical use case will be to use this in a
/// chained configuration before a forwarding or recursive resolver:
///
///   [[zones]]
///   zone = "."
///   zone_type = "hint"
///   stores = [{ type = "blocklist", lists = ["default/bl.txt", "default/bl2.txt"]}, { type = "recursor", roots = "default/root.zone"}]
///
/// Note: the order of the stores is important: the first one specified in the store list will be the first consulted.  Subsequent stores
/// will only be consulted if each prior store returns None in response to the query.
pub struct BlocklistAuthority {
    origin: LowerName,
    blocklist: HashMap<LowerName, bool>,
    wildcard_match: bool,
    min_wildcard_depth: u8,
}

impl BlocklistAuthority {
    /// Read the Authority for the origin from the specified configuration
    pub async fn try_from_config(
        origin: Name,
        _zone_type: ZoneType,
        config: &BlocklistConfig,
        root_dir: Option<&Path>,
    ) -> Result<Self, String> {
        info!("loading blocklist config: {}", origin);

        let mut authority = Self {
            origin: origin.into(),
            blocklist: HashMap::new(),
            wildcard_match: config.wildcard_match,
            min_wildcard_depth: config.min_wildcard_depth,
        };

        // Load block lists into the block table cache for this authority.
        for bl in &config.lists {
            info!("Adding blocklist {bl:?}");
            authority
                .add(format!("{}/{bl}", root_dir.unwrap().display()))
                .await;
        }

        Ok(authority)
    }

    /// Add a configured block list to the in-memory cache.
    pub async fn add(&mut self, file: String) -> bool {
        let mut handle =
            File::open(&file).expect(&format!("unable to open block list file '{}'", &file)[..]);
        let mut contents = String::new();
        let _ = handle.read_to_string(&mut contents);

        for mut entry in contents.split('\n') {
            // Strip comments and leading/trailing whitespace
            if let Some(idx) = entry.chars().position(|c| c == '#') {
                entry = &entry[0..idx].trim();
            }

            if entry.is_empty() {
                continue;
            }

            let mut str_entry = entry.to_string();
            if !entry.ends_with('.') {
                str_entry += ".";
            }

            trace!("Inserting blocklist entry {str_entry:?}");
            self.blocklist
                .insert(LowerName::from_str(&str_entry[..]).unwrap(), true);
        }

        true
    }

    /// Build a wildcard match list for a given host
    pub fn get_wildcards(&self, host: &LowerName) -> Vec<LowerName> {
        let mut wildcards = vec![];
        let mut host = Name::from(host);

        if host.num_labels() > self.min_wildcard_depth {
            for _ in 0..host.num_labels() - self.min_wildcard_depth {
                wildcards.push(host.clone().into_wildcard().into());
                host = host.trim_to((host.num_labels() - 1) as usize);
            }
        }

        debug!("Built wildcard list: {wildcards:?}");

        wildcards
    }
}

#[async_trait::async_trait]
impl Authority for BlocklistAuthority {
    type Lookup = BlocklistLookup;

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
        debug!("blocklist lookup: {} {}", name, rtype);

        let mut match_list = vec![name.to_owned()];
        if self.wildcard_match {
            match_list.append(&mut self.get_wildcards(name));
        }
        debug!("Blocklist match list: {match_list:?}");

        for host in match_list {
            if self.blocklist.contains_key(&host) {
                return Ok(Some(BlocklistLookup(Lookup::from_rdata(
                    Query::query(name.into(), rtype),
                    RData::A(A::new(0, 0, 0, 0)),
                ))));
            }
        }
        debug!("Query '{name}' is not in blocklist; returning None...");
        Ok(None)
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
            "Getting NSEC records is unimplemented for the blocklist",
        )))
    }
}

pub struct BlocklistLookup(Lookup);

impl LookupObject for BlocklistLookup {
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

#[cfg(test)]
mod test {
    use crate::{
        authority::{AuthorityObject, LookupOptions, ZoneType},
        proto::rr::domain::Name,
        proto::rr::{rdata::A, LowerName, RData, RecordType},
    };
    use std::path::Path;
    use std::str::FromStr;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_blocklist_basic() {
        let config = super::BlocklistConfig {
            wildcard_match: true,
            min_wildcard_depth: 2,
            lists: vec!["default/blocklist.txt".to_string()],
        };

        let blocklist = super::BlocklistAuthority::try_from_config(
            Name::from_str(".").unwrap(),
            ZoneType::Hint,
            &config,

            Some(Path::new("../../tests/test-data/test_configs/")),
        );

        let authority = blocklist.await;

        // Test: verify the blocklist authority was successfully created.
        match authority {
            Ok(ref _authority) => {}
            Err(e) => {
                panic!("Unable to create blocklist authority: {e}");
            }
        }

        let ao = Box::new(Arc::new(authority.unwrap())) as Box<dyn AuthorityObject>;

        // Test: lookup a record that is explicitly in the blocklist and that should match without a wildcard.
        let res = ao
            .lookup(
                &LowerName::from_str("foo.com.").unwrap(),
                RecordType::A,
                LookupOptions::default(),
            )
            .await;
        match res {
            Ok(Some(l)) => {
                if !l.iter().all(|x| {
                    x.name() == &Name::from_str("foo.com.").unwrap()
                        && x.data() == Some(&RData::A(A::new(0, 0, 0, 0)))
                }) {
                    panic!("foo.com lookup data is incorrect.");
                }
            }
            Ok(None) => {
                panic!("Lookup returned Ok(None); expected Ok(Some)");
            }
            Err(e) => {
                panic!("Lookup error: {e}!");
            }
        }

        // Test: lookup a record that is not in the blocklist. This test should fail.
        let res = ao
            .lookup(
                &LowerName::from_str("test.com.").unwrap(),
                RecordType::A,
                LookupOptions::default(),
            )
            .await;
        match res {
            Ok(Some(_l)) => {
                panic!("test.com lookup returned Ok; expected failure");
            }
            Ok(None) => {}
            Err(_e) => {
                panic!("test.com lookup returned Err; expected Ok(None)");
            }
        }

        // Test: lookup a record that will match a wildcard that is in the blocklist.
        let res = ao
            .lookup(
                &LowerName::from_str("www.foo.com.").unwrap(),
                RecordType::A,
                LookupOptions::default(),
            )
            .await;
        match res {
            Ok(Some(l)) => {
                if !l.iter().all(|x| {
                    x.name() == &Name::from_str("www.foo.com.").unwrap()
                        && x.data() == Some(&RData::A(A::new(0, 0, 0, 0)))
                }) {
                    panic!("www.foo.com lookup data is incorrect.");
                }
            }
            Ok(None) => {
                panic!("Lookup returned Ok(None); expected Ok(Some)");
            }
            Err(e) => {
                panic!("Lookup error: {e}!");
            }
        }

        // Test: lookup a record that will match a wildcard that is in the blocklist.
        let res = ao
            .lookup(
                &LowerName::from_str("www.com.foo.com.").unwrap(),
                RecordType::A,
                LookupOptions::default(),
            )
            .await;
        match res {
            Ok(Some(l)) => {
                if !l.iter().all(|x| {
                    x.name() == &Name::from_str("www.com.foo.com.").unwrap()
                        && x.data() == Some(&RData::A(A::new(0, 0, 0, 0)))
                }) {
                    panic!("www.com.foo.com lookup data is incorrect.");
                }
            }
            Ok(None) => {
                panic!("lookup returned Ok(None); expected Ok(Some)");
            }
            Err(e) => {
                panic!("Lookup error: {e}!");
            }
        }
    }

    #[tokio::test]
    async fn test_blocklist_wildcard_disabled() {
        let config = super::BlocklistConfig {
            min_wildcard_depth: 2,
            wildcard_match: false,
            lists: vec!["default/blocklist.txt".to_string()],
        };

        let blocklist = super::BlocklistAuthority::try_from_config(
            Name::from_str(".").unwrap(),
            ZoneType::Hint,
            &config,

            Some(Path::new("../../tests/test-data/test_configs/")),
        );

        let authority = blocklist.await;

        // Test: verify the blocklist authority was successfully created.
        match authority {
            Ok(ref _authority) => {}
            Err(e) => {
                panic!("Unable to create blocklist authority: {e}");
            }
        }

        let ao = Box::new(Arc::new(authority.unwrap())) as Box<dyn AuthorityObject>;

        // Test: lookup a record that is explicitly in the blocklist and that should match with a wildcard.
        let res = ao
            .lookup(
                &LowerName::from_str("foo.com.").unwrap(),
                RecordType::A,
                LookupOptions::default(),
            )
            .await;
        match res {
            Ok(Some(l)) => {
                if !l.iter().all(|x| {
                    x.name() == &Name::from_str("foo.com.").unwrap()
                        && x.data() == Some(&RData::A(A::new(0, 0, 0, 0)))
                }) {
                    panic!("foo.com lookup data is incorrect.");
                }
            }
            Ok(None) => {
                panic!("Lookup returned Ok(None); expected Ok(Some)");
            }
            Err(e) => {
                panic!("Lookup error: {e}!");
            }
        }

        // Test: lookup a record that is not in the blocklist, but would match a wildcard; this should fail.
        let res = ao
            .lookup(
                &LowerName::from_str("www.foo.com.").unwrap(),
                RecordType::A,
                LookupOptions::default(),
            )
            .await;
        match res {
            Ok(Some(_l)) => {
                panic!("www.foo.com lookup returned Ok(Some); expected Ok(None)");
            }
            Ok(None) => {}
            Err(_e) => {
                panic!("www.foo.com lookup returned Err; expected Ok(None)");
            }
        }
    }
}
