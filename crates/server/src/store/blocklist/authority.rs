// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{
    collections::HashMap,
    fs::File,
    io,
    io::{Error, Read},
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
    str::FromStr,
    time::{Duration, Instant},
};
use tracing::{error, info, trace};

#[cfg(feature = "__dnssec")]
use crate::{authority::Nsec3QueryInfo, dnssec::NxProofKind};
use crate::{
    authority::{
        Authority, LookupControlFlow, LookupError, LookupObject, LookupOptions, MessageRequest,
        UpdateResult, ZoneType,
    },
    proto::{
        op::{Query, ResponseCode},
        rr::{
            LowerName, Name, RData, Record, RecordType,
            rdata::{A, AAAA, TXT},
        },
    },
    resolver::lookup::Lookup,
    server::RequestInfo,
    store::blocklist::{BlocklistConfig, BlocklistConsultAction},
};

// TODO:
//  * Add (optional) support for logging the client IP address.  This will require some Authority
//    trait changes to accomplish
//  * Add query-type specific results for non-address queries
//  * Add support for per-blocklist sinkhole IPs, block messages, actions
//  * Add support for an exclusion list: allow the user to configure a list of patterns that
//    will never be insert into the in-memory blocklist (such as their own domain)
//  * Add support for regex matching

/// A conditional authority that will resolve queries against one or more block lists and return a
/// forged response.  The typical use case will be to use this in a chained configuration before a
/// forwarding or recursive resolver in order to pre-emptively block queries for hosts that are on
/// a block list. Refer to tests/test-data/test_configs/chained_blocklist.toml for an example
/// of this configuration.
///
/// The blocklist authority also supports the consult interface, which allows an authority to review
/// a query/response that has been processed by another authority, and, optionally, overwrite that
/// response before returning it to the requestor.  There is an example of this configuration in
/// tests/test-data/test_configs/example_consulting_blocklist.toml.  The main intended use of this
/// feature is to allow log-only configurations, to allow administrators to see if blocklist domains
/// are being queried.  While this can be configured to overwrite responses, it is not recommended
/// to do so - it is both more efficient, and more secure, to allow the blocklist to drop queries
/// pre-emptively, as in the first example.
pub struct BlocklistAuthority {
    origin: LowerName,
    blocklist: HashMap<LowerName, bool>,
    wildcard_match: bool,
    min_wildcard_depth: u8,
    sinkhole_ipv4: Ipv4Addr,
    sinkhole_ipv6: Ipv6Addr,
    ttl: u32,
    block_message: Option<String>,
    consult_action: BlocklistConsultAction,
}

impl BlocklistAuthority {
    /// Read the Authority for the origin from the specified configuration
    pub async fn try_from_config(
        origin: Name,
        _zone_type: ZoneType,
        config: &BlocklistConfig,
        base_dir: Option<&Path>,
    ) -> Result<Self, String> {
        info!("loading blocklist config: {origin}");

        let mut authority = Self {
            origin: origin.into(),
            blocklist: HashMap::new(),
            wildcard_match: config.wildcard_match,
            min_wildcard_depth: config.min_wildcard_depth,
            sinkhole_ipv4: match config.sinkhole_ipv4 {
                Some(ip) => ip,
                None => Ipv4Addr::UNSPECIFIED,
            },
            sinkhole_ipv6: match config.sinkhole_ipv6 {
                Some(ip) => ip,
                None => Ipv6Addr::UNSPECIFIED,
            },
            ttl: config.ttl,
            block_message: config.block_message.clone(),
            consult_action: config.consult_action,
        };

        let base_dir = match base_dir {
            Some(dir) => dir.display(),
            None => {
                return Err(format!(
                    "invalid blocklist (zone directory) base path specified: '{base_dir:?}'"
                ));
            }
        };

        // Load block lists into the block table cache for this authority.
        for bl in &config.lists {
            info!("adding blocklist {bl}");

            match File::open(format!("{base_dir}/{bl}")) {
                Ok(handle) => {
                    if let Err(e) = authority.add(handle) {
                        return Err(format!(
                            "unable to add data from blocklist {base_dir}/{bl}: {e:?}"
                        ));
                    }
                }
                Err(e) => {
                    return Err(format!(
                        "unable to open blocklist file {base_dir}/{bl}: {e:?}"
                    ));
                }
            }
        }

        Ok(authority)
    }

    /// Add the contents of a block list to the in-memory cache. This function is normally called
    /// from try_from_config, but it can be invoked after the blocklist authority is created.
    ///
    /// # Arguments
    ///
    /// * `handle` - A source implementing `std::io::Read` that contains the blocklist entries
    ///   to insert into the in-memory cache.
    ///
    /// # Return value
    ///
    /// `Result<(), std::io::Error>`
    ///
    /// # Expected format of blocklist entries
    ///
    /// * One entry per line
    /// * Any character after a '\#' will be treated as a comment and stripped out.
    /// * Leading wildcard entries are supported when the user has wildcard_match set to true.
    ///   E.g., '\*.foo.com' will match any host in the foo.com domain.  Intermediate wildcard
    ///   matches, such as 'www.\*.com' are not supported. **Note: when wildcard matching is enabled,
    ///   min_wildcard_depth (default: 2) controls how many static name labels must be present for a
    ///   wildcard entry to be valid.  With the default value of 2, an entry for '\*.foo.com' would
    ///   be accepted, but an entry for '\*.com' would not.**
    /// * All entries are treated as being fully-qualified. If an entry does not contain a trailing
    ///   '.', one will be added before insertion into the cache.
    ///
    /// # Example
    /// ```
    /// use std::{fs::File, net::{Ipv4Addr, Ipv6Addr}, path::Path, str::FromStr, sync::Arc};
    /// use hickory_proto::rr::{LowerName, RecordType};
    /// use hickory_resolver::Name;
    /// use hickory_server::{authority::{AuthorityObject, LookupControlFlow, LookupOptions, ZoneType}, store::blocklist::*};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let config = BlocklistConfig {
    ///         wildcard_match: true,
    ///         min_wildcard_depth: 2,
    ///         lists: vec!["default/blocklist.txt".to_string()],
    ///         sinkhole_ipv4: None,
    ///         sinkhole_ipv6: None,
    ///         block_message: None,
    ///         ttl: 86_400,
    ///         consult_action: BlocklistConsultAction::Disabled,
    ///     };
    ///
    ///     let mut blocklist = BlocklistAuthority::try_from_config(
    ///         Name::root(),
    ///         ZoneType::External,
    ///         &config,
    ///         Some(Path::new("../../tests/test-data/test_configs")),
    ///     ).await.unwrap();
    ///
    ///     let handle = File::open("../../tests/test-data/test_configs/default/blocklist2.txt").unwrap();
    ///     if let Err(e) = blocklist.add(handle) {
    ///         panic!("error adding blocklist: {e:?}");
    ///     }
    ///
    ///     let origin = blocklist.origin().clone();
    ///     let authority = Arc::new(blocklist) as Arc<dyn AuthorityObject>;
    ///
    ///     // In this example, malc0de.com only exists in the blocklist2.txt file we added to the
    ///     // authority after instantiating it.  The following simulates a lookup against the blocklist
    ///     // authority, and checks for the expected response for a blocklist match.
    ///     use LookupControlFlow::*;
    ///     let Break(Ok(_res)) = authority.lookup(
    ///                             &LowerName::from(Name::from_ascii("malc0de.com.").unwrap()),
    ///                             RecordType::A,
    ///                             LookupOptions::default(),
    ///                           ).await else {
    ///         panic!("blocklist authority did not return expected match");
    ///     };
    /// }
    /// ```
    pub fn add(&mut self, mut handle: impl Read) -> Result<(), Error> {
        let mut contents = String::new();

        if let Err(e) = handle.read_to_string(&mut contents) {
            error!("unable to read blocklist data: {e:?}");
            return Err(e);
        }

        for mut entry in contents.lines() {
            // Strip comments
            if let Some((item, _)) = entry.split_once('#') {
                entry = item.trim();
            }

            if entry.is_empty() {
                continue;
            }

            let mut str_entry = entry.to_string();
            if !entry.ends_with('.') {
                str_entry += ".";
            }

            let Ok(name) = LowerName::from_str(&str_entry[..]) else {
                error!(
                    "unable to derive LowerName for blocklist entry '{str_entry}'; skipping entry"
                );
                continue;
            };

            trace!("inserting blocklist entry {str_entry}");

            // The boolean value is not significant; only the key is used.
            self.blocklist.insert(name, true);
        }

        Ok(())
    }

    /// Build a wildcard match list for a given host
    fn wildcards(&self, host: &Name) -> Vec<LowerName> {
        host.iter()
            .enumerate()
            .filter_map(|(i, _x)| {
                if i > ((self.min_wildcard_depth - 1) as usize) {
                    Some(host.trim_to(i + 1).into_wildcard().into())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Perform a blocklist lookup. Returns true on match, false on no match.  This is also where
    /// wildcard expansion is done, if wildcard support is enabled for the blocklist authority.
    fn is_blocked(&self, name: &LowerName) -> bool {
        let mut match_list = vec![name.to_owned()];

        if self.wildcard_match {
            match_list.append(&mut self.wildcards(name));
        }

        trace!("blocklist match list: {match_list:?}");

        if match_list
            .iter()
            .any(|entry| self.blocklist.contains_key(entry))
        {
            info!("block list matched query {name}");
            return true;
        }

        false
    }

    /// Generate a BlocklistLookup to return on a blocklist match.  This will return a lookup with
    /// either an A or AAAA record and, if the user has configured a block message, a TXT record
    /// with the contents of that message.
    fn blocklist_response(&self, name: Name, rtype: RecordType) -> BlocklistLookup {
        let mut records = vec![];

        match rtype {
            RecordType::AAAA => records.push(Record::from_rdata(
                name.clone(),
                self.ttl,
                RData::AAAA(AAAA(self.sinkhole_ipv6)),
            )),
            _ => records.push(Record::from_rdata(
                name.clone(),
                self.ttl,
                RData::A(A(self.sinkhole_ipv4)),
            )),
        }

        if let Some(block_message) = &self.block_message {
            records.push(Record::from_rdata(
                name.clone(),
                self.ttl,
                RData::TXT(TXT::new(vec![block_message.clone()])),
            ));
        }

        BlocklistLookup(Lookup::new_with_deadline(
            Query::query(name.clone(), rtype),
            records.into(),
            Instant::now() + Duration::from_secs(u64::from(self.ttl)),
        ))
    }
}

#[async_trait::async_trait]
impl Authority for BlocklistAuthority {
    type Lookup = BlocklistLookup;

    fn zone_type(&self) -> ZoneType {
        ZoneType::External
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    /// Perform a blocklist lookup.  This will return LookupControlFlow::Break(Ok) on a match, or
    /// LookupControlFlow::Skip on no match.
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        use LookupControlFlow::*;

        trace!("blocklist lookup: {name} {rtype}");

        if self.is_blocked(name) {
            return Break(Ok(self.blocklist_response(Name::from(name), rtype)));
        }

        trace!("query '{name}' is not in blocklist; returning Skip...");
        Skip
    }

    /// Optionally, perform a blocklist lookup after another authority has done a lookup for this
    /// query.
    async fn consult(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
        last_result: LookupControlFlow<Box<dyn LookupObject>>,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        match self.consult_action {
            BlocklistConsultAction::Disabled => last_result,
            BlocklistConsultAction::Log => {
                self.is_blocked(name);
                last_result
            }
            BlocklistConsultAction::Enforce => {
                let lookup = self.lookup(name, rtype, lookup_options).await;

                if lookup.is_break() {
                    lookup.map_dyn()
                } else {
                    last_result
                }
            }
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
            "Getting NSEC records is unimplemented for the blocklist",
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
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        path::Path,
        str::FromStr,
        sync::Arc,
    };
    use tracing::error;

    use crate::{
        authority::{AuthorityObject, LookupOptions, ZoneType},
        proto::rr::domain::Name,
        proto::rr::{
            LowerName, RData, RecordType,
            rdata::{A, AAAA},
        },
        store::blocklist::BlocklistConsultAction,
    };
    use test_support::subscribe;

    enum TestResult {
        Break,
        Skip,
    }

    #[tokio::test]
    async fn test_blocklist_basic() {
        subscribe();
        let config = super::BlocklistConfig {
            wildcard_match: true,
            min_wildcard_depth: 2,
            lists: vec!["default/blocklist.txt".to_string()],
            sinkhole_ipv4: None,
            sinkhole_ipv6: None,
            block_message: None,
            ttl: 86_400,
            consult_action: BlocklistConsultAction::Disabled,
        };

        let blocklist = super::BlocklistAuthority::try_from_config(
            Name::root(),
            ZoneType::External,
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

        let ao = Arc::new(authority.unwrap()) as Arc<dyn AuthorityObject>;

        let v4 = A::new(0, 0, 0, 0);
        let v6 = AAAA::new(0, 0, 0, 0, 0, 0, 0, 0);

        use RecordType::{A as Rec_A, AAAA as Rec_AAAA};
        use TestResult::*;
        // Test: lookup a record that is in the blocklist and that should match without a wildcard.
        basic_test(&ao, "foo.com.", Rec_A, Break, Some(v4), None, None).await;

        // test: lookup a record that is not in the blocklist. This test should fail.
        basic_test(&ao, "test.com.", Rec_A, Skip, None, None, None).await;

        // Test: lookup a record that will match a wildcard that is in the blocklist.
        basic_test(&ao, "www.foo.com.", Rec_A, Break, Some(v4), None, None).await;

        // Test: lookup a record that will match a wildcard that is in the blocklist.
        basic_test(&ao, "www.com.foo.com.", Rec_A, Break, Some(v4), None, None).await;

        // Test: lookup a record that is in the blocklist and that should match without a wildcard.
        basic_test(&ao, "foo.com.", Rec_AAAA, Break, None, Some(v6), None).await;

        // test: lookup a record that is not in the blocklist. This test should fail.
        basic_test(&ao, "test.com.", Rec_AAAA, Skip, None, None, None).await;

        // Test: lookup a record that will match a wildcard that is in the blocklist.
        basic_test(&ao, "www.foo.com.", Rec_AAAA, Break, None, Some(v6), None).await;

        // Test: lookup a record that will match a wildcard that is in the blocklist.
        basic_test(&ao, "ab.cd.foo.com.", Rec_AAAA, Break, None, Some(v6), None).await;
    }

    #[tokio::test]
    async fn test_blocklist_wildcard_disabled() {
        subscribe();
        let config = super::BlocklistConfig {
            min_wildcard_depth: 2,
            wildcard_match: false,
            lists: vec!["default/blocklist.txt".to_string()],
            sinkhole_ipv4: Some(Ipv4Addr::new(192, 0, 2, 1)),
            sinkhole_ipv6: Some(Ipv6Addr::new(0, 0, 0, 0, 0xc0, 0, 2, 1)),
            block_message: Some(String::from("blocked")),
            ttl: 86_400,
            consult_action: BlocklistConsultAction::Disabled,
        };

        let blocklist = super::BlocklistAuthority::try_from_config(
            Name::root(),
            ZoneType::External,
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

        let ao = Arc::new(authority.unwrap()) as Arc<dyn AuthorityObject>;

        let v4 = A::new(192, 0, 2, 1);
        let v6 = AAAA::new(0, 0, 0, 0, 0xc0, 0, 2, 1);
        let msg = config.block_message;

        use RecordType::{A as Rec_A, AAAA as Rec_AAAA};
        use TestResult::*;

        // Test: lookup a record that is in the blocklist and that should match without a wildcard.
        basic_test(&ao, "foo.com.", Rec_A, Break, Some(v4), None, msg.clone()).await;

        // Test: lookup a record that is not in the blocklist, but would match a wildcard; this
        // should fail.
        basic_test(&ao, "www.foo.com.", Rec_A, Skip, None, None, msg.clone()).await;

        // Test: lookup a record that is in the blocklist and that should match without a wildcard.
        basic_test(&ao, "foo.com.", Rec_AAAA, Break, None, Some(v6), msg).await;
    }

    #[tokio::test]
    #[should_panic]
    async fn test_blocklist_wrong_block_message() {
        subscribe();
        let config = super::BlocklistConfig {
            min_wildcard_depth: 2,
            wildcard_match: false,
            lists: vec!["default/blocklist.txt".to_string()],
            sinkhole_ipv4: Some(Ipv4Addr::new(192, 0, 2, 1)),
            sinkhole_ipv6: Some(Ipv6Addr::new(0, 0, 0, 0, 0xc0, 0, 2, 1)),
            block_message: Some(String::from("blocked")),
            ttl: 86_400,
            consult_action: BlocklistConsultAction::Disabled,
        };

        let blocklist = super::BlocklistAuthority::try_from_config(
            Name::root(),
            ZoneType::External,
            &config,
            Some(Path::new("../../tests/test-data/test_configs/")),
        );

        let authority = blocklist.await;

        // Test: verify the blocklist authority was successfully created.
        match authority {
            Ok(ref _authority) => {}
            Err(e) => {
                error!("Unable to create blocklist authority: {e}");
                return;
            }
        }

        let ao = Arc::new(authority.unwrap()) as Arc<dyn AuthorityObject>;

        let sinkhole_v4 = A::new(192, 0, 2, 1);

        // Test: lookup a record that is in the blocklist, but specify an incorrect block message to
        // match.
        basic_test(
            &ao,
            "foo.com.",
            RecordType::A,
            TestResult::Break,
            Some(sinkhole_v4),
            None,
            Some(String::from("wrong message")),
        )
        .await;
    }

    #[allow(clippy::borrowed_box)]
    async fn basic_test(
        ao: &Arc<dyn AuthorityObject>,
        query: &'static str,
        q_type: RecordType,
        r_type: TestResult,
        ipv4: Option<A>,
        ipv6: Option<AAAA>,
        msg: Option<String>,
    ) {
        let res = ao
            .lookup(
                &LowerName::from_str(query).unwrap(),
                q_type,
                LookupOptions::default(),
            )
            .await;

        use super::LookupControlFlow::*;

        match r_type {
            TestResult::Break => match res {
                Break(Ok(l)) => {
                    if !l.iter().all(|x| match x.record_type() {
                        RecordType::TXT => {
                            if let Some(msg) = &msg {
                                x.data().to_string() == *msg
                            } else {
                                false
                            }
                        }
                        RecordType::AAAA => {
                            let Some(rec_ip) = ipv6 else {
                                panic!("expected to validate record IPv6, but None was passed");
                            };

                            x.name() == &Name::from_str(query).unwrap()
                                && x.data() == &RData::AAAA(rec_ip)
                        }
                        _ => {
                            let Some(rec_ip) = ipv4 else {
                                panic!("expected to validate record IPv4, but None was passed");
                            };

                            x.name() == &Name::from_str(query).unwrap()
                                && x.data() == &RData::A(rec_ip)
                        }
                    }) {
                        panic!("{query} lookup data is incorrect.");
                    }
                }
                _ => panic!("Unexpected result for {query}: {res}"),
            },
            TestResult::Skip => match res {
                Skip => {}
                _ => {
                    panic!("unexpected result for {query}; expected Skip, found {res}");
                }
            },
        }
    }
}
