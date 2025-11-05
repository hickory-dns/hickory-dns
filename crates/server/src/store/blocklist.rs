// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Blocklist resolver related types

#![cfg(feature = "blocklist")]

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

#[cfg(feature = "metrics")]
use metrics::{Counter, Gauge, Unit, counter, describe_counter, describe_gauge, gauge};
use serde::Deserialize;
use tracing::{info, trace, warn};

#[cfg(feature = "__dnssec")]
use crate::{dnssec::NxProofKind, zone_handler::Nsec3QueryInfo};
use crate::{
    proto::{
        op::{Query, ResponseSigner},
        rr::{
            LowerName, Name, RData, Record, RecordType,
            rdata::{A, AAAA, TXT},
        },
    },
    resolver::lookup::Lookup,
    server::{Request, RequestInfo},
    zone_handler::{
        AuthLookup, AxfrPolicy, LookupControlFlow, LookupError, LookupOptions, ZoneHandler,
        ZoneTransfer, ZoneType,
    },
};

// TODO:
//  * Add query-type specific results for non-address queries
//  * Add support for per-blocklist sinkhole IPs, block messages, actions
//  * Add support for an exclusion list: allow the user to configure a list of patterns that
//    will never be insert into the in-memory blocklist (such as their own domain)
//  * Add support for regex matching

/// A conditional zone handler that will resolve queries against one or more block lists and return
/// a forged response.  The typical use case will be to use this in a chained configuration before a
/// forwarding or recursive resolver in order to pre-emptively block queries for hosts that are on a
/// block list. Refer to tests/test-data/test_configs/chained_blocklist.toml for an example of this
/// configuration.
///
/// The blocklist zone handler also supports the consult interface, which allows a zone handler to
/// review a query/response that has been processed by another zone handler, and, optionally,
/// overwrite that response before returning it to the requestor.  There is an example of this
/// configuration in tests/test-data/test_configs/example_consulting_blocklist.toml.  The main
/// intended use of this feature is to allow log-only configurations, to allow administrators to see
/// if blocklist domains are being queried.  While this can be configured to overwrite responses, it
/// is not recommended to do so - it is both more efficient, and more secure, to allow the blocklist
/// to drop queries pre-emptively, as in the first example.
pub struct BlocklistZoneHandler {
    origin: LowerName,
    blocklist: HashMap<LowerName, bool>,
    wildcard_match: bool,
    min_wildcard_depth: u8,
    sinkhole_ipv4: Ipv4Addr,
    sinkhole_ipv6: Ipv6Addr,
    ttl: u32,
    block_message: Option<String>,
    consult_action: BlocklistConsultAction,
    log_clients: bool,
    #[cfg(feature = "metrics")]
    metrics: BlocklistMetrics,
}

impl BlocklistZoneHandler {
    /// Read the ZoneHandler for the origin from the specified configuration
    pub fn try_from_config(
        origin: Name,
        config: &BlocklistConfig,
        base_dir: Option<&Path>,
    ) -> Result<Self, String> {
        info!("loading blocklist config: {origin}");

        let mut handler = Self {
            origin: origin.into(),
            blocklist: HashMap::new(),
            wildcard_match: config.wildcard_match,
            min_wildcard_depth: config.min_wildcard_depth,
            sinkhole_ipv4: config.sinkhole_ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED),
            sinkhole_ipv6: config.sinkhole_ipv6.unwrap_or(Ipv6Addr::UNSPECIFIED),
            ttl: config.ttl,
            block_message: config.block_message.clone(),
            consult_action: config.consult_action,
            log_clients: config.log_clients,
            #[cfg(feature = "metrics")]
            metrics: BlocklistMetrics::new(),
        };

        let base_dir = match base_dir {
            Some(dir) => dir.display(),
            None => {
                return Err(format!(
                    "invalid blocklist (zone directory) base path specified: '{base_dir:?}'"
                ));
            }
        };

        // Load block lists into the block table cache for this zone handler.
        for bl in &config.lists {
            info!("adding blocklist {bl}");

            let file = match File::open(format!("{base_dir}/{bl}")) {
                Ok(file) => file,
                Err(e) => {
                    return Err(format!(
                        "unable to open blocklist file {base_dir}/{bl}: {e:?}"
                    ));
                }
            };

            if let Err(e) = handler.add(file) {
                return Err(format!(
                    "unable to add data from blocklist {base_dir}/{bl}: {e:?}"
                ));
            }
        }

        #[cfg(feature = "metrics")]
        handler
            .metrics
            .entries
            .set(handler.blocklist.keys().len() as f64);

        Ok(handler)
    }

    /// Add the contents of a block list to the in-memory cache. This function is normally called
    /// from try_from_config, but it can be invoked after the blocklist zone handler is created.
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
    /// use hickory_server::{
    ///     store::blocklist::*,
    ///     zone_handler::{LookupControlFlow, LookupOptions, ZoneHandler, ZoneType},
    /// };
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
    ///         log_clients: true,
    ///     };
    ///
    ///     let mut blocklist = BlocklistZoneHandler::try_from_config(
    ///         Name::root(),
    ///         &config,
    ///         Some(Path::new("../../tests/test-data/test_configs")),
    ///     ).unwrap();
    ///
    ///     let handle = File::open("../../tests/test-data/test_configs/default/blocklist2.txt").unwrap();
    ///     if let Err(e) = blocklist.add(handle) {
    ///         panic!("error adding blocklist: {e:?}");
    ///     }
    ///
    ///     let origin = blocklist.origin().clone();
    ///     let handler = Arc::new(blocklist) as Arc<dyn ZoneHandler>;
    ///
    ///     // In this example, malc0de.com only exists in the blocklist2.txt file we added to the
    ///     // zone handler after instantiating it.  The following simulates a lookup against the
    ///     // blocklist zone handler, and checks for the expected response for a blocklist match.
    ///     use LookupControlFlow::*;
    ///     let Break(Ok(_res)) = handler.lookup(
    ///                             &LowerName::from(Name::from_ascii("malc0de.com.").unwrap()),
    ///                             RecordType::A,
    ///                             None,
    ///                             LookupOptions::default(),
    ///                           ).await else {
    ///         panic!("blocklist zone handler did not return expected match");
    ///     };
    /// }
    /// ```
    pub fn add(&mut self, mut handle: impl Read) -> Result<(), Error> {
        let mut contents = String::new();

        handle.read_to_string(&mut contents)?;
        for mut entry in contents.lines() {
            // Strip comments
            if let Some((item, _)) = entry.split_once('#') {
                entry = item.trim();
            }

            if entry.is_empty() {
                continue;
            }

            let name = match entry.split_once(' ') {
                Some((ip, domain)) if ip.trim() == "0.0.0.0" && !domain.trim().is_empty() => domain,
                Some(_) => {
                    warn!("invalid blocklist entry '{entry}'; skipping entry");
                    continue;
                }
                None => entry,
            };

            let Ok(mut name) = LowerName::from_str(name) else {
                warn!("unable to derive LowerName for blocklist entry '{name}'; skipping entry");
                continue;
            };

            trace!("inserting blocklist entry {name}");

            // The boolean value is not significant; only the key is used.
            name.set_fqdn(true);
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
    /// wildcard expansion is done, if wildcard support is enabled for the blocklist zone handler.
    fn is_blocked(&self, name: &LowerName) -> bool {
        let mut match_list = vec![name.to_owned()];

        if self.wildcard_match {
            match_list.append(&mut self.wildcards(name));
        }

        trace!("blocklist match list: {match_list:?}");

        match_list
            .iter()
            .any(|entry| self.blocklist.contains_key(entry))
    }

    /// Generate a BlocklistLookup to return on a blocklist match.  This will return a lookup with
    /// either an A or AAAA record and, if the user has configured a block message, a TXT record
    /// with the contents of that message.
    fn blocklist_response(&self, name: Name, rtype: RecordType) -> Lookup {
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

        Lookup::new_with_deadline(
            Query::query(name.clone(), rtype),
            records.into(),
            Instant::now() + Duration::from_secs(u64::from(self.ttl)),
        )
    }
}

#[async_trait::async_trait]
impl ZoneHandler for BlocklistZoneHandler {
    fn zone_type(&self) -> ZoneType {
        ZoneType::External
    }

    fn axfr_policy(&self) -> AxfrPolicy {
        AxfrPolicy::Deny
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
        request_info: Option<&RequestInfo<'_>>,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        use LookupControlFlow::*;

        trace!("blocklist lookup: {name} {rtype}");

        #[cfg(feature = "metrics")]
        self.metrics.total_queries.increment(1);

        if self.is_blocked(name) {
            #[cfg(feature = "metrics")]
            {
                self.metrics.total_hits.increment(1);
                self.metrics.blocked_queries.increment(1);
            }
            match request_info {
                Some(info) if self.log_clients => info!(
                    query = %name,
                    client = %info.src,
                    action = "BLOCK",
                    "blocklist matched",
                ),
                _ => info!(
                    query = %name,
                    action = "BLOCK",
                    "blocklist matched",
                ),
            }
            return Break(Ok(AuthLookup::from(
                self.blocklist_response(Name::from(name), rtype),
            )));
        }

        trace!("query '{name}' is not in blocklist; returning Skip...");
        Skip
    }

    /// Optionally, perform a blocklist lookup after another zone handler has done a lookup for this
    /// query.
    async fn consult(
        &self,
        name: &LowerName,
        rtype: RecordType,
        request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
        last_result: LookupControlFlow<AuthLookup>,
    ) -> (
        LookupControlFlow<AuthLookup>,
        Option<Box<dyn ResponseSigner>>,
    ) {
        match self.consult_action {
            BlocklistConsultAction::Disabled => return (last_result, None),
            BlocklistConsultAction::Log => {
                #[cfg(feature = "metrics")]
                self.metrics.total_queries.increment(1);

                if self.is_blocked(name) {
                    #[cfg(feature = "metrics")]
                    {
                        self.metrics.logged_queries.increment(1);
                        self.metrics.total_hits.increment(1);
                    }
                    match request_info {
                        Some(info) if self.log_clients => {
                            info!(
                                query = %name,
                                client = %info.src,
                                action = "LOG",
                                "blocklist matched",
                            );
                        }
                        _ => info!(query = %name, action = "LOG", "blocklist matched"),
                    }
                }

                (last_result, None)
            }
            BlocklistConsultAction::Enforce => {
                let lookup = self.lookup(name, rtype, request_info, lookup_options).await;
                if lookup.is_break() {
                    (lookup, None)
                } else {
                    (last_result, None)
                }
            }
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

    async fn zone_transfer(
        &self,
        _request: &Request,
        _lookup_options: LookupOptions,
        _now: u64,
    ) -> Option<(
        Result<ZoneTransfer, LookupError>,
        Option<Box<dyn ResponseSigner>>,
    )> {
        None
    }

    async fn nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        LookupControlFlow::Continue(Err(LookupError::from(io::Error::other(
            "getting NSEC records is unimplemented for the blocklist",
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
        "blocklist"
    }
}

/// Consult action enum.  Controls how consult lookups are handled.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
pub enum BlocklistConsultAction {
    /// Do not log or block any request when the blocklist is called via consult
    #[default]
    Disabled,
    /// Log and block matching requests when the blocklist is called via consult
    Enforce,
    /// Log but do not block matching requests when the blocklist is called via consult
    Log,
}

/// Configuration for blocklist zones
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct BlocklistConfig {
    /// Support wildcards?  Defaults to true. If set to true, block list entries containing
    /// asterisks will be expanded to match queries.
    pub wildcard_match: bool,

    /// Minimum wildcard depth.  Defaults to 2.  Any wildcard entries without at least this many
    /// static elements will not be expanded (e.g., *.com has a depth of 1; *.example.com has a
    /// depth of two.) This is meant as a safeguard against an errant block list entry, such as *
    /// or *.com that might block many more hosts than intended.
    pub min_wildcard_depth: u8,

    /// Block lists to load.  These should be specified as relative (to the server zone directory)
    /// paths in the config file.
    pub lists: Vec<String>,

    /// IPv4 sinkhole IP. This is the IP that is returned when a blocklist entry is matched for an
    /// A query. If unspecified, an implementation-provided default will be used.
    pub sinkhole_ipv4: Option<Ipv4Addr>,

    /// IPv6 sinkhole IP.  This is the IP that is returned when a blocklist entry is matched for a
    /// AAAA query. If unspecified, an implementation-provided default will be used.
    pub sinkhole_ipv6: Option<Ipv6Addr>,

    /// Block TTL. This is the length of time a block response should be stored in the requesting
    /// resolvers cache, in seconds.  Defaults to 86,400 seconds.
    pub ttl: u32,

    /// Block message to return to the user.  This is an optional message that, if configured, will
    /// be returned as a TXT record in the additionals section when a blocklist entry is matched for
    /// a query.
    pub block_message: Option<String>,

    /// The consult action controls how the blocklist handles queries where another zone handler has
    /// already provided an answer.  By default, it ignores any such queries ("Disabled",) however
    /// it can be configured to log blocklist matches for those queries ("Log",) or can be
    /// configured to overwrite the previous responses ("Enforce".)
    pub consult_action: BlocklistConsultAction,

    /// Controls client IP logging for blocklist matches
    pub log_clients: bool,
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        Self {
            wildcard_match: true,
            min_wildcard_depth: 2,
            lists: vec![],
            sinkhole_ipv4: None,
            sinkhole_ipv6: None,
            ttl: 86_400,
            block_message: None,
            consult_action: BlocklistConsultAction::default(),
            log_clients: true,
        }
    }
}

#[cfg(feature = "metrics")]
struct BlocklistMetrics {
    entries: Gauge,
    blocked_queries: Counter,
    logged_queries: Counter,
    total_hits: Counter,
    total_queries: Counter,
}

#[cfg(feature = "metrics")]
impl BlocklistMetrics {
    fn new() -> Self {
        describe_gauge!(
            "hickory_blocklist_list_entries",
            Unit::Count,
            "The total number of entries in all configured blocklists",
        );
        describe_counter!(
            "hickory_blocklist_blocked_queries_total",
            Unit::Count,
            "The total number of requests that were blocked by the blocklist zone handler",
        );
        describe_counter!(
            "hickory_blocklist_logged_queries_total",
            Unit::Count,
            "The total number of requests that were logged by the blocklist zone handler",
        );
        describe_counter!(
            "hickory_blocklist_list_hits_total",
            Unit::Count,
            "The total number of requests that matched a blocklist entry",
        );
        describe_counter!(
            "hickory_blocklist_queries_total",
            Unit::Count,
            "The total number of requests the blocklist zone handler has processed",
        );

        Self {
            entries: gauge!("hickory_blocklist_list_entries"),
            blocked_queries: counter!("hickory_blocklist_blocked_queries_total"),
            logged_queries: counter!("hickory_blocklist_logged_queries_total"),
            total_hits: counter!("hickory_blocklist_list_hits_total"),
            total_queries: counter!("hickory_blocklist_queries_total"),
        }
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

    use super::*;
    use crate::{
        proto::rr::domain::Name,
        proto::rr::{
            LowerName, RData, RecordType,
            rdata::{A, AAAA},
        },
        zone_handler::LookupOptions,
    };
    use test_support::subscribe;

    #[tokio::test]
    async fn test_blocklist_basic() {
        subscribe();
        let config = BlocklistConfig {
            wildcard_match: true,
            min_wildcard_depth: 2,
            lists: vec!["default/blocklist.txt".to_string()],
            sinkhole_ipv4: None,
            sinkhole_ipv6: None,
            block_message: None,
            ttl: 86_400,
            consult_action: BlocklistConsultAction::Disabled,
            log_clients: true,
        };

        let h = handler(&config);
        let v4 = A::new(0, 0, 0, 0);
        let v6 = AAAA::new(0, 0, 0, 0, 0, 0, 0, 0);

        use RecordType::{A as Rec_A, AAAA as Rec_AAAA};
        use TestResult::*;
        // Test: lookup a record that is in the blocklist and that should match without a wildcard.
        basic_test(&h, "foo.com.", Rec_A, Break, Some(v4), None, None).await;

        // test: lookup a record that is not in the blocklist. This test should fail.
        basic_test(&h, "test.com.", Rec_A, Skip, None, None, None).await;

        // Test: lookup a record that will match a wildcard that is in the blocklist.
        basic_test(&h, "www.foo.com.", Rec_A, Break, Some(v4), None, None).await;

        // Test: lookup a record that will match a wildcard that is in the blocklist.
        basic_test(&h, "www.com.foo.com.", Rec_A, Break, Some(v4), None, None).await;

        // Test: lookup a record that is in the blocklist and that should match without a wildcard.
        basic_test(&h, "foo.com.", Rec_AAAA, Break, None, Some(v6), None).await;

        // test: lookup a record that is not in the blocklist. This test should fail.
        basic_test(&h, "test.com.", Rec_AAAA, Skip, None, None, None).await;

        // Test: lookup a record that will match a wildcard that is in the blocklist.
        basic_test(&h, "www.foo.com.", Rec_AAAA, Break, None, Some(v6), None).await;

        // Test: lookup a record that will match a wildcard that is in the blocklist.
        basic_test(&h, "ab.cd.foo.com.", Rec_AAAA, Break, None, Some(v6), None).await;
    }

    #[tokio::test]
    async fn test_blocklist_wildcard_disabled() {
        subscribe();
        let config = BlocklistConfig {
            min_wildcard_depth: 2,
            wildcard_match: false,
            lists: vec!["default/blocklist.txt".to_string()],
            sinkhole_ipv4: Some(Ipv4Addr::new(192, 0, 2, 1)),
            sinkhole_ipv6: Some(Ipv6Addr::new(0, 0, 0, 0, 0xc0, 0, 2, 1)),
            block_message: Some(String::from("blocked")),
            ttl: 86_400,
            consult_action: BlocklistConsultAction::Disabled,
            log_clients: true,
        };

        let h = handler(&config);
        let v4 = A::new(192, 0, 2, 1);
        let v6 = AAAA::new(0, 0, 0, 0, 0xc0, 0, 2, 1);
        let msg = config.block_message;

        use RecordType::{A as Rec_A, AAAA as Rec_AAAA};
        use TestResult::*;

        // Test: lookup a record that is in the blocklist and that should match without a wildcard.
        basic_test(&h, "foo.com.", Rec_A, Break, Some(v4), None, msg.clone()).await;

        // Test: lookup a record that is not in the blocklist, but would match a wildcard; this
        // should fail.
        basic_test(&h, "www.foo.com.", Rec_A, Skip, None, None, msg.clone()).await;

        // Test: lookup a record that is in the blocklist and that should match without a wildcard.
        basic_test(&h, "foo.com.", Rec_AAAA, Break, None, Some(v6), msg).await;
    }

    #[tokio::test]
    #[should_panic]
    async fn test_blocklist_wrong_block_message() {
        subscribe();
        let config = BlocklistConfig {
            min_wildcard_depth: 2,
            wildcard_match: false,
            lists: vec!["default/blocklist.txt".to_string()],
            sinkhole_ipv4: Some(Ipv4Addr::new(192, 0, 2, 1)),
            sinkhole_ipv6: Some(Ipv6Addr::new(0, 0, 0, 0, 0xc0, 0, 2, 1)),
            block_message: Some(String::from("blocked")),
            ttl: 86_400,
            consult_action: BlocklistConsultAction::Disabled,
            log_clients: true,
        };

        let h = handler(&config);
        let sinkhole_v4 = A::new(192, 0, 2, 1);

        // Test: lookup a record that is in the blocklist, but specify an incorrect block message to
        // match.
        basic_test(
            &h,
            "foo.com.",
            RecordType::A,
            TestResult::Break,
            Some(sinkhole_v4),
            None,
            Some(String::from("wrong message")),
        )
        .await;
    }

    #[tokio::test]
    async fn test_blocklist_hosts_format() {
        subscribe();
        let config = BlocklistConfig {
            min_wildcard_depth: 2,
            wildcard_match: true,
            lists: vec!["default/blocklist3.txt".to_string()],
            sinkhole_ipv4: Some(Ipv4Addr::new(192, 0, 2, 1)),
            sinkhole_ipv6: Some(Ipv6Addr::new(0, 0, 0, 0, 0xc0, 0, 2, 1)),
            block_message: Some(String::from("blocked")),
            ttl: 86_400,
            consult_action: BlocklistConsultAction::Disabled,
            log_clients: true,
        };

        let h = handler(&config);
        let v4 = A::new(192, 0, 2, 1);
        let msg = config.block_message;

        use TestResult::*;

        // Test: lookup a record from a blocklist file in plain format (only domain) which should match without a wildcard.
        basic_test(
            &h,
            "test.com.",
            RecordType::A,
            Break,
            Some(v4),
            None,
            msg.clone(),
        )
        .await;

        // Test: lookup a record from a blocklist file in hosts format (ip <space> domain) which should match without a wildcard.
        basic_test(
            &h,
            "anothertest.com.",
            RecordType::A,
            Break,
            Some(v4),
            None,
            msg.clone(),
        )
        .await;

        // Test: lookup a record from a blocklist file in hosts format (ip <space> domain) which should match with a wildcard.
        basic_test(
            &h,
            "yet.anothertest.com.",
            RecordType::A,
            Break,
            Some(v4),
            None,
            msg.clone(),
        )
        .await;
    }

    async fn basic_test(
        ao: &Arc<dyn ZoneHandler>,
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
                None,
                LookupOptions::default(),
            )
            .await;

        use LookupControlFlow::*;
        let lookup = match r_type {
            TestResult::Break => match res {
                Break(Ok(lookup)) => lookup,
                _ => panic!("Unexpected result for {query}: {res}"),
            },
            TestResult::Skip => match res {
                Skip => return,
                _ => {
                    panic!("unexpected result for {query}; expected Skip, found {res}");
                }
            },
        };

        if !lookup.iter().all(|x| match x.record_type() {
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

                x.name() == &Name::from_str(query).unwrap() && x.data() == &RData::AAAA(rec_ip)
            }
            _ => {
                let Some(rec_ip) = ipv4 else {
                    panic!("expected to validate record IPv4, but None was passed");
                };

                x.name() == &Name::from_str(query).unwrap() && x.data() == &RData::A(rec_ip)
            }
        }) {
            panic!("{query} lookup data is incorrect.");
        }
    }

    fn handler(config: &BlocklistConfig) -> Arc<dyn ZoneHandler> {
        let handler = BlocklistZoneHandler::try_from_config(
            Name::root(),
            config,
            Some(Path::new("../../tests/test-data/test_configs/")),
        );

        // Test: verify the blocklist zone handler was successfully created.
        match handler {
            Ok(handler) => Arc::new(handler),
            Err(error) => panic!("error creating blocklist zone handler: {error}"),
        }
    }

    enum TestResult {
        Break,
        Skip,
    }
}
