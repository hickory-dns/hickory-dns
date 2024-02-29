// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(feature = "blocklist")]

//! Blocklist resolver related types
mod authority;

pub use self::authority::BlocklistAuthority;

use serde::Deserialize;
use std::net::{Ipv4Addr, Ipv6Addr};

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

/// Configuration for file based zones
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

    /// The consult action controls how the blocklist handles queries where another authority has
    /// already provided an answer.  By default, it ignores any such queries ("Disabled",) however
    /// it can be configured to log blocklist matches for those queries ("Log",) or can be
    /// configured to overwrite the previous responses ("Enforce".)
    pub consult_action: BlocklistConsultAction,
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
        }
    }
}
