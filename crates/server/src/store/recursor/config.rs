// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{
    borrow::Cow,
    fs::File,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::Deserialize;

use crate::error::ConfigError;
use crate::proto::{
    rr::{RData, Record, RecordSet},
    serialize::txt::Parser,
};
use crate::resolver::Name;

/// Configuration for file based zones
#[derive(Clone, Deserialize, Eq, PartialEq, Debug)]
pub struct RecursiveConfig {
    /// File with roots, aka hints
    pub roots: PathBuf,

    /// Maximum nameserver cache size
    #[serde(default = "ns_cache_size_default")]
    pub ns_cache_size: usize,

    /// Maximum DNS record cache size
    #[serde(default = "record_cache_size_default")]
    pub record_cache_size: usize,
}

impl RecursiveConfig {
    pub(crate) fn read_roots(
        &self,
        root_dir: Option<&Path>,
    ) -> Result<Vec<SocketAddr>, ConfigError> {
        let path = if let Some(root_dir) = root_dir {
            Cow::Owned(root_dir.join(&self.roots))
        } else {
            Cow::Borrowed(&self.roots)
        };

        let mut roots = File::open(path.as_ref())?;
        let mut roots_str = String::new();
        roots.read_to_string(&mut roots_str)?;

        let (_zone, roots_zone) =
            Parser::new(roots_str, Some(path.into_owned()), Some(Name::root())).parse()?;

        // TODO: we may want to deny some of the root nameservers, for reasons...
        Ok(roots_zone
            .values()
            .flat_map(RecordSet::records_without_rrsigs)
            .filter_map(Record::data)
            .filter_map(RData::ip_addr) // we only want IPs
            .map(|ip| SocketAddr::from((ip, 53))) // all the roots only have tradition DNS ports
            .collect())
    }
}

fn ns_cache_size_default() -> usize { 1024 }
fn record_cache_size_default() -> usize { 1048576 }
