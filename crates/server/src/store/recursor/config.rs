// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{
    borrow::Cow,
    fs::File,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use trust_dns_client::{
    rr::{DNSClass, RData, Record, RecordSet},
    serialize::txt::{Lexer, Parser},
};
use trust_dns_resolver::Name;

use crate::error::ConfigError;

/// Configuration for file based zones
#[derive(Clone, Deserialize, Eq, PartialEq, Debug)]
pub struct RecursiveConfig {
    /// File with roots, aka hints
    pub roots: PathBuf,
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

        let lexer = Lexer::new(&roots_str);
        let mut parser = Parser::new();

        let (_zone, roots_zone) = parser.parse(lexer, Some(Name::root()), Some(DNSClass::IN))?;

        // TODO: we may want to deny some of the root nameservers, for reasons...
        Ok(roots_zone
            .values()
            .flat_map(RecordSet::records_without_rrsigs)
            .filter_map(Record::data)
            .filter_map(RData::to_ip_addr) // we only want IPs
            .map(|ip| SocketAddr::from((ip, 53))) // all the roots only have tradition DNS ports
            .collect())
    }
}
