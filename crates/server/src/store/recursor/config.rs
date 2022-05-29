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
#[derive(Clone, Deserialize, PartialEq, Debug)]
pub struct RecursiveConfig {
    /// File with hints
    pub hints: PathBuf,
}

impl RecursiveConfig {
    pub(crate) fn read_hints(
        &self,
        root_dir: Option<&Path>,
    ) -> Result<Vec<SocketAddr>, ConfigError> {
        let path = if let Some(root_dir) = root_dir {
            Cow::Owned(root_dir.join(&self.hints))
        } else {
            Cow::Borrowed(&self.hints)
        };

        let mut hints = File::open(path.as_ref())?;
        let mut hints_str = String::new();
        hints.read_to_string(&mut hints_str)?;

        let lexer = Lexer::new(&hints_str);
        let mut parser = Parser::new();

        let (_zone, hints_zone) = parser.parse(lexer, Some(Name::root()), Some(DNSClass::IN))?;

        // TODO: we may want to deny some of the root nameservers, for reasons...
        Ok(hints_zone
            .values()
            .flat_map(RecordSet::records_without_rrsigs)
            .filter_map(Record::data)
            .filter_map(RData::to_ip_addr) // we only want IPs
            .map(|ip| SocketAddr::from((ip, 53))) // all the hints only have tradition DNS ports
            .collect())
    }
}
