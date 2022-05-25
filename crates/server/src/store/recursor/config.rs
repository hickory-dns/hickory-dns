// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{
    fs::File,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use serde::Deserialize;
use trust_dns_client::{
    rr::{RData, Record, RecordSet},
    serialize::txt::{Lexer, Parser},
};

use crate::error::ConfigError;

/// Configuration for file based zones
#[derive(Clone, Deserialize, PartialEq, Debug)]
pub struct RecursiveConfig {
    /// File with hints
    pub hints: PathBuf,
}

impl RecursiveConfig {
    pub(crate) fn read_hints(&self) -> Result<Vec<SocketAddr>, ConfigError> {
        let mut hints = File::open(&self.hints)?;
        let mut hints_str = String::new();
        hints.read_to_string(&mut hints_str)?;

        let lexer = Lexer::new(&hints_str);
        let mut parser = Parser::new();

        let (_zone, hints_zone) = parser.parse(lexer, None, None)?;

        // TODO: we may want to deny some of the root nameservers, for reasons...
        Ok(hints_zone
            .values()
            .flat_map(RecordSet::records_without_rrsigs)
            .filter_map(Record::data)
            .filter_map(RData::as_ip_addr) // we only want IPs
            .map(|ip| SocketAddr::from((ip, 53))) // all the hints only have tradition DNS ports
            .collect())
    }
}
