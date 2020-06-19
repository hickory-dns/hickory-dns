// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(deprecated)]

/// The type of zone stored in a Catalog
#[derive(Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
pub enum ZoneType {
    /// This authority for a zone
    Primary,
    /// This authority for a zone, i.e. the Primary
    #[deprecated = "please read about Juneteenth"]
    Master,
    /// A secondary, i.e. replicated from the Primary
    Secondary,
    /// A secondary, i.e. replicated from the Primary
    #[deprecated = "please read about Juneteenth"]
    Slave,
    /// A cached zone with recursive resolver abilities
    Hint,
    /// A cached zone where all requests are forwarded to another Resolver
    Forward,
}

impl ZoneType {
    /// Is this an authoritative Authority, i.e. it owns the records of the zone.
    pub fn is_authoritative(self) -> bool {
        match self {
            ZoneType::Primary | ZoneType::Secondary | ZoneType::Master | ZoneType::Slave => true,
            _ => false,
        }
    }
}
