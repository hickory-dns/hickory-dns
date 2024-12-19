// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(deprecated, clippy::use_self)]

use serde::{Deserialize, Serialize};

/// The type of zone stored in a Catalog
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
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
    /// A cached zone that queries other nameservers
    External,
}

impl ZoneType {
    /// Is this an authoritative Authority, i.e. it owns the records of the zone.
    pub fn is_authoritative(self) -> bool {
        matches!(
            self,
            Self::Primary | Self::Secondary | Self::Master | Self::Slave
        )
    }
}
