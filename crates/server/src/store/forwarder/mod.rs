// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(feature = "resolver")]

//! Forwarding resolver related types

use serde::Deserialize;

use crate::resolver::config::{NameServerConfigGroup, ResolverOpts};

mod authority;
pub use authority::{ForwardAuthority, ForwardLookup};

/// Configuration for file based zones
#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ForwardConfig {
    /// upstream name_server configurations
    pub name_servers: NameServerConfigGroup,
    /// Resolver options
    pub options: Option<ResolverOpts>,
}
