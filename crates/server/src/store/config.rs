// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Configuration for the stores

use crate::store::file::FileConfig;
#[cfg(feature = "trust-dns-resolver")]
use crate::store::forwarder::ForwardConfig;
#[cfg(feature = "sqlite")]
use crate::store::sqlite::SqliteConfig;

/// Enumeration over all Store configurations
#[derive(Deserialize, PartialEq, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "lowercase")]
pub enum StoreConfig {
    /// File based configuration
    File(FileConfig),
    /// Sqlite based configuration file
    #[cfg(feature = "sqlite")]
    Sqlite(SqliteConfig),
    /// Forwarder, aka Resolver
    #[cfg(feature = "trust-dns-resolver")]
    Forward(ForwardConfig),
}
