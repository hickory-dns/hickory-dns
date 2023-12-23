// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Configuration for the stores

use serde::Deserialize;

#[cfg(feature = "blocklist")]
use crate::store::blocklist::BlockListConfig;
use crate::store::file::FileConfig;
#[cfg(feature = "hickory-resolver")]
use crate::store::forwarder::ForwardConfig;
#[cfg(feature = "hickory-recursor")]
use crate::store::recursor::RecursiveConfig;
#[cfg(feature = "sqlite")]
use crate::store::sqlite::SqliteConfig;

/// Enumeration over all Store configurations
#[derive(Deserialize, PartialEq, Eq, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum StoreConfig {
    /// File based configuration
    File(FileConfig),
    /// Sqlite based configuration file
    #[cfg(feature = "sqlite")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sqlite")))]
    Sqlite(SqliteConfig),
    /// Forwarding Resolver
    #[cfg(feature = "hickory-resolver")]
    #[cfg_attr(docsrs, doc(cfg(feature = "resolver")))]
    Forward(ForwardConfig),
    /// Recursive Resolver
    #[cfg(feature = "hickory-recursor")]
    #[cfg_attr(docsrs, doc(cfg(feature = "recursor")))]
    Recursor(RecursiveConfig),
    /// Blocklist Resolver
    #[cfg(feature = "blocklist")]
    BlockList(BlockListConfig),
    /// This is used by the configuration processing code to represent a deprecated or main-block config without an associated store.
    Default,
}
