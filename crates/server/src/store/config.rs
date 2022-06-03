// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Configuration for the stores

use serde::Deserialize;

use crate::store::file::FileConfig;
#[cfg(feature = "trust-dns-resolver")]
use crate::store::forwarder::ForwardConfig;
#[cfg(feature = "trust-dns-recursor")]
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
    #[cfg(feature = "trust-dns-resolver")]
    #[cfg_attr(docsrs, doc(cfg(feature = "resolver")))]
    Forward(ForwardConfig),
    /// Recursive Resolver
    #[cfg(feature = "trust-dns-recursor")]
    #[cfg_attr(docsrs, doc(cfg(feature = "recursor")))]
    Recursor(RecursiveConfig),
}
