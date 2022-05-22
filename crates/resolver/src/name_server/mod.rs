// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! A module with associated items for working with nameservers

mod connection_provider;
#[allow(clippy::module_inception)]
mod name_server;
mod name_server_pool;
mod name_server_state;
mod name_server_stats;

pub use self::connection_provider::{ConnectionProvider, RuntimeProvider, Spawn};
pub use self::connection_provider::{GenericConnection, GenericConnectionProvider};
#[cfg(feature = "mdns")]
#[cfg_attr(docsrs, doc(cfg(feature = "mdns")))]
pub(crate) use self::name_server::mdns_nameserver;
pub use self::name_server::NameServer;
pub use self::name_server_pool::NameServerPool;
use self::name_server_state::NameServerState;
use self::name_server_stats::NameServerStats;

#[cfg(feature = "tokio-runtime")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio-runtime")))]
pub use self::connection_provider::tokio_runtime::{
    TokioConnection, TokioConnectionProvider, TokioHandle, TokioRuntime,
};
