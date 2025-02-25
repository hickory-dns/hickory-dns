// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! A module with associated items for working with nameservers

mod connection_provider;
#[allow(clippy::module_inception)]
mod name_server;
mod name_server_pool;
mod name_server_state;
mod name_server_stats;

pub use self::connection_provider::{ConnectionProvider, GenericConnection, GenericConnector};
pub use self::name_server::{GenericNameServer, NameServer};
pub use self::name_server_pool::{GenericNameServerPool, NameServerPool};
use self::name_server_state::NameServerState;
use self::name_server_stats::NameServerStats;

#[cfg(feature = "tokio")]
pub use self::connection_provider::TokioConnectionProvider;
