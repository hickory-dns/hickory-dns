// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

mod connection_provider;
mod name_server_pool;
mod name_server_state;
mod name_server_stats;
#[allow(clippy::module_inception)]
mod name_server;

use self::name_server_state::NameServerState;
use self::name_server_stats::NameServerStats;
pub use self::name_server_pool::NameServerPool;
pub use self::connection_provider::ConnectionProvider;
pub(crate) use self::connection_provider::{StandardConnection, ConnectionHandle};
pub use self::name_server::NameServer;
#[cfg(feature = "mdns")]
pub(crate) use self::name_server::mdns_nameserver;