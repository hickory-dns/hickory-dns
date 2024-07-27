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

#[cfg(any(feature = "dns-over-quic", feature = "dns-over-h3"))]
pub use self::connection_provider::QuicSocketBinder;
pub use self::connection_provider::{ConnectionProvider, RuntimeProvider, Spawn};
pub use self::connection_provider::{GenericConnection, GenericConnector};
pub use self::name_server::{GenericNameServer, NameServer};
pub use self::name_server_pool::{GenericNameServerPool, NameServerPool};
use self::name_server_state::NameServerState;
use self::name_server_stats::NameServerStats;

#[cfg(feature = "tokio-runtime")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio-runtime")))]
pub use self::connection_provider::tokio_runtime::{
    TokioConnectionProvider, TokioHandle, TokioRuntimeProvider,
};
