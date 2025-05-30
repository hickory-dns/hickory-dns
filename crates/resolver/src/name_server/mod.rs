// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! A module with associated items for working with nameservers

mod connection_provider;
#[cfg(feature = "tokio")]
pub use connection_provider::TokioConnectionProvider;
pub use connection_provider::{ConnectionProvider, GenericConnection, GenericConnector};
#[allow(clippy::module_inception)]
mod name_server;
pub use name_server::NameServer;
mod name_server_pool;
pub use name_server_pool::{GenericNameServerPool, NameServerPool};

/// Specifies the details of a remote NameServer used for lookups
pub type GenericNameServer<R> = NameServer<GenericConnector<R>>;
