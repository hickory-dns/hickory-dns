// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(feature = "trust-dns-resolver")]

//! Forwarding resolver related types

mod authority;
mod config;

pub use self::authority::ForwardAuthority;
pub use self::authority::ForwardLookup;
pub use self::config::ForwardConfig;
