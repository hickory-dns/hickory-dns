// Copyright 2015-2018 Benjamin Fry <benjaminfry -@- me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! All persistent store implementations

pub mod blocklist;
pub mod file;
pub mod forwarder;
pub mod in_memory;
pub mod recursor;
#[cfg(feature = "sqlite")]
pub mod sqlite;
