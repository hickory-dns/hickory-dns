// Copyright 2015-2018 Benjamin Fry <benjaminfry -@- me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! SQLite serving with Dynamic DNS and journaling support

pub mod authority;
mod config;
pub mod persistence;

pub use self::authority::SqliteAuthority;
pub use self::config::SqliteConfig;
pub use self::persistence::Journal;
