// Copyright 2015-2018 Benjamin Fry <benjaminfry -@- me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! SQLite serving with Dynamic DNS and journaling support

use std::path::PathBuf;

use serde::Deserialize;

pub mod authority;
pub use authority::SqliteAuthority;
pub mod persistence;
pub use persistence::Journal;

/// Configuration for zone file for sqlite based zones
#[derive(Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct SqliteConfig {
    /// path to initial zone file
    pub zone_file_path: PathBuf,
    /// path to the sqlite journal file
    pub journal_file_path: String,
    /// Are updates allowed to this zone
    #[serde(default)]
    pub allow_update: bool,
}
