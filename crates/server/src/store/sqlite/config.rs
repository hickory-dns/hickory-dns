// Copyright 2015-2018 Benjamin Fry <benjaminfry -@- me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use serde::Deserialize;

/// Configuration for zone file for sqlite based zones
#[derive(Deserialize, PartialEq, Eq, Debug)]
pub struct SqliteConfig {
    /// path to initial zone file
    pub zone_file_path: String,
    /// path to the sqlite journal file
    pub journal_file_path: String,
    /// Are updates allowed to this zone
    #[serde(default)]
    pub allow_update: bool,
}
