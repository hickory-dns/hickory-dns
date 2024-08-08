// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use serde::Deserialize;

/// Configuration for file based zones
#[derive(Deserialize, PartialEq, Eq, Debug)]
pub struct FileConfig {
    /// path to the zone file
    pub zone_file_path: String,
}

impl FileConfig {
    /// Create a new [`FileConfig`] from a path.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            zone_file_path: path.into(),
        }
    }
}
