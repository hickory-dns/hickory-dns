// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use serde::Deserialize;

/// Configuration for file based zones
#[derive(Clone, Deserialize, Eq, PartialEq, Debug)]
pub struct BlocklistConfig {
    /// Support wildcards?  If set to true, block list entries containing asterisks will be expanded to match queries.
    #[serde(default = "wildcard_match_default")]
    pub wildcard_match: bool,

    /// Minimum wildcard depth.  Defaults to 2.  Any wildcard entries without at least this many static elements will not be expanded
    /// (e.g., *.com has a depth of 1; *.example.com has a depth of two.)
    #[serde(default = "min_wildcard_depth_default")]
    pub min_wildcard_depth: u8,

    /// This is meant as a safeguard against an errant block list entry, such as * or *.com that
    /// might block many more hosts than intended.  
    /// block lists to load.  These should be specified as relative (to the server zone directory) paths in the config file.
    pub lists: Vec<String>,
}

impl BlocklistConfig {
    /// the set of block lists which should be loaded
    pub fn get_block_lists(&self) -> &Vec<String> {
        &self.lists
    }
}

fn wildcard_match_default() -> bool {
    true
}
fn min_wildcard_depth_default() -> u8 {
    2
}
