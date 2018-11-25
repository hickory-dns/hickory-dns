// Copyright 2015-2016 Benjamin Fry <benjaminfry -@- me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Master file based serving with Dynamic DNS and journaling support

mod authority;
mod config;

pub use self::authority::Authority;
pub use self::config::Config;