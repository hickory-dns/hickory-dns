// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! System configuration loading
//!
//! This module is responsible for parsing and returning the configuration from
//!  the host system. It will read from the default location on each operating
//!  system, e.g. most Unixes have this written to `/etc/resolv.conf`
#![allow(missing_docs, unused_extern_crates)]

#[cfg(unix)]
#[cfg(feature = "system-config")]
mod unix;

#[cfg(unix)]
#[cfg(feature = "system-config")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "system-config", unix))))]
pub use self::unix::{parse_resolv_conf, read_system_conf};

#[cfg(windows)]
#[cfg(feature = "system-config")]
mod windows;

#[cfg(target_os = "windows")]
#[cfg(feature = "system-config")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "system-config", windows))))]
pub use self::windows::read_system_conf;
