// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! System configuration loading
//!
//! This module is resposible for parsing and returning the configuration from
//!  the host system. It will read from the default location on each operating
//!  system, e.g. most Unixes have this written to `/etc/resolv.conf`
#![allow(missing_docs, unused_extern_crates)]

#[cfg(unix)]
mod unix;

#[cfg(unix)]
pub(crate) use self::unix::read_system_conf;

#[cfg(all(feature = "ipconfig", target_os = "windows", target_pointer_width = "64"))]
mod windows;

/// Support only 64-bit until https://github.com/liranringel/ipconfig/issues/1 is resolved.
#[cfg(all(feature = "ipconfig", target_os = "windows", target_pointer_width = "64"))]
pub(crate) use self::windows::read_system_conf;
