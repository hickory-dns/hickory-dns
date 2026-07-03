// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! System configuration loading
//!
//! This module is responsible for parsing and returning the configuration from
//! the host system. It will read from the default location on each operating
//! system, e.g. most Unixes have this written to `/etc/resolv.conf`
#![allow(missing_docs)]

mod resolv_conf;

// `read_resolv_conf` `parse_resolv_conf` are simply utility functions for
// parsing a `resolv.conf` file, so it can be available on all platforms
pub use self::resolv_conf::{parse_resolv_conf, read_resolv_conf};

#[cfg(any(
    // If the user has explicitly opted into resolv.conf as their primary
    // "default system config", then compile it regardless of target platform
    feature = "system-config-resolv-conf",

    // Otherwise, if they have not explicitly opted into `resolv.conf`, but
    // have activated the general `system-config` feature, then choose platforms
    // where `resolv.conf` is typically the primary system configuration for
    // DNS.
    all(
        feature = "system-config",
        unix,
        not(any(target_vendor = "apple", target_os = "android")),
    )
))]
pub use self::resolv_conf::read_system_conf;

#[cfg(all(
    windows,
    feature = "system-config",
    not(feature = "system-config-resolv-conf"),
))]
mod windows;

#[cfg(all(
    windows,
    feature = "system-config",
    not(feature = "system-config-resolv-conf"),
))]
pub use self::windows::read_system_conf;

#[cfg(all(
    feature = "system-config",
    target_os = "android",
    not(feature = "system-config-resolv-conf"),
))]
mod android;

#[cfg(all(
    feature = "system-config",
    target_os = "android",
    not(feature = "system-config-resolv-conf"),
))]
pub use self::android::read_system_conf;

#[cfg(all(
    feature = "system-config",
    target_vendor = "apple",
    not(feature = "system-config-resolv-conf"),
))]
mod apple;

#[cfg(all(
    feature = "system-config",
    target_vendor = "apple",
    not(feature = "system-config-resolv-conf"),
))]
pub use self::apple::read_system_conf;
