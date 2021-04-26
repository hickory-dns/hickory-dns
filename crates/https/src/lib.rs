// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TLS protocol related components for DNS over TLS

// LIBRARY WARNINGS
#![warn(
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::unimplemented,
    missing_copy_implementations,
    missing_docs,
    non_snake_case,
    non_upper_case_globals,
    rust_2018_idioms,
    unreachable_pub
)]
#![allow(clippy::single_component_path_imports)]

//! Deprecated and removed as of 0.21.0, see the dns-over-https-rustls feature in `trust-dns-proto`

#![deprecated = "moved to trust_dns_proto::https"]

pub use trust_dns_proto::https::*;
