// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
// Copyright 2017 Google LLC.
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![warn(missing_docs)]
#![recursion_limit = "2048"]

//! TRust-DNS Protocol library

extern crate byteorder;
#[cfg(feature = "dnssec")]
extern crate data_encoding;
#[cfg(test)]
extern crate env_logger;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate futures;
extern crate idna;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[cfg(feature = "openssl")]
extern crate openssl;
extern crate rand;
#[cfg(feature = "ring")]
extern crate ring;
extern crate smallvec;
extern crate socket2;
#[macro_use]
extern crate tokio_core;
extern crate tokio_io;
#[cfg(feature = "ring")]
extern crate untrusted;
extern crate url;

pub mod error;
#[cfg(feature = "mdns")]
pub mod multicast;
pub mod op;
pub mod rr;
pub mod serialize;
pub mod tcp;
pub mod udp;
pub mod xfer;

pub use xfer::dns_future::DnsFuture;
pub use xfer::dns_handle::{BasicDnsHandle, DnsHandle, DnsStreamHandle, StreamHandle};
pub use xfer::retry_dns_handle::RetryDnsHandle;
#[cfg(feature = "dnssec")]
pub use xfer::secure_dns_handle::SecureDnsHandle;
pub use xfer::{BufDnsStreamHandle, BufStreamHandle, MessageStreamHandle};