// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
// Copyright 2017 Google LLC.
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![warn(missing_docs)]
#![recursion_limit = "2048"]

//! Trust-DNS Protocol library

extern crate async_trait;
#[cfg(feature = "dnssec")]
extern crate data_encoding;
#[macro_use]
extern crate enum_as_inner;
#[cfg(test)]
extern crate env_logger;
extern crate failure;
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
#[cfg(feature = "serde-config")]
extern crate serde;
extern crate smallvec;
extern crate socket2;
#[cfg(test)]
extern crate tokio;
extern crate tokio_executor;
extern crate tokio_io;
extern crate tokio_sync;
#[cfg(feature = "tokio-compat")]
extern crate tokio_net;
extern crate tokio_timer;
extern crate url;

macro_rules! try_ready_stream {
    ($e:expr) => ({
        match $e {
            Poll::Ready(Some(Ok(t))) => t,
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(From::from(e)))),
        }
    })
}

pub mod error;
#[cfg(feature = "mdns")]
pub mod multicast;
pub mod op;
pub mod rr;
pub mod serialize;
pub mod tcp;
pub mod udp;
pub mod xfer;

#[doc(hidden)]
pub use crate::xfer::dns_handle::{BasicDnsHandle, DnsHandle, DnsStreamHandle, StreamHandle};
#[doc(hidden)]
pub use crate::xfer::dns_multiplexer::DnsMultiplexer;
#[doc(hidden)]
pub use crate::xfer::retry_dns_handle::RetryDnsHandle;
#[doc(hidden)]
#[cfg(feature = "dnssec")]
pub use crate::xfer::secure_dns_handle::SecureDnsHandle;
#[doc(hidden)]
pub use crate::xfer::{BufDnsStreamHandle, BufStreamHandle, MessageStreamHandle};
