// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(feature = "dns-over-native-tls")]
#![allow(dead_code)]

use std::net::SocketAddr;

use futures::Future;

use trust_dns_native_tls::{TlsClientStream, TlsClientStreamBuilder};
use proto::error::ProtoError;
use proto::BufDnsStreamHandle;

pub(crate) fn new_tls_stream(
    socket_addr: SocketAddr,
    dns_name: String,
) -> (
    Box<dyn Future<Item = TlsClientStream, Error = ProtoError> + Send>,
    BufDnsStreamHandle,
) {
    let tls_builder = TlsClientStreamBuilder::new();
    tls_builder.build(socket_addr, dns_name)
}
