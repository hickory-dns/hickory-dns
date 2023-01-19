// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(feature = "dns-over-openssl")]
#![allow(dead_code)]

use std::net::SocketAddr;
use std::pin::Pin;

use futures_util::future::Future;

use proto::error::ProtoError;
use proto::openssl::{TlsClientStream, TlsClientStreamBuilder};
use proto::tcp::Connect;
use proto::BufDnsStreamHandle;

#[allow(clippy::type_complexity)]
pub(crate) fn new_tls_stream<S: Connect>(
    socket_addr: SocketAddr,
    bind_addr: Option<SocketAddr>,
    dns_name: String,
) -> (
    Pin<Box<dyn Future<Output = Result<TlsClientStream<S>, ProtoError>> + Send>>,
    BufDnsStreamHandle,
) {
    let mut tls_builder = TlsClientStreamBuilder::new();
    if let Some(bind_addr) = bind_addr {
        tls_builder.bind_addr(bind_addr);
    }
    tls_builder.build(socket_addr, dns_name)
}
