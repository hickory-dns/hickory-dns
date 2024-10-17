// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(feature = "dns-over-openssl")]
#![allow(dead_code)]

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use crate::proto::error::ProtoError;
use crate::proto::openssl::{TlsClientStream, TlsClientStreamBuilder};
use crate::proto::runtime::RuntimeProvider;
use crate::proto::BufDnsStreamHandle;

#[allow(clippy::type_complexity)]
pub(crate) fn new_tls_stream_with_future<P: RuntimeProvider, F>(
    future: F,
    socket_addr: SocketAddr,
    dns_name: String,
    provider: P,
) -> (
    Pin<Box<dyn Future<Output = Result<TlsClientStream<P::Tcp>, ProtoError>> + Send>>,
    BufDnsStreamHandle,
)
where
    F: Future<Output = std::io::Result<P::Tcp>> + Send + Unpin + 'static,
{
    TlsClientStreamBuilder::new(provider).build_with_future(future, socket_addr, dns_name)
}
