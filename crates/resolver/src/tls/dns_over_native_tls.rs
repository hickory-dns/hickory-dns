// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(feature = "dns-over-native-tls")]
#![allow(dead_code)]

use std::net::SocketAddr;
use std::pin::Pin;

use futures_util::future::Future;

use proto::error::ProtoError;
use proto::native_tls::{TlsClientStream, TlsClientStreamBuilder};
use proto::tcp::DnsTcpStream;
use proto::BufDnsStreamHandle;

#[allow(clippy::type_complexity)]
pub(crate) fn new_tls_stream_with_future<S, F>(
    future: F,
    socket_addr: SocketAddr,
    dns_name: String,
) -> (
    Pin<Box<dyn Future<Output = Result<TlsClientStream<S>, ProtoError>> + Send>>,
    BufDnsStreamHandle,
)
where
    S: DnsTcpStream,
    F: Future<Output = std::io::Result<S>> + Send + Unpin + 'static,
{
    TlsClientStreamBuilder::new().build_with_future(future, socket_addr, dns_name)
}
