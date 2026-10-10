// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TLS protocol related components for DNS over HTTP/3 (DoH3)

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Buf;
use futures_util::Stream;

use crate::NetError;

mod h3_client_stream;
pub use h3_client_stream::{H3ClientStream, H3ClientStreamBuilder};
mod h3_config;
mod h3_listener;

pub use h3_listener::{H3Connection, H3Listener};

/// [`Stream`] adapter for h3 body streaming.
pub struct BodyStream<T>(T);

impl<T, B> Stream for BodyStream<T>
where
    T: FnMut(&mut Context<'_>) -> Poll<Result<Option<B>, h3::error::StreamError>> + Unpin,
    B: Buf,
{
    type Item = Result<B, NetError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let Poll::Ready(result) = (this.0)(cx) else {
            return Poll::Pending;
        };

        Poll::Ready(match result {
            Ok(Some(buf)) => Some(Ok(buf)),
            Ok(None) => None,
            Err(e) => Some(Err(NetError::from(format!(
                "h3 stream receive data failed: {e}"
            )))),
        })
    }
}

impl<T, B> From<T> for BodyStream<T>
where
    T: FnMut(&mut Context<'_>) -> Poll<Result<Option<B>, h3::error::StreamError>> + Unpin,
    B: Buf,
{
    fn from(stream: T) -> Self {
        Self(stream)
    }
}
