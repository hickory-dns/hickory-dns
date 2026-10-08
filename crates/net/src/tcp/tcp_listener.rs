use std::{future::poll_fn, io, task::Poll};

use tracing::warn;

use crate::{
    runtime::{Accepted, DnsTcpListener},
    utils::sanitize_src_addr,
};

/// Accepts TCP connections whose peer addresses are safe for responses.
#[derive(Debug)]
pub struct TcpListener<L: DnsTcpListener> {
    listener: L,
}

impl<L: DnsTcpListener> TcpListener<L> {
    /// Wraps an already-bound TCP listener.
    pub fn new(listener: L) -> Self {
        Self { listener }
    }

    /// Accepts a connection whose peer address is safe for responses.
    ///
    /// Each poll checks at most one candidate connection. Connections from unsafe source
    /// addresses are dropped, and the task is woken to poll again.
    /// Listener errors are returned without retrying.
    ///
    /// The peer must have a nonzero port and an IP address that is neither unspecified nor
    /// an IPv4 broadcast address.
    /// Cancelling this future preserves the cancellation guarantees of
    /// [`DnsTcpListener::poll_accept`].
    pub async fn accept(&mut self) -> io::Result<Accepted<L::Stream>> {
        poll_fn(|cx| {
            let accepted = core::task::ready!(self.listener.poll_accept(cx))?;
            let src_addr = accepted.src_addr;
            if let Err(error) = sanitize_src_addr(src_addr) {
                warn!(%src_addr, %error, "address can not be responded to");
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(Ok(accepted))
        })
        .await
    }
}
