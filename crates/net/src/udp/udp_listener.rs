use core::future::poll_fn;
use core::pin::Pin;
use core::task::Poll;
use std::fmt;
use std::io;

use futures_util::{Stream, ready};
use tracing::{debug, warn};

use crate::{
    proto::op::SerialMessage, runtime::DnsUdpSocket, udp::UdpStream, utils::sanitize_src_addr,
};

/// Receives UDP messages whose source addresses are safe for responses.
///
/// Server-side validation lives here so client streams retain their existing receive behavior.
pub struct UdpListener<S: DnsUdpSocket> {
    stream: UdpStream<S>,
}

impl<S: DnsUdpSocket> fmt::Debug for UdpListener<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpListener").finish_non_exhaustive()
    }
}

impl<S: DnsUdpSocket> UdpListener<S> {
    /// Wraps an existing UDP stream.
    pub fn new(stream: UdpStream<S>) -> Self {
        Self { stream }
    }

    /// Receives a UDP message whose source address is safe for responses.
    ///
    /// Each poll checks at most one candidate message. Messages from unsafe source addresses
    /// are dropped, and the task is woken to poll again. Receiving continues to drive the
    /// stream's outgoing message queue, and socket errors are returned without retrying.
    ///
    /// The source must have a nonzero port and an IP address that is neither unspecified nor
    /// an IPv4 broadcast address.
    pub async fn receive(&mut self) -> Option<io::Result<SerialMessage>> {
        poll_fn(|cx| {
            let message = match ready!(Pin::new(&mut self.stream).poll_next(cx)) {
                Some(Ok(message)) => message,
                result => return Poll::Ready(result),
            };
            let src_addr = message.addr();
            debug!("received udp request from: {}", src_addr);
            if let Err(e) = sanitize_src_addr(src_addr) {
                warn!("address can not be responded to {src_addr}: {e}");
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(Some(Ok(message)))
        })
        .await
    }
}
