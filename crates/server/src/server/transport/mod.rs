//! Transport protocol abstractions and builders for server registration.

use std::{future::Future, sync::Arc};

use tokio::task::JoinSet;

use crate::net::NetError;
use crate::server::{ServerContext, request_handler::RequestHandler};

/// # Task ownership
///
/// The returned future owns the listening resource:
///
/// * The cancellation signal is obtained from the [`ServerContext`] it is given.
/// * Built-in transports own UDP requests or accepted connections in a local
///   `JoinSet`, which cancels those tasks when the returned future is dropped.
/// * Protocols may spawn requests independently of the connection task. The transport
///   chooses how to finish accepted work when it stops.
/// * The server waits for the registered transport futures. It does not separately
///   wait for child tasks to finish cancellation.
pub(super) trait Transport: Sized + Send + 'static {
    /// Listener closure returns `Ok(false)` so it can be checked against shutdown.
    /// Successful input and recoverable errors return `Ok(true)`; other errors propagate directly.
    fn accept<H: RequestHandler>(
        &mut self,
        cx: Arc<ServerContext<H>>,
        tasks: &mut JoinSet<()>,
    ) -> impl Future<Output = Result<bool, NetError>> + Send;

    /// Runs a transport whose listener was initialized by its constructor.
    fn run<H: RequestHandler>(
        mut self,
        cx: Arc<ServerContext<H>>,
    ) -> impl Future<Output = Result<(), NetError>> + Send + 'static {
        async move {
            let mut tasks = JoinSet::new();

            while let Some(result) = cx // stop on graceful shutdown
                .shutdown
                .run_until_cancelled(self.accept(cx.clone(), &mut tasks))
                .await
            {
                if !result? {
                    break;
                }

                while tasks.try_join_next().is_some() {}
            }

            if cx.shutdown.is_cancelled() {
                Ok(())
            } else {
                Err(NetError::from("unexpected close of socket"))
            }
        }
    }
}

mod udp;
pub use udp::Udp;

mod tcp;
pub use tcp::Tcp;

#[cfg(feature = "__tls")]
mod tls;
#[cfg(feature = "__tls")]
pub use tls::Tls;

#[cfg(feature = "__https")]
mod h2;
#[cfg(feature = "__https")]
pub use h2::H2;

#[cfg(feature = "__quic")]
mod quic;
#[cfg(feature = "__quic")]
pub use quic::Quic;

#[cfg(feature = "__h3")]
mod h3;
#[cfg(feature = "__h3")]
pub use h3::H3;
