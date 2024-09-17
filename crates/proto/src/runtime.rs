//! Abstractions to deal with different async runtimes.

use std::future::Future;
use std::marker::Send;
use std::time::Duration;

use async_trait::async_trait;

#[cfg(any(test, feature = "tokio-runtime"))]
use tokio::runtime::Runtime;
#[cfg(any(test, feature = "tokio-runtime"))]
use tokio::task::JoinHandle;

/// Spawn a background task, if it was present
#[cfg(any(test, feature = "tokio-runtime"))]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio-runtime")))]
pub fn spawn_bg<F: Future<Output = R> + Send + 'static, R: Send + 'static>(
    runtime: &Runtime,
    background: F,
) -> JoinHandle<R> {
    runtime.spawn(background)
}

#[cfg(feature = "tokio-runtime")]
#[doc(hidden)]
pub mod iocompat {
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use futures_io::{AsyncRead, AsyncWrite};
    use tokio::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite, ReadBuf};

    /// Conversion from `tokio::io::{AsyncRead, AsyncWrite}` to `std::io::{AsyncRead, AsyncWrite}`
    pub struct AsyncIoTokioAsStd<T: TokioAsyncRead + TokioAsyncWrite>(pub T);

    impl<T: TokioAsyncRead + TokioAsyncWrite + Unpin> Unpin for AsyncIoTokioAsStd<T> {}
    impl<R: TokioAsyncRead + TokioAsyncWrite + Unpin> AsyncRead for AsyncIoTokioAsStd<R> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut buf = ReadBuf::new(buf);
            let polled = Pin::new(&mut self.0).poll_read(cx, &mut buf);

            polled.map_ok(|_| buf.filled().len())
        }
    }

    impl<W: TokioAsyncRead + TokioAsyncWrite + Unpin> AsyncWrite for AsyncIoTokioAsStd<W> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    /// Conversion from `std::io::{AsyncRead, AsyncWrite}` to `tokio::io::{AsyncRead, AsyncWrite}`
    pub struct AsyncIoStdAsTokio<T: AsyncRead + AsyncWrite>(pub T);

    impl<T: AsyncRead + AsyncWrite + Unpin> Unpin for AsyncIoStdAsTokio<T> {}
    impl<R: AsyncRead + AsyncWrite + Unpin> TokioAsyncRead for AsyncIoStdAsTokio<R> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0)
                .poll_read(cx, buf.initialized_mut())
                .map_ok(|len| buf.advance(len))
        }
    }

    impl<W: AsyncRead + AsyncWrite + Unpin> TokioAsyncWrite for AsyncIoStdAsTokio<W> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Pin::new(&mut self.get_mut().0).poll_close(cx)
        }
    }
}

/// Generic executor.
// This trait is created to facilitate running the tests defined in the tests mod using different types of
// executors. It's used in Fuchsia OS, please be mindful when update it.
pub trait Executor {
    /// Create the implementor itself.
    fn new() -> Self;

    /// Spawns a future object to run synchronously or asynchronously depending on the specific
    /// executor.
    fn block_on<F: Future>(&mut self, future: F) -> F::Output;
}

#[cfg(feature = "tokio-runtime")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio-runtime")))]
impl Executor for Runtime {
    fn new() -> Self {
        Self::new().expect("failed to create tokio runtime")
    }

    fn block_on<F: Future>(&mut self, future: F) -> F::Output {
        Self::block_on(self, future)
    }
}

/// Generic Time for Delay and Timeout.
// This trait is created to allow to use different types of time systems. It's used in Fuchsia OS, please be mindful when update it.
#[async_trait]
pub trait Time {
    /// Return a type that implements `Future` that will wait until the specified duration has
    /// elapsed.
    async fn delay_for(duration: Duration);

    /// Return a type that implement `Future` to complete before the specified duration has elapsed.
    async fn timeout<F: 'static + Future + Send>(
        duration: Duration,
        future: F,
    ) -> Result<F::Output, std::io::Error>;
}

/// New type which is implemented using tokio::time::{Delay, Timeout}
#[cfg(any(test, feature = "tokio-runtime"))]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio-runtime")))]
#[derive(Clone, Copy, Debug)]
pub struct TokioTime;

#[cfg(any(test, feature = "tokio-runtime"))]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio-runtime")))]
#[async_trait]
impl Time for TokioTime {
    async fn delay_for(duration: Duration) {
        tokio::time::sleep(duration).await
    }

    async fn timeout<F: 'static + Future + Send>(
        duration: Duration,
        future: F,
    ) -> Result<F::Output, std::io::Error> {
        tokio::time::timeout(duration, future)
            .await
            .map_err(move |_| std::io::Error::new(std::io::ErrorKind::TimedOut, "future timed out"))
    }
}
