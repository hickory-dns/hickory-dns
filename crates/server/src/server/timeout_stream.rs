use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::FutureExt;
use futures_util::stream::{Stream, StreamExt};
use tokio::time::{Sleep, sleep};
use tracing::debug;

/// This wraps the underlying Stream in a timeout.
///
/// Any `Ok(Poll::Ready(_))` from the underlying Stream will reset the timeout.
pub struct TimeoutStream<S> {
    stream: S,
    timeout_duration: Option<Duration>,
    timeout: Option<Pin<Box<Sleep>>>,
}

impl<S> TimeoutStream<S> {
    /// Returns a new TimeoutStream
    ///
    /// # Arguments
    ///
    /// * `stream` - stream to wrap
    /// * `timeout_duration` - timeout between each request, once exceed the connection is killed
    pub fn new(stream: S, timeout_duration: Option<Duration>) -> Self {
        Self {
            stream,
            timeout_duration,
            timeout: None,
        }
    }

    fn timeout(timeout_duration: Option<Duration>) -> Option<Pin<Box<Sleep>>> {
        timeout_duration.map(|timeout_duration| Box::pin(sleep(timeout_duration)))
    }
}

impl<S, I> Stream for TimeoutStream<S>
where
    S: Stream<Item = Result<I, io::Error>> + Unpin,
{
    type Item = Result<I, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.stream.poll_next_unpin(cx) {
            r @ Poll::Ready(_) => {
                // Cancel the timeout future, if present. We may start another one on the next poll.
                self.timeout = None;

                r
            }
            Poll::Pending => {
                // If the timeout future isn't set, and timeouts are enabled, set one now.
                if self.timeout.is_none() {
                    self.timeout = Self::timeout(self.timeout_duration);
                }

                if let Some(timeout) = &mut self.timeout {
                    match timeout.poll_unpin(cx) {
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(()) => {
                            debug!("timeout on stream");
                            Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                format!("nothing ready in {:?}", self.timeout_duration),
                            ))))
                        }
                    }
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{pin::pin, sync::Arc};

    use futures_channel::mpsc::unbounded;
    use futures_util::stream::iter;
    use tokio::{spawn, sync::Barrier, time::sleep};

    use super::*;
    use test_support::subscribe;

    #[tokio::test]
    async fn test_no_timeout() {
        subscribe();

        // Try with both a very long timeout and no timeout.
        let timeouts = [Some(Duration::from_secs(360)), None];

        for timeout in timeouts {
            let sequence = iter(vec![Ok(1), Err(io::Error::other("error")), Ok(2)]);

            let timeout_stream = TimeoutStream::new(sequence, timeout);

            let (val, timeout_stream) = timeout_stream.into_future().await;
            assert_eq!(val.expect("nothing in stream").ok(), Some(1));

            let (error, timeout_stream) = timeout_stream.into_future().await;
            assert!(error.expect("nothing in stream").is_err());

            let (val, timeout_stream) = timeout_stream.into_future().await;
            assert_eq!(val.expect("nothing in stream").ok(), Some(2));

            let (val, _) = timeout_stream.into_future().await;
            assert!(val.is_none());
        }
    }

    struct NeverStream {}

    impl Stream for NeverStream {
        type Item = Result<(), io::Error>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn test_timeout() {
        subscribe();

        let timeout_stream = TimeoutStream::new(NeverStream {}, Some(Duration::from_millis(1)));

        assert!(
            timeout_stream
                .into_future()
                .await
                .0
                .expect("nothing in stream")
                .is_err()
        );
    }

    /// Test TimeoutStream with a stream that becomes ready after a delay.
    #[tokio::test(start_paused = true)]
    async fn test_slowloris() {
        subscribe();

        let (sender, receiver) = unbounded::<Result<(), io::Error>>();

        let send_task = spawn({
            async move {
                sleep(Duration::from_millis(500)).await;
                sender.unbounded_send(Ok(())).unwrap();

                sleep(Duration::from_millis(750)).await;
                sender.unbounded_send(Ok(())).unwrap();

                sleep(Duration::from_millis(1500)).await;
                sender.unbounded_send(Ok(())).unwrap();
            }
        });

        let mut timeout_stream = pin!(TimeoutStream::new(receiver, Some(Duration::from_secs(1))));

        timeout_stream.next().await.unwrap().unwrap();

        timeout_stream.next().await.unwrap().unwrap();

        let err = timeout_stream.next().await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        send_task.await.unwrap();
    }

    /// Check that time between the stream returning Ready and the next poll is not counted against
    /// the timeout.
    ///
    /// This makes sure that slower request processing doesn't cause an unnecessary disconnection.
    #[tokio::test(start_paused = true)]
    async fn test_timeout_delay_between_polls() {
        subscribe();

        let (sender, receiver) = unbounded::<Result<(), io::Error>>();

        let barrier = Arc::new(Barrier::new(2));

        let send_task = spawn({
            let barrier = barrier.clone();
            async move {
                for _ in 0..2 {
                    sleep(Duration::from_millis(500)).await;
                    sender.unbounded_send(Ok(())).unwrap();
                    barrier.wait().await;
                }
            }
        });

        let mut timeout_stream = pin!(TimeoutStream::new(receiver, Some(Duration::from_secs(1))));

        timeout_stream.next().await.unwrap().unwrap();

        // Synchronize tasks before next sleeps.
        barrier.wait().await;

        // Insert a long delay between the last Ready poll and next Pending poll. We don't want this
        // to be counted against the timeout.
        sleep(Duration::from_secs(5)).await;

        timeout_stream.next().await.unwrap().unwrap();

        barrier.wait().await;
        send_task.await.unwrap();
    }
}
