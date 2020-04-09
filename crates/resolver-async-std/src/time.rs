use std::future::Future;
use std::time::Duration;

use async_trait::async_trait;
use trust_dns_resolver::proto::Time;

/// AsyncStd backed timer implementation
pub struct AsyncStdTime;

#[async_trait]
impl Time for AsyncStdTime {
    async fn delay_for(duration: Duration) {
        async_std::task::sleep(duration).await
    }

    async fn timeout<F: 'static + Future + Send>(
        duration: Duration,
        future: F,
    ) -> Result<F::Output, std::io::Error> {
        async_std::future::timeout(duration, future)
            .await
            .map_err(move |_| std::io::Error::new(std::io::ErrorKind::TimedOut, "future timed out"))
    }
}
