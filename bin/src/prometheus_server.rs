use std::future::{Ready, ready};

use http::header::CONTENT_TYPE;
use hyper::{Request, Response, body::Incoming, service::Service};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::{conn::auto::Builder, graceful::GracefulShutdown},
};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use tokio::{net::TcpListener, select, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

#[cfg(any(feature = "__tls", feature = "__quic"))]
use hickory_resolver::metrics::opportunistic_encryption::PROBE_DURATION_SECONDS;
#[cfg(feature = "recursor")]
use hickory_resolver::metrics::recursor::{CACHE_HIT_DURATION, CACHE_MISS_DURATION};

/// An HTTP server that responds to Prometheus scrape requests.
pub(crate) struct PrometheusServer {
    join_handle: JoinHandle<()>,
    cancellation_token: CancellationToken,
}

impl PrometheusServer {
    /// Register a metrics recorder, and start an HTTP server with the provided listener to provide
    /// metrics to Prometheus.
    pub(crate) fn new(listener: TcpListener) -> Result<Self, String> {
        // Set up metrics recorder.
        let handle = configure_buckets(PrometheusBuilder::new())
            .install_recorder()
            .map_err(|e| format!("failed to install prometheus endpoint {e}"))?;

        let service = PrometheusService::new(handle);
        let cancellation_token = CancellationToken::new();
        let token_clone = cancellation_token.clone();
        let shutdown = GracefulShutdown::new();
        let join_handle = tokio::spawn(async move {
            let builder = Builder::new(TokioExecutor::new());
            loop {
                let stream = select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, _)) => stream,
                            Err(error) => {
                                debug!(%error, "error accepting connection");
                                continue;
                            }
                        }
                    },
                    _ = cancellation_token.cancelled() => {
                        drop(listener);
                        break;
                    },
                };
                let io = TokioIo::new(stream);
                let conn = builder.serve_connection_with_upgrades(io, service.clone());
                let conn = shutdown.watch(conn.into_owned());
                tokio::spawn(async move {
                    if let Err(error) = conn.await {
                        debug!(%error, "connection error");
                    }
                });
            }
            shutdown.shutdown().await;
        });

        Ok(Self {
            join_handle,
            cancellation_token: token_clone,
        })
    }

    /// Stop the Prometheus HTTP server.
    pub(crate) async fn stop(self) {
        self.cancellation_token.cancel();
        if let Err(error) = self.join_handle.await {
            error!(%error, "Error from Prometheus server task");
        }
    }
}

#[derive(Clone)]
struct PrometheusService {
    handle: PrometheusHandle,
}

impl PrometheusService {
    fn new(handle: PrometheusHandle) -> Self {
        Self { handle }
    }
}

impl Service<Request<Incoming>> for PrometheusService {
    type Response = Response<String>;

    type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

    type Future =
        Ready<Result<Response<String>, Box<dyn std::error::Error + Send + Sync + 'static>>>;

    fn call(&self, _req: Request<Incoming>) -> Self::Future {
        let response_builder =
            Response::builder().header(CONTENT_TYPE, "text/plain; version=0.0.4");
        match response_builder.body(self.handle.render()) {
            Ok(response) => ready(Ok(response)),
            Err(e) => ready(Err(Box::new(e))),
        }
    }
}

/// Update the PrometheusBuilder to set histogram bucket sizes.
///
/// We set buckets explicitly so that histogram metrics are treated as "true"
/// Prometheus histograms instead of summaries (the `metrics` crate default).
///
/// We do this per-metric because:
/// a) some metrics need internet latency sized buckets, and others smaller internal
///    buckets
/// b) using set_buckets_for_metric() only has effect if the global set_buckets()
///   builder fn is **not** used.
fn configure_buckets(mut builder: PrometheusBuilder) -> PrometheusBuilder {
    for (name, buckets) in HISTOGRAMS {
        builder = builder.set_buckets_for_metric(Matcher::Full((*name).to_owned()), buckets).unwrap(
            /* safety: bucket values are static and non-empty */
        );
    }
    builder
}

/// Histogram metric names and associated bucket sizes.
const HISTOGRAMS: &[(&str, &[f64])] = &[
    #[cfg(any(feature = "__tls", feature = "__quic"))]
    (PROBE_DURATION_SECONDS, INTERNET_LATENCY_BUCKETS),
    #[cfg(feature = "recursor")]
    (CACHE_MISS_DURATION, INTERNET_LATENCY_BUCKETS),
    #[cfg(feature = "recursor")]
    (CACHE_HIT_DURATION, INTERNAL_LATENCY_BUCKETS),
];

/// Histogram buckets for operations that traverse the internet to remote systems.
///
/// The values used are matched to the Go client defaults.
#[cfg(any(feature = "recursor", feature = "__tls", feature = "__quic"))]
const INTERNET_LATENCY_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Histogram buckets for internal operations that don't depend on remote systems.
///
/// The values used are a range of buckets between 100μs and 100ms.
#[cfg(feature = "recursor")]
const INTERNAL_LATENCY_BUCKETS: &[f64] = &[
    0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1,
];
