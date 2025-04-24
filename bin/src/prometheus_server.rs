use std::future::{Ready, ready};

use http::header::CONTENT_TYPE;
use hyper::{Request, Response, body::Incoming, service::Service};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::{conn::auto::Builder, graceful::GracefulShutdown},
};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio::{net::TcpListener, select, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

/// An HTTP server that repsonds to Prometheus scrape requests.
pub struct PrometheusServer {
    join_handle: JoinHandle<()>,
    cancellation_token: CancellationToken,
}

impl PrometheusServer {
    /// Register a metrics recorder, and start an HTTP server with the provided listener to provide
    /// metrics to Prometheus.
    pub fn new(listener: TcpListener) -> Result<Self, String> {
        // Set up metrics recorder.
        let handle = PrometheusBuilder::new()
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
    pub async fn stop(self) {
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
