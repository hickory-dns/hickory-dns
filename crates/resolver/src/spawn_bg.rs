// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Types related to spawning background tasks

use std::future::Future;
use std::pin::Pin;

use tokio::{self, runtime::Handle};

use crate::proto::error::ProtoError;

/// A boxed join handle to use to await the backgrounds completion
pub type BgJoinHandle =
    Pin<Box<dyn Future<Output = Result<(), ProtoError>> + Send + Sync + 'static>>;

/// A trait for spawning resolver background tasks
pub trait SpawnBg: Clone + Send + Sync + Unpin + 'static {
    /// Spawn an (optional) background task
    fn spawn_bg<F: Future<Output = Result<(), ProtoError>> + Send + 'static>(
        &self,
        background: F,
    ) -> BgJoinHandle;
}

/// Used to spawn background tasks on a Tokio Runtime
#[derive(Clone)]
pub struct TokioSpawnBg(Handle);

impl TokioSpawnBg {
    pub(crate) fn new(runtime: Handle) -> Self {
        TokioSpawnBg(runtime)
    }
}

impl SpawnBg for TokioSpawnBg {
    fn spawn_bg<F: Future<Output = Result<(), ProtoError>> + Send + 'static>(
        &self,
        background: F,
    ) -> BgJoinHandle {
        use futures::{FutureExt, TryFutureExt};

        let join = self.0.spawn(background);
        let join = join
            .map_err(|e| ProtoError::from(format!("failed to spawn task: {}", e)))
            .map(|r| r.and_then(|r| r));
        Box::pin(join)
    }
}
