// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std::future::Future;

use futures::future;
use tokio::{self, runtime::Handle};

use crate::proto::error::ProtoError;

/// A trait for spawning resolver background tasks
pub trait SpawnBg: Clone + Send + Sync + Unpin + 'static {
    /// THe future that will resolve when the background task completes.
    type JoinHandle: Future<Output = Result<(), ProtoError>> + Send + Sync + Unpin + 'static;

    /// Spawn an (optional) background task
    fn spawn_bg<F: Future<Output = Result<(), ProtoError>> + Send + 'static>(
        &self,
        background: F,
    ) -> Self::JoinHandle;
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
    // FIXME: let's remove this JoinHandle for now
    type JoinHandle = future::Ready<Result<(), ProtoError>>;

    fn spawn_bg<F: Future<Output = Result<(), ProtoError>> + Send + 'static>(
        &self,
        background: F,
    ) -> Self::JoinHandle {
        self.0.spawn(background);
        future::ready(Ok(()))
    }
}
