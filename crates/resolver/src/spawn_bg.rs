// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std::future::Future;

use tokio::{self, executor::Spawn};
use tokio::runtime::TaskExecutor;
use futures::{future, FutureExt};

use crate::error::ResolveError;

/// A trait for spawning resolver background tasks
pub trait SpawnBg: Send + 'static {
    type JoinHandle: Future<Output = Result<(), ResolveError>> + Send + Unpin + 'static;

    fn spawn_bg<F: Future<Output = Result<(), ResolveError>> + Send + 'static>(&self, background: Option<F>) -> Option<Self::JoinHandle>;
}

/// Used to spawn background tasks on a Tokio Runtime
pub struct TokioSpawnBg();

impl TokioSpawnBg {
    pub(crate) fn new() -> Self {
        TokioSpawnBg()
    }
}

impl SpawnBg for TokioSpawnBg {
    // TODO: change to join handle on update to tokio 0.2
    type JoinHandle = future::Pending<Result<(), ResolveError>>;

    fn spawn_bg<F: Future<Output = Result<(), ResolveError>> + Send + 'static>(&self, background: Option<F>) -> Option<Self::JoinHandle> {
        if let Some(bg) = background {
            let _: Spawn = tokio::spawn(bg.map(|_| ()));
            Some(future::pending::<Result<(), ResolveError>>())
        } else {
            None
        }
    }
}