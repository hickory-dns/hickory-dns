/*
 * Copyright (C) 2015-2016 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! DNS Client associated classes for performing queries and other operations.

#[allow(clippy::module_inception)]
pub(crate) mod client;
pub use client::{Client, ClientHandle, ClientStreamingResponse};

#[cfg(all(feature = "__dnssec", feature = "tokio"))]
pub(crate) mod dnssec_client;
#[cfg(all(feature = "__dnssec", feature = "tokio"))]
pub use dnssec_client::{AsyncSecureClientBuilder, DnssecClient};

mod memoize_client_handle;
pub use memoize_client_handle::MemoizeClientHandle;

mod rc_stream;

#[cfg(test)]
mod tests;
