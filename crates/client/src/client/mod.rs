/*
 * Copyright (C) 2015-2016 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! DNS Client associated classes for performing queries and other operations.

pub(crate) mod async_client;
#[cfg(feature = "dnssec")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
pub(crate) mod async_secure_client;
#[allow(clippy::module_inception)]
mod client;
pub mod client_connection;
mod memoize_client_handle;
mod rc_stream;

#[allow(deprecated)]
pub use self::async_client::{AsyncClient, ClientFuture, ClientHandle, ClientStreamingResponse};
#[cfg(feature = "dnssec")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
pub use self::async_secure_client::{AsyncDnssecClient, AsyncSecureClientBuilder};
#[cfg(feature = "dnssec")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
pub use self::client::SyncDnssecClient;
#[allow(deprecated)]
pub use self::client::{BlockingStream, Client, SyncClient};
pub use self::client_connection::ClientConnection;
pub use self::client_connection::Signer;
pub use self::memoize_client_handle::MemoizeClientHandle;
