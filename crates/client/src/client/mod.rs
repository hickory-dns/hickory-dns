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

#[allow(clippy::module_inception)]
mod client;
mod client_connection;
pub(crate) mod client_future;
mod memoize_client_handle;
mod rc_future;

#[cfg(any(feature = "openssl", feature = "ring"))]
pub use self::client::SecureSyncClient;
#[allow(deprecated)]
pub use self::client::{Client, SyncClient};
pub use self::client_connection::ClientConnection;
#[allow(deprecated)]
pub use self::client_future::{AsyncClient, ClientFuture, ClientHandle, ClientResponse};
pub use self::memoize_client_handle::MemoizeClientHandle;
