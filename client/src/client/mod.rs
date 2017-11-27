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

mod client;
mod client_connection;
mod client_future;
mod memoize_client_handle;
mod rc_future;

#[allow(deprecated)]
pub use self::client::{Client, SyncClient};
#[cfg(any(feature = "openssl", feature = "ring"))]
pub use self::client::SecureSyncClient;
pub use self::client_connection::ClientConnection;
#[allow(deprecated)]
pub use self::client_future::{BasicClientHandle, ClientFuture, ClientHandle};
pub use self::memoize_client_handle::MemoizeClientHandle;

/// This is an alias for [`trust_dns_proto::StreamHandle`]
#[deprecated(note = "use [`trust_dns_proto::StreamHandle`] instead")]
pub use trust_dns_proto::StreamHandle;

/// This is an alias for [`trust_dns_proto::DnsStreamHandle`]
#[deprecated(note = "use [`trust_dns_proto::DnsStreamHandle`] instead")]
pub use trust_dns_proto::DnsStreamHandle as ClientStreamHandle;

/// This is an alias for [`trust_dns_proto::RetryDnsHandle`]
#[deprecated(note = "use [`trust_dns_proto::RetryDnsHandle`] instead")]
pub use trust_dns_proto::RetryDnsHandle as RetryClientHandle;

/// This is an alias for [`trust_dns_proto::SecureDnsHandle`]
#[cfg(feature = "dnssec")]
#[deprecated(note = "use [`trust_dns_proto::SecureDnsHandle`] instead")]
pub use trust_dns_proto::SecureDnsHandle as SecureClientHandle;
