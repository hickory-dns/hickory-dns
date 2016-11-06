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

//! Use `Client` along with `trust_dns::udp::UdpClientConnection` or
//! `trust_dns::tcp::TcpClientConnection`.

mod client;
mod client_connection;
mod client_future;
mod memoize_client_handle;
mod rc_future;
mod retry_client_handle;
mod secure_client_handle;

#[allow(deprecated)]
pub use self::client::Client;
pub use self::client_connection::ClientConnection;
pub use self::client_future::{ClientFuture, BasicClientHandle, ClientHandle, StreamHandle};
pub use self::memoize_client_handle::MemoizeClientHandle;
pub use self::retry_client_handle::RetryClientHandle;
pub use self::secure_client_handle::SecureClientHandle;
