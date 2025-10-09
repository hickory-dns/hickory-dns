/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
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

//! UDP protocol related components for DNS

use core::time::Duration;

#[cfg(test)]
#[allow(clippy::print_stdout)]
mod tests;
mod udp_client_stream;
mod udp_stream;

pub use self::udp_client_stream::{UdpClientConnect, UdpClientStream, UdpClientStreamBuilder};
pub use self::udp_stream::{DnsUdpSocket, UdpSocket, UdpStream};

/// Max size for the UDP receive buffer as recommended by
/// [RFC6891](https://datatracker.ietf.org/doc/html/rfc6891#section-6.2.5).
pub const MAX_RECEIVE_BUFFER_SIZE: usize = 4_096;

/// Default retry interval floor.  This value is somewhat arbitrary, but is based on
/// observed, real-world latencies and offers the chance to send three queries in a
/// second to maximize the chance of a successful response in periods of high packet
/// loss without overwhelming upstream servers.
pub const DEFAULT_RETRY_FLOOR: Duration = Duration::from_millis(333);
