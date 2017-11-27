/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
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

//! TLS protocol related components for DNS over TLS

extern crate futures;
extern crate openssl;
extern crate tokio_core;
extern crate tokio_openssl;
extern crate trust_dns;
extern crate trust_dns_proto;

mod tls_client_stream;
pub mod tls_server;
mod tls_stream;

pub use self::tls_client_stream::{TlsClientStream, TlsClientStreamBuilder};
pub use self::tls_stream::{tls_stream_from_existing_tls_stream, TlsStream, TlsStreamBuilder};
