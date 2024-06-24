/*
 * Copyright (C) 2015-2019 Benjamin Fry <benjaminfry@me.com>
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

//! All record data structures and related serialization methods

// TODO: these should each be it's own struct, it would make parsing and decoding a little cleaner
//  and also a little more ergonomic when accessing.
// each of these module's has the parser for that rdata embedded, to keep the file sizes down...
pub(crate) mod a;
pub(crate) mod aaaa;
pub(crate) mod caa;
pub(crate) mod csync;
#[cfg(feature = "dnssec")]
pub(crate) mod dnskey;
#[cfg(feature = "dnssec")]
pub(crate) mod ds;
pub(crate) mod hinfo;
pub(crate) mod mx;
pub(crate) mod name;
pub(crate) mod naptr;
pub(crate) mod null;
pub(crate) mod openpgpkey;
pub(crate) mod soa;
pub(crate) mod srv;
pub(crate) mod sshfp;
pub(crate) mod svcb;
pub(crate) mod tlsa;
pub(crate) mod txt;
