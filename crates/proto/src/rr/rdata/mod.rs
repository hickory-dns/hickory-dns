// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! All record data structures and related serialization methods

// TODO: these should each be it's own struct, it would make parsing and decoding a little cleaner
//  and also a little more ergonomic when accessing.
// each of these module's has the parser for that rdata embedded, to keep the file sizes down...
pub mod a;
pub mod aaaa;
pub mod caa;
pub mod cert;
pub mod csync;
pub mod hinfo;
pub mod https;
pub mod mx;
pub mod name;
pub mod naptr;
pub mod null;
pub mod openpgpkey;
pub mod opt;
pub mod soa;
pub mod srv;
pub mod sshfp;
pub mod svcb;
pub mod tlsa;
pub mod txt;

pub use self::a::A;
pub use self::aaaa::AAAA;
pub use self::caa::CAA;
pub use self::cert::CERT;
pub use self::csync::CSYNC;
pub use self::hinfo::HINFO;
pub use self::https::HTTPS;
pub use self::mx::MX;
pub use self::name::{ANAME, CNAME, NS, PTR};
pub use self::naptr::NAPTR;
pub use self::null::NULL;
pub use self::openpgpkey::OPENPGPKEY;
pub use self::opt::OPT;
pub use self::soa::SOA;
pub use self::srv::SRV;
pub use self::sshfp::SSHFP;
pub use self::svcb::SVCB;
pub use self::tlsa::TLSA;
pub use self::txt::TXT;
