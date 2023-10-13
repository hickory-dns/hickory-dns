// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Resource record related components, e.g. `Name` aka label, `Record`, `RData`, ...

pub mod zone;

use crate::proto::rr;
pub use crate::proto::rr::dns_class;
pub use crate::proto::rr::domain;
pub use crate::proto::rr::record_data;
pub use crate::proto::rr::record_type;
pub use crate::proto::rr::resource;

pub use self::dns_class::DNSClass;
pub use self::record_data::RData;
pub use self::record_type::RecordType;
pub use self::resource::Record;
pub use self::rr::domain::{IntoName, Label, Name};
#[allow(deprecated)]
pub use self::rr::IntoRecordSet;
pub use self::rr::RecordData;
pub use self::rr::RecordSet;

/// All record data structures and related serialization methods
pub mod rdata {
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    pub use crate::proto::rr::dnssec::rdata::*;
    pub use crate::proto::rr::rdata::*;
}
