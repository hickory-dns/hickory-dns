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

//! Resource record related components, e.g. `Name` aka label, `Record`, `RData`, ...

pub mod dns_class;
// TODO: rename to sec
#[cfg(feature = "dnssec")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
pub mod dnssec;
pub mod domain;
pub mod rdata;
pub mod record_data;
pub mod record_type;
pub mod resource;
mod rr_set;
pub mod type_bit_map;

pub use self::dns_class::DNSClass;
pub use self::domain::{IntoName, Name, TryParseIp};
pub use self::record_data::RData;
pub use self::record_type::RecordType;
pub use self::resource::Record;
#[allow(deprecated)]
pub use self::rr_set::IntoRecordSet;
pub use self::rr_set::RecordSet;
pub use self::rr_set::RrsetRecords;
