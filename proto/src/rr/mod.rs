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
pub mod dnssec;
pub mod domain;
pub mod rdata;
pub mod record_data;
pub mod record_type;
pub mod resource;
mod rr_key;
mod rr_set;

pub use self::domain::Name;
pub use self::dns_class::DNSClass;
pub use self::record_data::RData;
pub use self::record_type::RecordType;
pub use self::resource::Record;
pub use self::rr_key::RrKey;
pub use self::rr_set::IntoRecordSet;
pub use self::rr_set::RecordSet;

/// A RecordSet is a set of Records whose types all match, but data do not
#[deprecated = "will be removed post 0.9.x, use RecordSet"]
pub type RrSet = RecordSet;
