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
mod lower_name;
pub mod rdata;
pub mod record_data;
pub mod record_type;
pub mod resource;
mod rr_key;
mod rr_set;
pub mod type_bit_map;

use std::fmt;

use crate::error::ProtoResult;
use crate::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, Restrict};

pub use self::dns_class::DNSClass;
pub use self::domain::{IntoName, Name, TryParseIp};
pub use self::record_data::RData;
pub use self::record_type::RecordType;
pub use self::resource::Record;
#[allow(deprecated)]
pub use self::rr_set::IntoRecordSet;
pub use self::rr_set::RecordSet;
pub use self::rr_set::RrsetRecords;
pub use lower_name::LowerName;
pub use rr_key::RrKey;

/// RecordData that is stored in a DNS Record.
pub trait RecordData: Clone + Sized + PartialEq + Eq + fmt::Display + BinEncodable {
    /// Attempts to convert to this RecordData from the RData type, if it is not the correct type the original is returned
    #[allow(clippy::result_large_err)]
    fn try_from_rdata(data: RData) -> Result<Self, RData>;

    /// Attempts to borrow this RecordData from the RData type, if it is not the correct type the original is returned
    /// FIXME: make this return Option instead of Result
    fn try_borrow(data: &RData) -> Result<&Self, &RData>;

    /// Get the associated RecordType for the RData
    fn record_type(&self) -> RecordType;

    /// Converts this RecordData into generic RData
    fn into_rdata(self) -> RData;
}

trait RecordDataDecodable<'r>: Sized {
    /// Read the RecordData from the data stream.
    ///
    /// * `decoder` - data stream from which the RData will be read
    /// * `record_type` - specifies the RecordType that has already been read from the stream
    /// * `length` - the data length that should be read from the stream for this RecordData
    fn read_data(
        decoder: &mut BinDecoder<'r>,
        record_type: RecordType,
        length: Restrict<u16>,
    ) -> ProtoResult<Self>;
}

impl<'r, T> RecordDataDecodable<'r> for T
where
    T: 'r + BinDecodable<'r> + Sized,
{
    fn read_data(
        decoder: &mut BinDecoder<'r>,
        _record_type: RecordType,
        _length: Restrict<u16>,
    ) -> ProtoResult<Self> {
        T::read(decoder)
    }
}
