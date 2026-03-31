// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Resource record related components, e.g. `Name` aka label, `Record`, `RData`, ...

use core::fmt::{Debug, Display};

use crate::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, DecodeError, Restrict};

pub mod dns_class;
pub use dns_class::DNSClass;

pub mod domain;
pub use domain::{IntoName, Name};

mod lower_name;
pub use lower_name::LowerName;

pub mod rdata;

pub mod record;
pub use record::Record;

pub mod record_data;
pub use record_data::RData;

pub mod record_type;
pub use record_type::RecordType;

pub(crate) mod record_type_set;
pub use record_type_set::RecordTypeSet;

mod rr_key;
pub use rr_key::RrKey;

mod rr_set;
#[cfg(feature = "__dnssec")]
pub use rr_set::RecordsAndRrsigsIter;
pub use rr_set::{RecordSet, RecordSetParts, RrsetRecords};

pub mod serial_number;
pub use serial_number::SerialNumber;

mod tsig;
#[cfg(feature = "__dnssec")]
pub use tsig::TSigVerifier;
pub use tsig::{TSigResponseContext, TSigner};

/// RecordData that is stored in a DNS Record.
///
/// This trait allows for generic usage of `RecordData` types inside the `Record` type. Specific RecordData types can be used to enforce compile time constraints on a Record.
pub trait RecordData: Clone + Sized + PartialEq + Eq + Display + Debug + BinEncodable {
    /// Attempts to borrow this RecordData from the RData type, if it is not the correct type the original is returned
    fn try_borrow(data: &RData) -> Option<&Self>;

    /// Get the associated RecordType for the RecordData
    fn record_type(&self) -> RecordType;

    /// Converts this RecordData into generic RecordData
    fn into_rdata(self) -> RData;

    /// RDLENGTH = 0
    fn is_update(&self) -> bool {
        false
    }
}

pub(crate) trait RecordDataDecodable<'r>: Sized {
    /// Read the RecordData from the data stream.
    ///
    /// * `decoder` - data stream from which the RData will be read
    /// * `record_type` - specifies the RecordType that has already been read from the stream
    /// * `length` - the data length that should be read from the stream for this RecordData
    fn read_data(decoder: &mut BinDecoder<'r>, length: Restrict<u16>) -> Result<Self, DecodeError>;
}

impl<'r, T> RecordDataDecodable<'r> for T
where
    T: 'r + BinDecodable<'r> + Sized,
{
    fn read_data(
        decoder: &mut BinDecoder<'r>,
        _length: Restrict<u16>,
    ) -> Result<Self, DecodeError> {
        T::read(decoder)
    }
}
