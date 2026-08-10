//! Number type to support Serial Number Arithmetics

use crate::{
    error::ProtoResult,
    serialize::binary::{BinEncodable, BinEncoder},
};
use core::{cmp::Ordering, fmt, num::ParseIntError, ops::Add, ops::AddAssign, str::FromStr};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Wrapper type to support Serial Number Arithmetics as defined
/// in RFC 1982. The signaure fields (expireation, inception) defined in RFC 4034, section 3.1.5
/// are serial numbers.
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct SerialNumber(pub(crate) u32);

impl SerialNumber {
    /// Create a new `SerialNumber` from the given value
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns internal value
    pub fn get(&self) -> u32 {
        self.0
    }
}

impl From<u32> for SerialNumber {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl FromStr for SerialNumber {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u32>().map(Self::from)
    }
}

/// Serial Number Addition, see RFC 1982, section 3.1
///
/// The result is a wrapping add.
impl Add for SerialNumber {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.wrapping_add(rhs.0))
    }
}

/// Serial Number Addition and assign.
impl AddAssign for SerialNumber {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = (*self + rhs).0;
    }
}

/// Serial Number Comparison, see RFC 1982, section 3.2
impl PartialOrd for SerialNumber {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        const SERIAL_BITS_HALF: u32 = 1 << (u32::BITS - 1);

        let i1 = self.0;
        let i2 = other.0;

        if i1 == i2 {
            Some(Ordering::Equal)
        } else if (i1 < i2 && (i2 - i1) < SERIAL_BITS_HALF)
            || (i1 > i2 && (i1 - i2) > SERIAL_BITS_HALF)
        {
            Some(Ordering::Less)
        } else if (i1 < i2 && (i2 - i1) > SERIAL_BITS_HALF)
            || (i1 > i2 && (i1 - i2) < SERIAL_BITS_HALF)
        {
            Some(Ordering::Greater)
        } else {
            None
        }
    }
}

impl fmt::Display for SerialNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl BinEncodable for SerialNumber {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        self.0.emit(encoder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display() {
        assert_eq!(format!("{}", SerialNumber::from(42)), "42");
    }

    #[test]
    fn from_str() {
        assert_eq!(
            "42".parse::<SerialNumber>().unwrap(),
            SerialNumber::from(42)
        )
    }

    #[test]
    fn from_str_error() {
        assert!("abc".parse::<SerialNumber>().is_err());
    }
}
