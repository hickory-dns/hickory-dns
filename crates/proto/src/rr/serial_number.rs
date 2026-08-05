//! Number type to support Serial Number Arithmetics

use core::{cmp::Ordering, ops::Add};

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

/// Serial Number Addition, see RFC 1982, section 3.1
///
/// The result is a wrapping add.
impl Add for SerialNumber {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.wrapping_add(rhs.0))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equal() {
       let a = SerialNumber (42);
       let b = SerialNumber (42);
       assert_eq!(a.partial_cmp(&b), Some(Ordering::Equal));
    }

    #[test]
    fn test_none() {
        let a = SerialNumber(0);
        let b = SerialNumber (1 << 31);
        assert_eq!(a.partial_cmp(&b), None);    
    }

    #[test]
    fn test_less() {
        let a = SerialNumber(40);
        let b = SerialNumber (42);
        assert_eq!(a.partial_cmp(&b), Some(Ordering::Less));    
    }

    #[test]
    fn test_less_wrap() {
        let a = SerialNumber(u32::MAX);
        let b = SerialNumber (0);
        assert_eq!(a.partial_cmp(&b), Some(Ordering::Less));    
    }

    #[test]
    fn test_greater() {
        let a = SerialNumber(42);
        let b = SerialNumber (40);
        assert_eq!(a.partial_cmp(&b), Some(Ordering::Greater));    
    }

    #[test]
    fn test_greater_wrap() {
        let a = SerialNumber(0);
        let b = SerialNumber (u32::MAX);
        assert_eq!(a.partial_cmp(&b), Some(Ordering::Greater));    
    }

    #[test]
    fn test_add_wrapping() {
        let a = SerialNumber(1);
        let b = SerialNumber (u32::MAX);
        assert_eq!(a+b ,SerialNumber(0));    
    }

}