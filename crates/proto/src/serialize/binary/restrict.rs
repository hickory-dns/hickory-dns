/// Untrusted types will be wrapped in this type.
///
/// To gain access to the data, some form of verification through one of the public methods is necessary.
#[derive(Clone, Copy)]
pub struct Restrict<T>(T);

impl<T> Restrict<T> {
    /// Create a new restricted type
    #[inline]
    pub fn new(restricted: T) -> Self {
        Self(restricted)
    }

    /// It is the responsibility of this function to verify the contained type is valid.
    ///
    /// ```
    /// use trust_dns_proto::serialize::binary::Restrict;
    ///
    /// let unrestricted = Restrict::new(0).verify(|r| *r == 0).then(|r| *r + 1).unwrap();
    /// assert!(unrestricted == 1);
    /// ```
    ///
    /// # Returns
    ///
    /// If `f` returns true then the value is valid and a chainable `Verified` type is returned
    #[inline]
    pub fn verify<'a, F: Fn(&'a T) -> bool>(&'a self, f: F) -> Verified<'a, T> {
        if f(&self.0) {
            Verified(VerifiedInner::Valid(&self.0))
        } else {
            Verified(VerifiedInner::Invalid(&self.0))
        }
    }

    /// It is the responsibility of this function to verify the contained type is valid.
    ///
    /// ```
    /// use trust_dns_proto::serialize::binary::Restrict;
    ///
    /// let unrestricted = Restrict::new(0).verify_unwrap(|r| *r == 0).unwrap();
    /// assert!(unrestricted == 0);
    /// ```
    ///
    /// # Returns
    ///
    /// If `f` returns true then the value is valid and `Ok(T)` is returned. Otherwise
    ///  `Err(T)` is returned.
    #[inline]
    pub fn verify_unwrap<F: Fn(&T) -> bool>(self, f: F) -> Result<T, T> {
        if f(&self.0) {
            Ok(self.0)
        } else {
            Err(self.0)
        }
    }

    /// Unwraps the value without verifying the data, akin to Result::unwrap and Option::unwrap, but will not panic
    #[inline]
    pub fn unverified(self) -> T {
        self.0
    }

    /// Map the internal type of the restriction
    ///
    /// ```
    /// use trust_dns_proto::serialize::binary::Restrict;
    ///
    /// let restricted = Restrict::new(0).map(|b| vec![b, 1]);
    /// assert!(restricted.verify(|v| v == &[0, 1]).is_valid());
    /// assert!(!restricted.verify(|v| v == &[1, 0]).is_valid());
    /// ```
    #[inline]
    pub fn map<R, F: Fn(T) -> R>(self, f: F) -> Restrict<R> {
        Restrict(f(self.0))
    }
}

/// Verified data that can be operated on
pub struct Verified<'a, T>(VerifiedInner<'a, T>);

impl<'a, T> Verified<'a, T> {
    /// Perform some operation on the data, and return a result.
    #[inline]
    pub fn then<R, F: Fn(&T) -> R>(&self, f: F) -> Result<R, &T> {
        match self.0 {
            VerifiedInner::Valid(t) => Ok(f(t)),
            VerifiedInner::Invalid(t) => Err(t),
        }
    }

    /// Is this valid
    #[inline]
    pub fn is_valid(&self) -> bool {
        match self.0 {
            VerifiedInner::Valid(_) => true,
            VerifiedInner::Invalid(_) => false,
        }
    }
}

/// Verified data that can be operated on
enum VerifiedInner<'a, T> {
    Valid(&'a T),
    Invalid(&'a T),
}

/// Common checked math operations for the Restrict type
pub trait RestrictedMath {
    /// Argument for the math operations
    type Arg: 'static + Sized + Copy;
    /// Return value, generally the same as Arg
    type Value: 'static + Sized + Copy;

    /// Checked addition, see `usize::checked_add`
    fn checked_add(&self, arg: Self::Arg) -> Result<Restrict<Self::Value>, Self::Arg>;
    /// Checked subtraction, see `usize::checked_sub`
    fn checked_sub(&self, arg: Self::Arg) -> Result<Restrict<Self::Value>, Self::Arg>;
    /// Checked multiplication, see `usize::checked_mul`
    fn checked_mul(&self, arg: Self::Arg) -> Result<Restrict<Self::Value>, Self::Arg>;
}

impl RestrictedMath for Restrict<usize> {
    type Arg = usize;
    type Value = usize;

    fn checked_add(&self, arg: Self::Arg) -> Result<Restrict<Self::Value>, Self::Arg> {
        self.0.checked_add(arg).map(Restrict).ok_or(arg)
    }
    fn checked_sub(&self, arg: Self::Arg) -> Result<Restrict<Self::Value>, Self::Arg> {
        self.0.checked_sub(arg).map(Restrict).ok_or(arg)
    }
    fn checked_mul(&self, arg: Self::Arg) -> Result<Restrict<Self::Value>, Self::Arg> {
        self.0.checked_mul(arg).map(Restrict).ok_or(arg)
    }
}

impl RestrictedMath for Restrict<u8> {
    type Arg = u8;
    type Value = u8;

    fn checked_add(&self, arg: Self::Arg) -> Result<Restrict<Self::Value>, Self::Arg> {
        self.0.checked_add(arg).map(Restrict).ok_or(arg)
    }
    fn checked_sub(&self, arg: Self::Arg) -> Result<Restrict<Self::Value>, Self::Arg> {
        self.0.checked_sub(arg).map(Restrict).ok_or(arg)
    }
    fn checked_mul(&self, arg: Self::Arg) -> Result<Restrict<Self::Value>, Self::Arg> {
        self.0.checked_mul(arg).map(Restrict).ok_or(arg)
    }
}

impl RestrictedMath for Restrict<u16> {
    type Arg = u16;
    type Value = u16;

    fn checked_add(&self, arg: Self::Arg) -> Result<Restrict<Self::Value>, Self::Arg> {
        self.0.checked_add(arg).map(Restrict).ok_or(arg)
    }
    fn checked_sub(&self, arg: Self::Arg) -> Result<Restrict<Self::Value>, Self::Arg> {
        self.0.checked_sub(arg).map(Restrict).ok_or(arg)
    }
    fn checked_mul(&self, arg: Self::Arg) -> Result<Restrict<Self::Value>, Self::Arg> {
        self.0.checked_mul(arg).map(Restrict).ok_or(arg)
    }
}

impl<R, A> RestrictedMath for Result<R, A>
where
    R: RestrictedMath,
    A: 'static + Sized + Copy,
{
    type Arg = <R as RestrictedMath>::Arg;
    type Value = <R as RestrictedMath>::Value;

    fn checked_add(&self, arg: Self::Arg) -> Result<Restrict<Self::Value>, Self::Arg> {
        match *self {
            Ok(ref r) => r.checked_add(arg),
            Err(_) => Err(arg),
        }
    }

    fn checked_sub(&self, arg: Self::Arg) -> Result<Restrict<Self::Value>, Self::Arg> {
        match *self {
            Ok(ref r) => r.checked_sub(arg),
            Err(_) => Err(arg),
        }
    }

    fn checked_mul(&self, arg: Self::Arg) -> Result<Restrict<Self::Value>, Self::Arg> {
        match *self {
            Ok(ref r) => r.checked_mul(arg),
            Err(_) => Err(arg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checked_add() {
        assert_eq!(
            Restrict(1_usize).checked_add(2_usize).unwrap().unverified(),
            3_usize
        );
        assert_eq!(
            Restrict(1_u16).checked_add(2_u16).unwrap().unverified(),
            3_u16
        );
        assert_eq!(Restrict(1_u8).checked_add(2_u8).unwrap().unverified(), 3_u8);
    }

    #[test]
    fn test_checked_sub() {
        assert_eq!(
            Restrict(2_usize).checked_sub(1_usize).unwrap().unverified(),
            1_usize
        );
        assert_eq!(
            Restrict(2_u16).checked_sub(1_u16).unwrap().unverified(),
            1_u16
        );
        assert_eq!(Restrict(2_u8).checked_sub(1_u8).unwrap().unverified(), 1_u8);
    }

    #[test]
    fn test_checked_mul() {
        assert_eq!(
            Restrict(1_usize).checked_mul(2_usize).unwrap().unverified(),
            2_usize
        );
        assert_eq!(
            Restrict(1_u16).checked_mul(2_u16).unwrap().unverified(),
            2_u16
        );
        assert_eq!(Restrict(1_u8).checked_mul(2_u8).unwrap().unverified(), 2_u8);
    }
}
