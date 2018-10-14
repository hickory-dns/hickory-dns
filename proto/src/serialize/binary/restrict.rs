/// Untrusted types are boxed in this, only access is through the verify method
pub struct Restrict<T>(T);

impl<T> Restrict<T> {
    /// Create a new restricted type
    #[inline]
    pub fn new(restricted: T) -> Self {
        Restrict(restricted)
    }

    /// it is the responsibility of th function to verfy
    ///
    /// ```
    /// use trust_dns_proto::serialize::binary::Restrict;
    ///
    /// let unrestricted = Restrict::new(0).verify(|r| *r == 0).then(|r| *r + 1).unwrap();
    /// assert!(unrestricted == 1);
    /// ```
    #[inline]
    pub fn verify<'a, F: Fn(&'a T) -> bool>(&'a self, f: F) -> Verified<'a, T> {
        if f(&self.0) {
            Verified(VerifiedInner::Valid(&self.0))
        } else {
            Verified(VerifiedInner::Invalid(&self.0))
        }
    }

    /// it is the responsibility of th function to verfy
    ///
    /// ```
    /// use trust_dns_proto::serialize::binary::Restrict;
    ///
    /// let unrestricted = Restrict::new(0).verify_unwrap(|r| *r == 0).unwrap();
    /// assert!(unrestricted == 0);
    /// ```
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
pub struct Verified<'a, T: 'a>(VerifiedInner<'a, T>);

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
enum VerifiedInner<'a, T: 'a> {
    Valid(&'a T),
    Invalid(&'a T),
}
