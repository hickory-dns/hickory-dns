use std::cmp::{Ordering, PartialEq};
use std::fmt;

use super::*;

/// A copy-on-write version of name.
///
/// Due to internal storage requirements for some Name variants this can not just be Cow<NameRef>.
#[derive(Clone, Ord, Eq)]
pub enum CowName<'a> {
    // FIXME: remove this variant?
    /// A reference to the Trait Object variant
    //Borrowed(&'a dyn DnsName),
    /// BorrowedName is zero overhead abstraction over `NameRef` or `Name`
    BorrowedName(BorrowedName<'a>),
    /// A reference to an unowned set of bytes, there is an allocation of label offsets
    NameRef(NameRef<'a>),
    /// An owned version of a Vec of bytes
    Owned(Name),
}

#[test]
fn test_is_send_sync() {
    fn send_sync<T>() -> bool {
        true
    }

    assert!(send_sync::<CowName>());
}

impl From<Name> for CowName<'static> {
    fn from(name: Name) -> Self {
        CowName::Owned(name)
    }
}

impl<'a> From<NameRef<'a>> for CowName<'a> {
    fn from(name: NameRef<'a>) -> Self {
        CowName::NameRef(name)
    }
}

impl<'a> From<BorrowedName<'a>> for CowName<'a> {
    fn from(name: BorrowedName<'a>) -> Self {
        CowName::BorrowedName(name)
    }
}

impl<'a> From<&'a dyn DnsName> for CowName<'a> {
    fn from(name: &'a dyn DnsName) -> Self {
        CowName::BorrowedName(name.borrowed_name())
    }
}

impl<'a> CowName<'a> {
    /// Is this one of the low cost borrowed variants
    pub fn is_borrowed(&self) -> bool {
        !self.is_owned()
    }

    /// Is this the Owned `Name` variant
    pub fn is_owned(&self) -> bool {
        if let CowName::Owned(_) = self {
            true
        } else {
            false
        }
    }

    /// Get a Trait Object reference to the inner name
    pub fn as_object(&'a self) -> &'a (dyn DnsName + 'a) {
        match self {
            // CowName::Borrowed(name) => *name,
            CowName::BorrowedName(name) => name,
            CowName::NameRef(name) => name,
            CowName::Owned(name) => name,
        }
    }

    /// Convert to the owned `Name` variant internally (if not already done)
    pub fn to_mut(&mut self) -> &mut Name {
        match self {
            // CowName::Borrowed(name) => *self = CowName::Owned(name.to_owned()),
            CowName::BorrowedName(name) => *self = CowName::Owned(name.to_name()),
            CowName::NameRef(name) => *self = CowName::Owned(name.to_name()),
            _ => (),
        }

        if let CowName::Owned(owned) = self {
            owned
        } else {
            unreachable!("non-owned types should be handled above")
        }
    }

    pub(crate) fn to_ref(self) -> Option<NameRef<'a>> {
        if let CowName::NameRef(name) = self {
            Some(name)
        } else {
            None
        }
    }
}

impl<'a> DnsName for CowName<'a> {
    #[inline]
    fn labels(&self) -> LabelIter {
        match self {
            // CowName::Borrowed(name) => name.labels(),
            CowName::BorrowedName(name) => name.labels(),
            CowName::NameRef(name) => name.labels(),
            CowName::Owned(name) => name.labels(),
        }
    }

    #[inline]
    fn is_fqdn(&self) -> bool {
        match self {
            // CowName::Borrowed(name) => name.is_fqdn(),
            CowName::BorrowedName(name) => name.is_fqdn(),
            CowName::NameRef(name) => name.is_fqdn(),
            CowName::Owned(name) => name.is_fqdn(),
        }
    }

    fn set_fqdn(&mut self, is_fqdn: bool) {
        match self {
            // CowName::Borrowed(name) => assert!(name.is_fqdn() == is_fqdn, "hmm..."),
            CowName::BorrowedName(name) => name.set_fqdn(is_fqdn),
            CowName::NameRef(name) => name.set_fqdn(is_fqdn),
            CowName::Owned(name) => name.set_fqdn(is_fqdn),
        }
    }

    #[inline]
    fn borrowed_name<'b>(&'b self) -> BorrowedName<'b> {
        match self {
            // CowName::Borrowed(name) => name.borrowed_name(),
            CowName::BorrowedName(name) => name.borrowed_name(),
            CowName::NameRef(name) => name.borrowed_name(),
            CowName::Owned(name) => name.borrowed_name(),
        }
    }
}

impl<'a> From<CowName<'a>> for Name {
    /// Attempts to diectly unwrap to Name, without allocating additionally.
    fn from(name: CowName<'a>) -> Self {
        match name {
            // CowName::Borrowed(name) => name.to_name(),
            CowName::BorrowedName(name) => name.to_name(),
            CowName::NameRef(name) => name.to_name(),
            CowName::Owned(name) => name,
        }
    }
}

impl<'a, D: DnsName + ?Sized> PartialEq<D> for CowName<'a> {
    #[inline]
    fn eq(&self, other: &D) -> bool {
        match self {
            // CowName::Borrowed(name) => name.borrowed_name().eq(other),
            CowName::BorrowedName(name) => name.eq(other),
            CowName::NameRef(name) => name.eq(other),
            CowName::Owned(name) => name.eq(other),
        }
    }
}

impl<'a, D: DnsName + ?Sized> PartialOrd<D> for CowName<'a> {
    #[inline]
    fn partial_cmp(&self, other: &D) -> Option<Ordering> {
        match self {
            // CowName::Borrowed(name) => name.borrowed_name().partial_cmp(other),
            CowName::BorrowedName(name) => name.partial_cmp(other),
            CowName::NameRef(name) => name.partial_cmp(other),
            CowName::Owned(name) => name.partial_cmp(other),
        }
    }
}

impl<'a> fmt::Display for CowName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            // CowName::Borrowed(name) => name.fmt(f),
            CowName::BorrowedName(name) => name.fmt(f),
            CowName::NameRef(name) => name.fmt(f),
            CowName::Owned(name) => name.fmt(f),
        }
    }
}

impl<'a> fmt::Debug for CowName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
