use super::*;

pub enum CowName<'a> {
    Borrowed(&'a dyn DnsName),
    BorrowedName(BorrowedName<'a>),
    NameRef(NameRef<'a>),
    Owned(Name),
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
        CowName::Borrowed(name)
    }
}

impl<'a> CowName<'a> {
    pub fn is_borrowed(&self) -> bool {
        !self.is_owned()
    }

    pub fn is_owned(&self) -> bool {
        if let CowName::Owned(_) = self {
            true
        } else {
            false
        }
    }

    pub fn borrowed(&'a self) -> &'a (dyn DnsName + 'a) {
        match self {
            CowName::Borrowed(name) => *name,
            CowName::BorrowedName(name) => name,
            CowName::NameRef(name) => name,
            CowName::Owned(name) => name,
        }
    }

    pub fn to_mut(&mut self) -> &mut Name {
        match self {
            CowName::Borrowed(name) => *self = CowName::Owned(name.to_owned()),
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
    fn labels(&self) -> LabelIter {
        match self {
            CowName::Borrowed(name) => name.labels(),
            CowName::BorrowedName(name) => name.labels(),
            CowName::NameRef(name) => name.labels(),
            CowName::Owned(name) => name.labels(),
        }
    }

    fn is_fqdn(&self) -> bool {
        match self {
            CowName::Borrowed(name) => name.is_fqdn(),
            CowName::BorrowedName(name) => name.is_fqdn(),
            CowName::NameRef(name) => name.is_fqdn(),
            CowName::Owned(name) => name.is_fqdn(),
        }
    }

    fn set_fqdn(&mut self, is_fqdn: bool) {
        match self {
            CowName::Borrowed(name) => assert!(name.is_fqdn() == is_fqdn, "hmm..."),
            CowName::BorrowedName(name) => name.set_fqdn(is_fqdn),
            CowName::NameRef(name) => name.set_fqdn(is_fqdn),
            CowName::Owned(name) => name.set_fqdn(is_fqdn),
        }
    }

    fn borrowed_name<'b>(&'b self) -> BorrowedName<'b> {
        match self {
            CowName::Borrowed(name) => name.borrowed_name(),
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
            CowName::Borrowed(name) => name.to_name(),
            CowName::BorrowedName(name) => name.to_name(),
            CowName::NameRef(name) => name.to_name(),
            CowName::Owned(name) => name,
        }
    }
}
