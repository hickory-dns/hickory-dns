use core::fmt;
use core::str::FromStr;
use std::borrow::Cow;

use crate::Error;

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct FQDN {
    inner: Cow<'static, str>,
}

// TODO likely needs further validation
#[allow(non_snake_case)]
pub fn FQDN(input: impl Into<Cow<'static, str>>) -> Result<FQDN, Error> {
    let input = input.into();

    if !input.ends_with('.') {
        return Err("FQDN must end with a `.`".into());
    }

    if input != "." && input.starts_with('.') {
        return Err("non-root FQDN cannot start with a `.`".into());
    }

    Ok(FQDN { inner: input })
}

impl FQDN {
    pub const ROOT: Self = Self {
        inner: Cow::Borrowed("."),
    };

    pub const TEST_TLD: Self = Self {
        inner: Cow::Borrowed("testing."),
    };

    pub const COM_TLD: Self = Self {
        inner: Cow::Borrowed("com."),
    };

    pub const EDE_DOT_COM: Self = Self {
        inner: Cow::Borrowed("extended-dns-errors.com."),
    };

    pub const TEST_DOMAIN: Self = Self {
        inner: Cow::Borrowed("hickory-dns.testing."),
    };

    pub const EXAMPLE_SUBDOMAIN: Self = Self {
        inner: Cow::Borrowed("example.hickory-dns.testing."),
    };

    pub fn is_root(&self) -> bool {
        self.inner == "."
    }

    pub fn as_str(&self) -> &str {
        &self.inner
    }

    pub fn push_label(&self, label: &str) -> Self {
        assert!(!label.is_empty());
        assert!(!label.contains('.'));

        Self {
            inner: format!("{label}.{}", self.inner).into(),
        }
    }

    pub fn into_owned(self) -> Self {
        let owned = match self.inner {
            Cow::Borrowed(borrowed) => borrowed.to_string(),
            Cow::Owned(owned) => owned,
        };

        Self {
            inner: Cow::Owned(owned),
        }
    }

    pub fn parent(&self) -> Option<Self> {
        let (fragment, parent) = self.inner.split_once('.').unwrap();

        if fragment.is_empty() {
            None
        } else {
            let parent = if parent.is_empty() {
                Self::ROOT
            } else {
                FQDN(parent.to_string()).unwrap()
            };
            Some(parent)
        }
    }

    /// Returns true if this domain name is an ancestor of another domain name.
    ///
    /// This returns true if all the labels of this name appear in the other name, starting on the right side.
    pub fn is_ancestor_of(&self, other: &Self) -> bool {
        // Skip empty substrings to avoid special cases related to the root name.
        let mut self_labels = self.inner.rsplit('.').filter(|label| !label.is_empty());
        let mut other_labels = other.inner.rsplit('.').filter(|label| !label.is_empty());
        loop {
            match (self_labels.next(), other_labels.next()) {
                // Labels are equal, check next label.
                (Some(self_label), Some(other_label)) if self_label == other_label => continue,
                // Labels are not equal.
                (Some(_), Some(_)) => return false,
                // Names are equal.
                (None, None) => return true,
                // Other name is a descendant.
                (None, Some(_)) => return true,
                // The other name is an ancestor, not self.
                (Some(_), None) => return false,
            }
        }
    }

    pub fn num_labels(&self) -> usize {
        self.inner
            .split('.')
            .filter(|label| !label.is_empty())
            .count()
    }

    pub fn last_label(&self) -> &str {
        self.inner.split_once('.').map(|(label, _)| label).unwrap()
    }
}

impl FromStr for FQDN {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Error> {
        FQDN(input.to_string())
    }
}

impl fmt::Debug for FQDN {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for FQDN {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent() -> Result<(), Error> {
        let mut fqdn = FQDN::EXAMPLE_SUBDOMAIN;
        assert_eq!(3, fqdn.num_labels());

        let parent = fqdn.parent();
        assert_eq!(Some(FQDN::TEST_DOMAIN), parent);
        fqdn = parent.unwrap();
        assert_eq!(2, fqdn.num_labels());

        let parent = fqdn.parent();
        assert_eq!(Some(FQDN::TEST_TLD), parent);
        fqdn = parent.unwrap();
        assert_eq!(1, fqdn.num_labels());

        let parent = fqdn.parent();
        assert_eq!(Some(FQDN::ROOT), parent);
        fqdn = parent.unwrap();
        assert_eq!(0, fqdn.num_labels());

        let parent = fqdn.parent();
        assert!(parent.is_none());

        Ok(())
    }

    #[test]
    fn ancestor() -> Result<(), Error> {
        assert!(!FQDN("abcd.")?.is_ancestor_of(&FQDN("cd.")?));
        assert!(!FQDN("cd.")?.is_ancestor_of(&FQDN("abcd.")?));

        assert!(FQDN("com.")?.is_ancestor_of(&FQDN("com.")?));
        assert!(FQDN(".")?.is_ancestor_of(&FQDN("com.")?));
        assert!(!FQDN("com.")?.is_ancestor_of(&FQDN(".")?));

        assert!(!FQDN("a.b.c.d.")?.is_ancestor_of(&FQDN("b.c.d.")?));
        assert!(FQDN("b.c.d.")?.is_ancestor_of(&FQDN("a.b.c.d.")?));
        assert!(!FQDN("a.b.c.d.")?.is_ancestor_of(&FQDN("z.b.c.d.")?));
        assert!(!FQDN("www.a.b.c.d.")?.is_ancestor_of(&FQDN("www.z.b.c.d.")?));

        Ok(())
    }
}
