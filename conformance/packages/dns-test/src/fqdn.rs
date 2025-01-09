use core::fmt;
use core::str::FromStr;
use std::borrow::Cow;

use crate::{Error, Result};

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct FQDN {
    inner: Cow<'static, str>,
}

// TODO likely needs further validation
#[allow(non_snake_case)]
pub fn FQDN(input: impl Into<Cow<'static, str>>) -> Result<FQDN> {
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
    pub const ROOT: FQDN = FQDN {
        inner: Cow::Borrowed("."),
    };

    pub const TEST_TLD: FQDN = FQDN {
        inner: Cow::Borrowed("testing."),
    };

    pub const COM_TLD: FQDN = FQDN {
        inner: Cow::Borrowed("com."),
    };

    pub const EDE_DOT_COM: FQDN = FQDN {
        inner: Cow::Borrowed("extended-dns-errors.com."),
    };

    pub const TEST_DOMAIN: FQDN = FQDN {
        inner: Cow::Borrowed("hickory-dns.testing."),
    };

    pub const EXAMPLE_SUBDOMAIN: FQDN = FQDN {
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

    pub fn into_owned(self) -> FQDN {
        let owned = match self.inner {
            Cow::Borrowed(borrowed) => borrowed.to_string(),
            Cow::Owned(owned) => owned,
        };

        FQDN {
            inner: Cow::Owned(owned),
        }
    }

    pub fn parent(&self) -> Option<FQDN> {
        let (fragment, parent) = self.inner.split_once('.').unwrap();

        if fragment.is_empty() {
            None
        } else {
            let parent = if parent.is_empty() {
                FQDN::ROOT
            } else {
                FQDN(parent.to_string()).unwrap()
            };
            Some(parent)
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

    fn from_str(input: &str) -> Result<Self> {
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
    fn parent() -> Result<()> {
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
}
