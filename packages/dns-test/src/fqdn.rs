use core::fmt;
use core::str::FromStr;
use std::borrow::Cow;

use crate::{Error, Result};

#[derive(Clone, PartialEq)]
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

    pub const COM: FQDN = FQDN {
        inner: Cow::Borrowed("com."),
    };

    pub fn is_root(&self) -> bool {
        self.inner == "."
    }

    pub fn as_str(&self) -> &str {
        &self.inner
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
