use core::fmt;
use core::str::FromStr;
use std::borrow::Cow;

use crate::{Error, Result};

#[derive(Clone, PartialEq)]
pub struct FQDN<'a> {
    inner: Cow<'a, str>,
}

// TODO likely needs further validation
#[allow(non_snake_case)]
pub fn FQDN<'a>(input: impl Into<Cow<'a, str>>) -> Result<FQDN<'a>> {
    let input = input.into();
    if !input.ends_with('.') {
        return Err("domain must end with a `.`".into());
    }

    if input != "." && input.starts_with('.') {
        return Err("non-root domain cannot start with a `.`".into());
    }

    Ok(FQDN { inner: input })
}

impl<'a> FQDN<'a> {
    pub const ROOT: FQDN<'static> = FQDN {
        inner: Cow::Borrowed("."),
    };

    pub const COM: FQDN<'static> = FQDN {
        inner: Cow::Borrowed("com."),
    };

    pub fn is_root(&self) -> bool {
        self.inner == "."
    }

    pub fn as_str(&self) -> &str {
        &self.inner
    }

    pub fn into_owned(self) -> FQDN<'static> {
        let owned = match self.inner {
            Cow::Borrowed(borrowed) => borrowed.to_string(),
            Cow::Owned(owned) => owned,
        };

        FQDN {
            inner: Cow::Owned(owned),
        }
    }
}

impl FromStr for FQDN<'static> {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Ok(FQDN(input)?.into_owned())
    }
}

impl fmt::Debug for FQDN<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for FQDN<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.inner)
    }
}
