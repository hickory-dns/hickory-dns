use core::fmt;
use std::borrow::Cow;

use crate::Result;

#[derive(Clone)]
pub struct Domain<'a> {
    inner: Cow<'a, str>,
}

// TODO likely needs further validation
#[allow(non_snake_case)]
pub fn Domain<'a>(input: impl Into<Cow<'a, str>>) -> Result<Domain<'a>> {
    let input = input.into();
    if !input.ends_with('.') {
        return Err("domain must end with a `.`".into());
    }

    if input != "." && input.starts_with('.') {
        return Err("non-root domain cannot start with a `.`".into());
    }

    Ok(Domain { inner: input })
}

impl<'a> Domain<'a> {
    pub const ROOT: Domain<'static> = Domain {
        inner: Cow::Borrowed("."),
    };

    pub fn is_root(&self) -> bool {
        self.inner == "."
    }

    pub fn as_str(&self) -> &str {
        &self.inner
    }

    pub fn into_owned(self) -> Domain<'static> {
        let owned = match self.inner {
            Cow::Borrowed(borrowed) => borrowed.to_string(),
            Cow::Owned(owned) => owned,
        };

        Domain {
            inner: Cow::Owned(owned),
        }
    }
}

impl fmt::Display for Domain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.inner)
    }
}
