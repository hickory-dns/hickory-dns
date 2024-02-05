use crate::Result;

#[derive(Clone, Copy)]
pub struct Domain<'a> {
    inner: &'a str,
}

// TODO likely needs further validation
#[allow(non_snake_case)]
pub fn Domain(input: &str) -> Result<Domain<'_>> {
    if !input.ends_with('.') {
        return Err("domain must end with a `.`".into());
    }

    if input != "." && input.starts_with('.') {
        return Err("non-root domain cannot start with a `.`".into());
    }

    Ok(Domain { inner: input })
}

impl<'a> Domain<'a> {
    pub const ROOT: Domain<'static> = Domain { inner: "." };

    pub fn is_root(&self) -> bool {
        self.inner == "."
    }

    pub fn as_str(&self) -> &'a str {
        self.inner
    }
}
