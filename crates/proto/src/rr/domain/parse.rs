use std::borrow::Cow;
use std::char;
use std::fmt::{self, Write};

use super::*;
use crate::error::*;

struct LabelCollector<'a> {
    cur_label: Cow<'a, str>,
    start_idx: usize,
    len: usize,
    name: NameCollector<'a>,
}

impl<'a> LabelCollector<'a> {
    fn new(name: &'a str) -> Self {
        let cur_label = Cow::Borrowed(name);
        let name = NameCollector::Ref(NameRef::from_unparsed_slice(name.as_bytes()));

        LabelCollector {
            cur_label,
            start_idx: 0,
            len: 0,
            name,
        }
    }

    fn is_borrowed(&self) -> bool {
        if let Cow::Borrowed(_) = self.cur_label {
            self.name.is_ref()
        } else {
            false
        }
    }

    fn push_char(&mut self, at_idx: usize, ch: char) {
        if let Cow::Borrowed(_) = self.cur_label {
            // if it's borrowed, then we are just checking that the bytes all match
            // if they don't match, then convert to owned and append
            if ch.is_ascii()
                && (self.start_idx + self.len == at_idx)
                && self
                    .cur_label
                    .as_bytes()
                    .get(at_idx)
                    .map(|s| *s == ch as u8)
                    .unwrap_or(false)
            {
                // if self
                //     .cur_label
                //     .as_bytes()
                //     .get(self.start_idx)
                //     .map(|s| *s == b'.')
                //     .unwrap_or(false)
                // {
                //     // set the new start to skip the .
                //     self.start_idx += at_idx;
                // }

                self.len += 1;
                return; // no need to do anything, just tracking the next index
            } else {
                // this was a converted char

                // because this might contain a multibyte char, we'll use chars for the conversion
                let owned = self.cur_label[self.start_idx..]
                    .chars()
                    .take(self.len)
                    .collect::<String>();
                self.cur_label = Cow::Owned(owned);
            }
        }

        // getting here means that we have an owned string that needs the label appended
        self.cur_label.to_mut().push(ch);
        self.len += 1;
    }

    fn complete_label<E: LabelEnc>(&mut self) -> Result<(), ProtoError> {
        if self.len > 0 {
            match &mut self.cur_label {
                Cow::Borrowed(label) => {
                    let end_idx = self.start_idx + self.len;

                    // this is safe, b/c push_char will convert to owned on any non-ascii characters.
                    let label = &label[self.start_idx..end_idx];
                    let label = E::to_label(label)?;

                    self.name
                        .push_label(&label.as_ref(), self.start_idx, end_idx);
                    self.is_borrowed();
                    self.start_idx = self.start_idx + self.len + 1;
                }
                Cow::Owned(label) => {
                    let new_label = E::to_label(label)?;
                    self.name.push_label(new_label.as_ref(), 0, 0);
                    label.clear();
                }
            }

            self.len = 0;
        }

        Ok(())
    }

    fn into_cow(self) -> CowName<'a> {
        self.name.into_cow()
    }

    fn set_fqdn(&mut self, is_fqdn: bool) {
        self.name.set_fqdn(is_fqdn);
    }
}

enum NameCollector<'a> {
    Ref(NameRef<'a>),
    Owned(Name),
}

impl<'a> NameCollector<'a> {
    fn is_ref(&self) -> bool {
        if let NameCollector::Ref(_) = self {
            true
        } else {
            false
        }
    }

    fn set_fqdn(&mut self, is_fqdn: bool) {
        match self {
            NameCollector::Ref(n) => n.set_fqdn(is_fqdn),
            NameCollector::Owned(n) => n.set_fqdn(is_fqdn),
        }
    }

    fn to_owned(&mut self) -> &mut Name {
        loop {
            let name = match self {
                NameCollector::Ref(name) => name.to_name(),
                NameCollector::Owned(name) => return name,
            };

            *self = NameCollector::Owned(name);
        }
    }

    fn push_label(&mut self, label: &[u8], start_idx: usize, end_idx: usize) {
        match self {
            NameCollector::Ref(ref mut name) => match name.push_label(label, start_idx, end_idx) {
                Ok(()) => return,
                Err(()) => (),
            },
            _ => (),
        }

        // need the owned version to push non-slices
        self.to_owned();

        match self {
            NameCollector::Owned(ref mut name) => name.push_label(&label),
            _ => unreachable!("Ref should have been handled above"),
        }
    }

    fn into_cow(self) -> CowName<'a> {
        match self {
            NameCollector::Ref(name) => CowName::NameRef(name),
            NameCollector::Owned(name) => CowName::Owned(name),
        }
    }
}

pub(super) fn from_encoded_str<'a, 'b: 'a, E: LabelEnc>(
    local: &'a str,
    origin: Option<&(dyn DnsName + 'b)>,
) -> ProtoResult<CowName<'a>> {
    let mut name = LabelCollector::new(local);
    let mut state = ParseState::Label;

    // short circuit root parse
    if local == "." {
        let mut name = name.into_cow();
        name.set_fqdn(true);
        return Ok(name as _);
    }

    // TODO: it would be nice to relocate this to Label, but that is hard because the label boundary can only be detected after processing escapes...
    // evaluate all characters
    for (idx, ch) in local.char_indices() {
        match state {
            ParseState::Label => match ch {
                '.' => {
                    name.complete_label::<E>()?;
                }
                '\\' => state = ParseState::Escape1,
                ch if !ch.is_control() && !ch.is_whitespace() => name.push_char(idx, ch),
                _ => return Err(format!("unrecognized char: {}", ch).into()),
            },
            ParseState::Escape1 => {
                if ch.is_numeric() {
                    state = ParseState::Escape2(
                        ch.to_digit(8)
                            .ok_or_else(|| ProtoError::from(format!("illegal char: {}", ch)))?,
                    );
                } else {
                    // it's a single escaped char
                    name.push_char(idx, ch);
                    state = ParseState::Label;
                }
            }
            ParseState::Escape2(i) => {
                if ch.is_numeric() {
                    state = ParseState::Escape3(
                        i,
                        ch.to_digit(8)
                            .ok_or_else(|| ProtoError::from(format!("illegal char: {}", ch)))?,
                    );
                } else {
                    return Err(ProtoError::from(format!("unrecognized char: {}", ch)));
                }
            }
            ParseState::Escape3(i, ii) => {
                if ch.is_numeric() {
                    // octal conversion
                    let val: u32 = (i * 8 * 8)
                        + (ii * 8)
                        + ch.to_digit(8)
                            .ok_or_else(|| ProtoError::from(format!("illegal char: {}", ch)))?;
                    let ch: char = char::from_u32(val)
                        .ok_or_else(|| ProtoError::from(format!("illegal char: {}", ch)))?;
                    name.push_char(idx, ch);
                    state = ParseState::Label;
                } else {
                    return Err(format!("unrecognized char: {}", ch).into());
                }
            }
        }
    }

    // completes the current label
    name.complete_label::<E>()?;

    if local.ends_with('.') {
        name.set_fqdn(true);
    } else if let Some(other) = origin {
        let mut name = name.into_cow();
        name.to_mut().append_domain2(other);
        return Ok(name);
    }

    Ok(name.into_cow() as _)
}

enum ParseState {
    Label,
    Escape1,
    Escape2(u32),
    Escape3(u32, u32),
}

pub trait LabelEnc {
    fn to_label<'a>(name: &'a str) -> ProtoResult<Cow<'a, [u8]>>;
    fn write_label<W: Write, L: DnsLabel>(f: &mut W, label: &L) -> Result<(), fmt::Error>;
}

pub(super) struct LabelEncAscii;
impl LabelEnc for LabelEncAscii {
    fn to_label<'a>(name: &'a str) -> ProtoResult<Cow<'a, [u8]>> {
        LabelRef::from_ascii(name)
            .map(|n| n.as_bytes())
            .map(Cow::Borrowed)
    }

    fn write_label<W: Write, L: DnsLabel>(f: &mut W, label: &L) -> Result<(), fmt::Error> {
        label.write_ascii(f)
    }
}

pub(super) struct LabelEncUtf8;
impl LabelEnc for LabelEncUtf8 {
    fn to_label<'a>(name: &'a str) -> ProtoResult<Cow<'a, [u8]>> {
        Label::parse_label_no_alloc(name)
    }

    fn write_label<W: Write, L: DnsLabel>(f: &mut W, label: &L) -> Result<(), fmt::Error> {
        label.write_utf8(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_alloc() {
        let name = from_encoded_str::<LabelEncAscii>("www.example.com", None).unwrap();

        assert!(!name.is_fqdn());
        assert!(name.is_borrowed());

        let mut labels = name.labels();
        assert_eq!(labels.next().unwrap().as_bytes(), b"www");
        assert_eq!(labels.next().unwrap().as_bytes(), b"example");
        assert_eq!(labels.next().unwrap().as_bytes(), b"com");

        let name = from_encoded_str::<LabelEncAscii>("www.example.com.", None).unwrap();
        assert!(name.is_fqdn());
        assert!(name.is_borrowed());
    }

    #[test]
    fn test_fail_alloc() {
        let name = from_encoded_str::<LabelEncAscii>("www.🦀.com", None);

        assert!(name.is_err());
    }
}
