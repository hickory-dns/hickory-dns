// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Labels are used as the internal components of a Name.
//!
//! A label is stored internally as ascii, where all unicode characters are converted to punycode internally.

#[allow(clippy::useless_attribute)]
#[allow(unused)]
#[allow(deprecated)]
use std::ascii::AsciiExt;
use std::borrow::Borrow;
use std::cmp::{Ordering, PartialEq};
use std::fmt::{self, Debug, Display, Formatter, Write};
use std::hash::{Hash, Hasher};
use tinyvec::TinyVec;

use idna;
use log::debug;

use crate::error::*;

const WILDCARD: &[u8] = b"*";
const IDNA_PREFIX: &[u8] = b"xn--";

/// Labels are always stored as ASCII, unicode characters must be encoded with punycode
#[derive(Clone, Eq)]
pub struct Label(TinyVec<[u8; 24]>);

impl Label {
    /// These must only be ASCII, with unicode encoded to PunyCode, or other such transformation.
    ///
    /// This uses the bytes as raw ascii values, with nothing escaped on the wire.
    /// Generally users should use `from_str` or `from_ascii`
    pub fn from_raw_bytes(bytes: &[u8]) -> ProtoResult<Self> {
        if bytes.len() > 63 {
            return Err(format!("Label exceeds maximum length 63: {}", bytes.len()).into());
        };
        Ok(Self(TinyVec::from(bytes)))
    }

    /// Translates this string into IDNA safe name, encoding to punycode as necessary.
    pub fn from_utf8(s: &str) -> ProtoResult<Self> {
        if s.as_bytes() == WILDCARD {
            return Ok(Self::wildcard());
        }

        // special case for SRV type records
        if s.starts_with('_') {
            return Self::from_ascii(s);
        }

        match idna::Config::default()
            .use_std3_ascii_rules(true)
            .transitional_processing(true)
            .verify_dns_length(true)
            .to_ascii(s)
        {
            Ok(puny) => Self::from_ascii(&puny),
            e => Err(format!("Label contains invalid characters: {:?}", e).into()),
        }
    }

    /// Takes the ascii string and returns a new label.
    ///
    /// This will return an Error if the label is not an ascii string
    pub fn from_ascii(s: &str) -> ProtoResult<Self> {
        if s.as_bytes() == WILDCARD {
            return Ok(Self::wildcard());
        }

        if !s.is_empty()
            && s.is_ascii()
            && s.chars().take(1).all(|c| is_safe_ascii(c, true, false))
            && s.chars().skip(1).all(|c| is_safe_ascii(c, false, false))
        {
            Self::from_raw_bytes(s.as_bytes())
        } else {
            Err(format!("Malformed label: {}", s).into())
        }
    }

    /// Returns a new Label of the Wildcard, i.e. "*"
    pub fn wildcard() -> Self {
        Self(TinyVec::from(WILDCARD))
    }

    /// Converts this label to lowercase
    pub fn to_lowercase(&self) -> Self {
        // TODO: replace case conversion when (ascii_ctype #39658) stabilizes
        if let Some((idx, _)) = self
            .0
            .iter()
            .enumerate()
            .find(|&(_, c)| *c != c.to_ascii_lowercase())
        {
            let mut lower_label: Vec<u8> = self.0.to_vec();
            lower_label[idx..].make_ascii_lowercase();
            Self(TinyVec::from(lower_label.as_slice()))
        } else {
            self.clone()
        }
    }

    /// Returns true if this label is the wildcard, '*', label
    pub fn is_wildcard(&self) -> bool {
        self.as_bytes() == WILDCARD
    }

    /// Returns the lenght in bytes of this label
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if the label contains no characters
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the raw bytes of the label, this is good for writing to the wire.
    ///
    /// See [`Display`] for presentation version (unescaped from punycode, etc)
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Performs the equivalence operation disregarding case
    pub fn eq_ignore_ascii_case(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }

    /// compares with the other label, ignoring case
    pub fn cmp_with_f<F: LabelCmp>(&self, other: &Self) -> Ordering {
        let s = self.0.iter();
        let o = other.0.iter();

        for (s, o) in s.zip(o) {
            match F::cmp_u8(*s, *o) {
                Ordering::Equal => continue,
                not_eq => return not_eq,
            }
        }

        self.0.len().cmp(&other.0.len())
    }

    /// Performs the conversion to utf8 from IDNA as necessary, see `fmt` for more details
    pub fn to_utf8(&self) -> String {
        format!("{}", self)
    }

    /// Converts this label to safe ascii, escaping characters as necessary
    ///
    /// If this is an IDNA, punycode, label, then the xn-- prefix will be maintained as ascii
    pub fn to_ascii(&self) -> String {
        let mut ascii = String::with_capacity(self.as_bytes().len());

        self.write_ascii(&mut ascii)
            .expect("should never fail to write a new string");
        ascii
    }

    /// Writes this label to safe ascii, escaping characters as necessary
    pub fn write_ascii<W: Write>(&self, f: &mut W) -> Result<(), fmt::Error> {
        // We can't guarantee that the same input will always translate to the same output
        fn escape_non_ascii<W: Write>(
            byte: u8,
            f: &mut W,
            is_first: bool,
        ) -> Result<(), fmt::Error> {
            let to_triple_escape = |ch: u8| format!("\\{:03o}", ch);
            let to_single_escape = |ch: char| format!("\\{}", ch);

            match char::from(byte) {
                c if is_safe_ascii(c, is_first, true) => f.write_char(c)?,
                // it's not a control and is printable as well as inside the standard ascii range
                c if byte > b'\x20' && byte < b'\x7f' => f.write_str(&to_single_escape(c))?,
                _ => f.write_str(&to_triple_escape(byte))?,
            }

            Ok(())
        }

        // traditional ascii case...
        let mut chars = self.as_bytes().iter();
        if let Some(ch) = chars.next() {
            escape_non_ascii(*ch, f, true)?;
        }

        for ch in chars {
            escape_non_ascii(*ch, f, false)?;
        }

        Ok(())
    }
}

impl AsRef<[u8]> for Label {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Borrow<[u8]> for Label {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

fn is_safe_ascii(c: char, is_first: bool, for_encoding: bool) -> bool {
    match c {
        c if !c.is_ascii() => false,
        c if c.is_alphanumeric() => true,
        '-' if !is_first => true,     // dash is allowed
        '_' => true,                  // SRV like labels
        '*' if is_first => true,      // wildcard
        '.' if !for_encoding => true, // needed to allow dots, for things like email addresses
        _ => false,
    }
}

impl Display for Label {
    /// outputs characters in a safe string manner.
    ///
    /// if the string is punycode, i.e. starts with `xn--`, otherwise it translates to a safe ascii string
    ///   escaping characters as necessary.
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        if self.as_bytes().starts_with(IDNA_PREFIX) {
            // this should never be outside the ascii codes...
            let label = String::from_utf8_lossy(self.borrow());
            let (label, e) = idna::Config::default()
                .use_std3_ascii_rules(false)
                .transitional_processing(false)
                .verify_dns_length(false)
                .to_unicode(&label);

            if e.is_ok() {
                return f.write_str(&label);
            } else {
                debug!(
                    "xn-- prefixed string did not translate via IDNA properly: {:?}",
                    e
                )
            }
        }

        // it wasn't known to be utf8
        self.write_ascii(f)
    }
}

impl Debug for Label {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        let label = String::from_utf8_lossy(self.borrow());
        f.write_str(&label)
    }
}

impl PartialEq<Self> for Label {
    fn eq(&self, other: &Self) -> bool {
        self.eq_ignore_ascii_case(other)
    }
}

impl PartialOrd<Self> for Label {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Label {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_with_f::<CaseInsensitive>(other)
    }
}

impl Hash for Label {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        for b in self.borrow() as &[u8] {
            state.write_u8(b.to_ascii_lowercase());
        }
    }
}

/// Label comparison trait for case sensitive or insensitive comparisons
pub trait LabelCmp {
    /// this should mimic the cmp method from [`PartialOrd`]
    fn cmp_u8(l: u8, r: u8) -> Ordering;
}

/// For case sensitive comparisons
pub(super) struct CaseSensitive;

impl LabelCmp for CaseSensitive {
    fn cmp_u8(l: u8, r: u8) -> Ordering {
        l.cmp(&r)
    }
}

/// For case insensitive comparisons
pub(super) struct CaseInsensitive;

impl LabelCmp for CaseInsensitive {
    fn cmp_u8(l: u8, r: u8) -> Ordering {
        l.to_ascii_lowercase().cmp(&r.to_ascii_lowercase())
    }
}

/// Conversion into a Label
pub trait IntoLabel: Sized {
    /// Convert this into Label
    fn into_label(self) -> ProtoResult<Label>;
}

impl<'a> IntoLabel for &'a Label {
    fn into_label(self) -> ProtoResult<Label> {
        Ok(self.clone())
    }
}

impl IntoLabel for Label {
    fn into_label(self) -> ProtoResult<Label> {
        Ok(self)
    }
}

impl<'a> IntoLabel for &'a str {
    fn into_label(self) -> ProtoResult<Label> {
        Label::from_utf8(self)
    }
}

impl IntoLabel for String {
    fn into_label(self) -> ProtoResult<Label> {
        Label::from_utf8(&self)
    }
}

impl<'a> IntoLabel for &'a [u8] {
    fn into_label(self) -> ProtoResult<Label> {
        Label::from_raw_bytes(self)
    }
}

impl IntoLabel for Vec<u8> {
    fn into_label(self) -> ProtoResult<Label> {
        Label::from_raw_bytes(&self)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;

    #[test]
    fn test_encoding() {
        assert_eq!(
            Label::from_utf8("abc").unwrap(),
            Label::from_raw_bytes(b"abc").unwrap()
        );
        // case insensitive, this works...
        assert_eq!(
            Label::from_utf8("ABC").unwrap(),
            Label::from_raw_bytes(b"ABC").unwrap()
        );
        assert_eq!(
            Label::from_utf8("🦀").unwrap(),
            Label::from_raw_bytes(b"xn--zs9h").unwrap()
        );
        assert_eq!(
            Label::from_utf8("rust-🦀-icon").unwrap(),
            Label::from_raw_bytes(b"xn--rust--icon-9447i").unwrap()
        );
        assert_eq!(
            Label::from_ascii("ben.fry").unwrap(),
            Label::from_raw_bytes(b"ben.fry").unwrap()
        );
        assert_eq!(Label::from_utf8("🦀").unwrap().to_utf8(), "🦀");
        assert_eq!(Label::from_utf8("🦀").unwrap().to_ascii(), "xn--zs9h");
    }

    #[test]
    fn test_decoding() {
        assert_eq!(Label::from_raw_bytes(b"abc").unwrap().to_string(), "abc");
        assert_eq!(
            Label::from_raw_bytes(b"xn--zs9h").unwrap().to_string(),
            "🦀"
        );
        assert_eq!(
            Label::from_raw_bytes(b"xn--rust--icon-9447i")
                .unwrap()
                .to_string(),
            "rust-🦀-icon"
        );
    }

    #[test]
    fn test_to_lowercase() {
        assert_ne!(Label::from_ascii("ABC").unwrap().to_string(), "abc");
        assert_ne!(Label::from_ascii("abcDEF").unwrap().to_string(), "abcdef");
        assert_eq!(
            Label::from_ascii("ABC").unwrap().to_lowercase().to_string(),
            "abc"
        );
        assert_eq!(
            Label::from_ascii("abcDEF")
                .unwrap()
                .to_lowercase()
                .to_string(),
            "abcdef"
        );
    }

    #[test]
    fn test_to_cmp_f() {
        assert_eq!(
            Label::from_ascii("ABC")
                .unwrap()
                .cmp_with_f::<CaseInsensitive>(&Label::from_ascii("abc").unwrap()),
            Ordering::Equal
        );
        assert_eq!(
            Label::from_ascii("abcDEF")
                .unwrap()
                .cmp_with_f::<CaseInsensitive>(&Label::from_ascii("abcdef").unwrap()),
            Ordering::Equal
        );
        assert_eq!(
            Label::from_ascii("ABC")
                .unwrap()
                .cmp_with_f::<CaseSensitive>(&Label::from_ascii("abc").unwrap()),
            Ordering::Less
        );
        assert_eq!(
            Label::from_ascii("abcDEF")
                .unwrap()
                .cmp_with_f::<CaseSensitive>(&Label::from_ascii("abcdef").unwrap()),
            Ordering::Less
        );
    }

    #[test]
    fn test_partial_cmp() {
        let comparisons: Vec<(Label, Label)> = vec![
            (
                Label::from_raw_bytes(b"yljkjljk").unwrap(),
                Label::from_raw_bytes(b"Z").unwrap(),
            ),
            (
                Label::from_raw_bytes(b"Z").unwrap(),
                Label::from_raw_bytes(b"zABC").unwrap(),
            ),
            (
                Label::from_raw_bytes(&[1]).unwrap(),
                Label::from_raw_bytes(b"*").unwrap(),
            ),
            (
                Label::from_raw_bytes(b"*").unwrap(),
                Label::from_raw_bytes(&[200]).unwrap(),
            ),
        ];

        for (left, right) in comparisons {
            println!("left: {}, right: {}", left, right);
            assert_eq!(left.cmp(&right), Ordering::Less);
        }
    }

    #[test]
    fn test_is_wildcard() {
        assert!(Label::from_raw_bytes(b"*").unwrap().is_wildcard());
        assert!(Label::from_ascii("*").unwrap().is_wildcard());
        assert!(Label::from_utf8("*").unwrap().is_wildcard());
        assert!(!Label::from_raw_bytes(b"abc").unwrap().is_wildcard());
    }

    #[test]
    fn test_ascii_escape() {
        assert_eq!(
            Label::from_raw_bytes(&[0o200]).unwrap().to_string(),
            "\\200"
        );
        assert_eq!(
            Label::from_raw_bytes(&[0o001]).unwrap().to_string(),
            "\\001"
        );
        assert_eq!(Label::from_ascii(".").unwrap().to_ascii(), "\\.");
        assert_eq!(
            Label::from_ascii("ben.fry").unwrap().to_string(),
            "ben\\.fry"
        );
        assert_eq!(Label::from_raw_bytes(&[0o200]).unwrap().to_ascii(), "\\200");
    }
}
