// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Labels are used as the internal components of a Name.
//!
//! A label is stored internally as ascii, where all unicode characters are converted to punycode internally.

use alloc::{string::String, vec::Vec};
use core::borrow::Borrow;
use core::cmp::{Ordering, PartialEq};
use core::fmt::{self, Debug, Display, Formatter, Write};
use core::hash::{Hash, Hasher};

use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};
use tinyvec::TinyVec;
use tracing::debug;

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
        // Check for label validity.
        // RFC 2181, Section 11 "Name Syntax".
        // > The length of any one label is limited to between 1 and 63 octets.
        if bytes.is_empty() {
            return Err("Label requires a minimum length of 1".into());
        }
        if bytes.len() > 63 {
            return Err(ProtoErrorKind::LabelBytesTooLong(bytes.len()).into());
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

        // length don't exceeding 63 is done in `from_ascii`
        // on puny encoded string
        // idna error are opaque so early failure is not possible.
        match Uts46::new().to_ascii(
            s.as_bytes(),
            AsciiDenyList::STD3,
            Hyphens::Allow,
            DnsLength::Ignore,
        ) {
            Ok(puny) => Self::from_ascii(&puny),
            e => Err(format!("Label contains invalid characters: {e:?}").into()),
        }
    }

    /// Takes the ascii string and returns a new label.
    ///
    /// This will return an Error if the label is not an ascii string
    pub fn from_ascii(s: &str) -> ProtoResult<Self> {
        if s.len() > 63 {
            return Err(ProtoErrorKind::LabelBytesTooLong(s.len()).into());
        }

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
            Err(format!("Malformed label: {s}").into())
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

    /// Returns the length in bytes of this label
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
        format!("{self}")
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
            let to_triple_escape = |ch: u8| format!("\\{ch:03o}");
            let to_single_escape = |ch: char| format!("\\{ch}");

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
            let (label, e) =
                Uts46::new().to_unicode(label.as_bytes(), AsciiDenyList::EMPTY, Hyphens::Allow);

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

impl IntoLabel for &Label {
    fn into_label(self) -> ProtoResult<Label> {
        Ok(self.clone())
    }
}

impl IntoLabel for Label {
    fn into_label(self) -> ProtoResult<Label> {
        Ok(self)
    }
}

impl IntoLabel for &str {
    fn into_label(self) -> ProtoResult<Label> {
        Label::from_utf8(self)
    }
}

impl IntoLabel for String {
    fn into_label(self) -> ProtoResult<Label> {
        Label::from_utf8(&self)
    }
}

impl IntoLabel for &[u8] {
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

    use alloc::string::ToString;
    use std::{eprintln, println};

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

    fn assert_panic_label_too_long(error: ProtoResult<Label>, len: usize) {
        // poor man debug since ProtoResult don't implement Partial Eq due to ssl errors.
        eprintln!("{error:?}");
        assert!(error.is_err());
        match error.unwrap_err().kind() {
            ProtoErrorKind::LabelBytesTooLong(n) if *n == len => (),
            ProtoErrorKind::LabelBytesTooLong(e) => {
                panic!(
                    "LabelTooLongError error don't report expected size {} of the label provided.",
                    e
                )
            }
            _ => panic!("Should have returned a LabelTooLongError"),
        }
    }

    #[test]
    fn test_label_too_long_ascii_with_utf8() {
        let label_too_long = "alwaystestingcodewithatoolonglabeltoolongtofitin63bytesisagoodhabit";
        let error = Label::from_utf8(label_too_long);
        assert_panic_label_too_long(error, label_too_long.len());
    }

    #[test]
    fn test_label_too_long_utf8_puny_emoji() {
        // too long only puny 65
        let emoji_case = "💜🦀🏖️🖥️😨🚀✨🤖💚🦾🦿😱😨✉️👺📚💻🗓️🤡🦀😈🚀💀⚡🦄";
        let error = Label::from_utf8(emoji_case);
        assert_panic_label_too_long(error, 64);
    }

    #[test]
    fn test_label_too_long_utf8_puny_emoji_mixed() {
        // too long mixed 65
        // Something international to say
        // "Hello I like automn coffee 🦀 interesting"
        let emoji_case = "こんにちは-I-mögen-jesień-café-🦀-intéressant";
        let error = Label::from_utf8(emoji_case);
        assert_panic_label_too_long(error, 65);
    }

    #[test]
    fn test_label_too_long_utf8_puny_mixed() {
        // edge case 64 octet long.
        // xn--testwithalonglabelinutf8tofitin63octetsisagoodhabit-f2106cqb
        let edge_case = "🦀testwithalonglabelinutf8tofitin63octetsisagoodhabit🦀";
        let error = Label::from_utf8(edge_case);
        assert_panic_label_too_long(error, 64);
    }

    #[test]
    fn test_label_too_long_raw() {
        let label_too_long = b"alwaystestingcodewithatoolonglabeltoolongtofitin63bytesisagoodhabit";
        let error = Label::from_raw_bytes(label_too_long);
        assert_panic_label_too_long(error, label_too_long.len());
    }

    #[test]
    fn test_label_too_long_ascii() {
        let label_too_long = "alwaystestingcodewithatoolonglabeltoolongtofitin63bytesisagoodhabit";
        let error = Label::from_ascii(label_too_long);
        assert_panic_label_too_long(error, label_too_long.len());
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
    fn test_from_ascii_adversial_utf8() {
        let expect_err = Label::from_ascii("🦀");
        assert!(expect_err.is_err());
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
            println!("left: {left}, right: {right}");
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
