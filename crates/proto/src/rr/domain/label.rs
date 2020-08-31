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
use std::borrow::{Borrow, Cow};
use std::cmp::{Ordering, PartialEq};
use std::fmt::{self, Debug, Display, Formatter, Write};
use std::hash::{Hash, Hasher};

use idna;
use log::debug;

use crate::error::*;

pub(super) const ROOT_LABEL: &[u8] = b".";
const WILDCARD: &[u8] = b"*";
const IDNA_PREFIX: &[u8] = b"xn--";

/// Labels are always stored as ASCII, unicode characters must be encoded with punycode
pub trait DnsLabel {
    /// Zero cost conversion for the Label to bytes
    fn as_bytes(&self) -> &[u8];

    /// Check if this label is (ascii chars only) lowercase
    #[inline]
    fn is_root(&self) -> bool {
        self.as_bytes() == ROOT_LABEL || self.is_empty()
    }

    /// Check if this label is (ascii chars only) lowercase
    #[inline]
    fn is_lowercase(&self) -> bool {
        let bytes = self.as_bytes();
        bytes.iter().all(|c| c.is_ascii_lowercase())
    }

    /// Is this Label of 0 length
    #[inline]
    fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }

    /// Length in bytes of this Label
    fn len(&self) -> usize {
        self.as_bytes().len()
    }

    /// Returns true if this label is the wildcard, '*', label
    #[inline]
    fn is_wildcard(&self) -> bool {
        self.as_bytes() == WILDCARD
    }

    /// Performs the equivalence operation disregarding case
    #[inline]
    fn eq_ignore_ascii_case<D: DnsLabel + ?Sized>(&self, other: &D) -> bool {
        self.as_bytes().eq_ignore_ascii_case(&other.as_bytes())
    }

    /// compares with the other label, ignoring case
    #[inline]
    fn cmp_with_f<F: LabelCmp>(&self, other: &Self) -> Ordering {
        let s = self.as_bytes().iter();
        let o = other.as_bytes().iter();

        for (s, o) in s.zip(o) {
            match F::cmp_u8(*s, *o) {
                Ordering::Equal => continue,
                not_eq => return not_eq,
            }
        }

        self.as_bytes().len().cmp(&other.as_bytes().len())
    }

    /// Checks to see that these bytes are ascii only
    ///
    /// # Example
    ///
    /// ```rust
    /// use trust_dns_proto::rr::domain::{DnsLabel, LabelRef};
    ///
    /// assert!(LabelRef::from_raw_bytes(b"www").unwrap().is_safe_ascii());
    /// assert!(!LabelRef::from_raw_bytes(b"www.").unwrap().is_safe_ascii());
    /// assert!(!LabelRef::from_raw_bytes("🦀".as_bytes()).unwrap().is_safe_ascii());
    /// ```
    #[inline]
    fn is_safe_ascii(&self) -> bool {
        fn inner_is_safe_ascii(byte: u8, is_first: bool) -> bool {
            match char::from(byte) {
                c if is_safe_ascii(c, is_first, true) => (),
                // it's not a control and is printable as well as inside the standard ascii range
                _c if byte > b'\x20' && byte < b'\x7f' => return false,
                _ => return false,
            }

            true
        }

        // traditional ascii case...
        let mut chars = self.as_bytes().iter();
        if let Some(ch) = chars.next() {
            if !inner_is_safe_ascii(*ch, true) {
                return false;
            }
        }

        for ch in chars {
            if !inner_is_safe_ascii(*ch, false) {
                return false;
            }
        }

        true
    }

    /// Writes this label to safe ascii, escaping characters as necessary
    #[inline]
    fn write_ascii<W: Write>(&self, f: &mut W) -> Result<(), fmt::Error> {
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

    /// outputs characters in a safe string manner.
    ///
    /// if the string is punycode, i.e. starts with `xn--`, otherwise it translates to a safe ascii string
    ///   escaping characters as necessary.
    #[inline]
    fn write_utf8<W: Write>(&self, f: &mut W) -> Result<(), fmt::Error> {
        if self.as_bytes().starts_with(IDNA_PREFIX) {
            // this should never be outside the ascii codes...
            let label = String::from_utf8_lossy(self.as_bytes());
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

    /// Performs the conversion to utf8 from IDNA as necessary, see `fmt` for more details
    #[inline]
    fn to_utf8<'a>(&'a self) -> Cow<'a, str>
    where
        Self: Sized,
    {
        if !self.as_bytes().starts_with(IDNA_PREFIX) && self.is_safe_ascii() {
            return String::from_utf8_lossy(self.as_bytes());
        }

        let mut utf8 = String::with_capacity(self.as_bytes().len());

        self.write_utf8(&mut utf8)
            .expect("should never fail to write a new string");
        Cow::Owned(utf8)
    }

    /// Converts this label to safe ascii, escaping characters as necessary
    ///
    /// If this is an IDNA, punycode, label, then the xn-- prefix will be maintained as ascii
    #[inline]
    fn to_ascii<'a>(&'a self) -> Cow<'a, str>
    where
        Self: Sized,
    {
        if self.is_safe_ascii() {
            return String::from_utf8_lossy(self.as_bytes());
        }

        let mut ascii = String::with_capacity(self.as_bytes().len());

        self.write_ascii(&mut ascii)
            .expect("should never fail to write a new string");
        Cow::Owned(ascii)
    }
}

/// A label to a referred set of bytes
#[repr(transparent)]
pub struct LabelRef([u8]);

impl LabelRef {
    /// Returns a wildcard label
    #[inline]
    pub fn wildcard() -> &'static Self {
        Self::from_unchecked(WILDCARD)
    }

    /// Converts to an Owned Label
    #[inline]
    pub fn to_label(&self) -> Label {
        Label(self.0.to_vec())
    }

    #[inline]
    #[allow(unsafe_code)]
    pub(crate) fn from_unchecked<'a>(bytes: &'a [u8]) -> &'a Self {
        unsafe { std::mem::transmute(bytes) }
    }

    /// These must only be ASCII, with unicode encoded to PunyCode, or other such transformation.
    ///
    /// This uses the bytes as raw ascii values, with nothing escaped on the wire.
    /// Generally users should use `from_str` or `from_ascii`
    #[inline]
    pub fn from_raw_bytes(bytes: &[u8]) -> ProtoResult<&Self> {
        if bytes.len() > 63 {
            return Err(format!("Label exceeds maximum length 63: {}", bytes.len()).into());
        };
        Ok(LabelRef::from_unchecked(bytes))
    }

    /// Takes the ascii string and returns a new label.
    ///
    /// This will return an Error if the label is not an ascii string
    #[inline]
    pub fn from_ascii(s: &str) -> ProtoResult<&Self> {
        if s.as_bytes() == WILDCARD {
            return Ok(LabelRef::wildcard());
        }

        if !s.is_empty()
            && s.is_ascii()
            && s.chars().take(1).all(|c| is_safe_ascii(c, true, false))
            && s.chars().skip(1).all(|c| is_safe_ascii(c, false, false))
        {
            LabelRef::from_raw_bytes(s.as_bytes())
        } else {
            Err(format!("Malformed label: {}", s).into())
        }
    }

    /// Expose the Label as the raw bytes
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl DnsLabel for LabelRef {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> DnsLabel for &'a LabelRef {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Display for LabelRef {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        self.write_utf8(f)
    }
}

impl Debug for LabelRef {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        let label = String::from_utf8_lossy(self.borrow());
        f.write_str(&label)
    }
}

impl AsRef<[u8]> for LabelRef {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Borrow<[u8]> for LabelRef {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

#[allow(deprecated)]
impl<L: DnsLabel> PartialEq<L> for LabelRef {
    fn eq(&self, other: &L) -> bool {
        self.eq_ignore_ascii_case(other)
    }
}

#[allow(deprecated)]
impl PartialEq<LabelRef> for LabelRef {
    fn eq(&self, other: &LabelRef) -> bool {
        self.eq_ignore_ascii_case(other)
    }
}

impl Eq for LabelRef {}

/// Labels are always stored as ASCII, unicode characters must be encoded with punycode
#[derive(Clone, Eq)]
pub struct Label(Vec<u8>);

impl DnsLabel for Label {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[allow(deprecated)]
impl Label {
    /// These must only be ASCII, with unicode encoded to PunyCode, or other such transformation.
    ///
    /// This uses the bytes as raw ascii values, with nothing escaped on the wire.
    /// Generally users should use `from_str` or `from_ascii`
    pub fn from_raw_bytes(bytes: &[u8]) -> ProtoResult<Self> {
        if bytes.len() > 63 {
            return Err(format!("Label exceeds maximum length 63: {}", bytes.len()).into());
        };
        Ok(Label(bytes.to_vec()))
    }

    pub(super) fn parse_label_no_alloc(s: &str) -> ProtoResult<Cow<[u8]>> {
        match LabelRef::from_ascii(s) {
            // this returns the entire label, as it was validated as good
            Ok(_label) => return Ok(Cow::Borrowed(s.as_bytes())),
            Err(_) => (),
        }

        Ok(Cow::Owned(Label::from_utf8(s)?.to_vec()))
    }

    /// Translates this string into IDNA safe name, encoding to punycode as necessary.
    pub fn from_utf8(s: &str) -> ProtoResult<Self>
    where
        Self: Sized,
    {
        if s.as_bytes() == WILDCARD {
            return Ok(LabelRef::wildcard().to_label());
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
    pub fn from_ascii(s: &str) -> ProtoResult<Label> {
        if s.as_bytes() == WILDCARD {
            return Ok(LabelRef::wildcard().to_label());
        }

        if !s.is_empty()
            && s.is_ascii()
            && s.chars().take(1).all(|c| is_safe_ascii(c, true, false))
            && s.chars().skip(1).all(|c| is_safe_ascii(c, false, false))
        {
            Label::from_raw_bytes(s.as_bytes())
        } else {
            Err(format!("Malformed label: {}", s).into())
        }
    }

    /// Converts this label to lowercase, in place
    pub fn make_lowercase(&mut self) {
        self.0.make_ascii_lowercase();
    }

    /// Converts this label to ascii lowercase (i.e. non-ascii chars are left alone)
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
            Label(lower_label)
        } else {
            self.clone()
        }
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

    pub(super) fn to_vec(self) -> Vec<u8> {
        self.0
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

#[allow(deprecated)]
impl AsRef<[u8]> for Label {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[allow(deprecated)]
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

#[allow(deprecated)]
impl Display for Label {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        self.write_utf8(f)
    }
}

#[allow(deprecated)]
impl Debug for Label {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        let label = String::from_utf8_lossy(self.borrow());
        f.write_str(&label)
    }
}

#[allow(deprecated)]
impl<L: DnsLabel> PartialEq<L> for Label {
    fn eq(&self, other: &L) -> bool {
        self.eq_ignore_ascii_case(other)
    }
}

#[allow(deprecated)]
impl PartialOrd<Label> for Label {
    fn partial_cmp(&self, other: &Label) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[allow(deprecated)]
impl Ord for Label {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_with_f::<CaseInsensitive>(other)
    }
}

#[allow(deprecated)]
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
    fn into_label(self: Self) -> ProtoResult<Label>;
}

impl<'a> IntoLabel for &'a Label {
    fn into_label(self: Self) -> ProtoResult<Label> {
        Ok(self.clone())
    }
}

impl IntoLabel for Label {
    fn into_label(self: Self) -> ProtoResult<Label> {
        Ok(self)
    }
}

impl<'a> IntoLabel for &'a str {
    fn into_label(self: Self) -> ProtoResult<Label> {
        Label::from_utf8(self)
    }
}

impl IntoLabel for String {
    fn into_label(self: Self) -> ProtoResult<Label> {
        Label::from_utf8(&self)
    }
}

impl<'a> IntoLabel for &'a [u8] {
    fn into_label(self: Self) -> ProtoResult<Label> {
        Label::from_raw_bytes(self)
    }
}

impl IntoLabel for Vec<u8> {
    fn into_label(self: Self) -> ProtoResult<Label> {
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
            LabelRef::from_raw_bytes(b"abc").unwrap()
        );
        // case insensitive, this works...
        assert_eq!(
            Label::from_utf8("ABC").unwrap(),
            LabelRef::from_raw_bytes(b"ABC").unwrap()
        );
        assert_eq!(
            Label::from_utf8("🦀").unwrap(),
            LabelRef::from_raw_bytes(b"xn--zs9h").unwrap()
        );
        assert_eq!(
            Label::from_utf8("rust-🦀-icon").unwrap(),
            LabelRef::from_raw_bytes(b"xn--rust--icon-9447i").unwrap()
        );
        assert_eq!(
            Label::from_ascii("ben.fry").unwrap(),
            LabelRef::from_raw_bytes(b"ben.fry").unwrap()
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
