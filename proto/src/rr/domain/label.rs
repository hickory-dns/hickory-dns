//! Labels are used as the internal components of a Name.
//!
//! A label is stored internally as ascii, where all unicode characters are converted to punycode interenally.

#[allow(unused)]
use std::ascii::AsciiExt;
use std::cmp::{Ordering, PartialEq};
use std::borrow::Borrow;
use std::fmt::{self, Debug, Display, Formatter, Write};
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use std::sync::Arc as Rc;

use idna::uts46;

use error::*;

const WILDCARD: &[u8] = b"*";
const IDNA_PREFIX: &[u8] = b"xn--";

/// Labels are always stored as ASCII, unicode characters must be encoded with punycode
#[derive(Clone, Eq)]
pub struct Label(Rc<[u8]>);

impl Label {
    /// These must only be ASCII, with unicode encoded to PunyCode
    ///
    /// This uses the bytes as raw ascii values.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        Ok(Label(Rc::from(bytes)))
    }

    /// Converts this label to lowercase
    pub fn to_lowercase(&self) -> Self {
        // TODO: replace case conversion when (ascii_ctype #39658) stabilizes
        if let Some((idx, _)) = self.0.iter().enumerate().find(|&(_, c)| *c != c.to_ascii_lowercase()) {
            let mut lower_label: Vec<u8> = self.0.to_vec();
            lower_label[idx..].make_ascii_lowercase();
            Label(Rc::from(lower_label))
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

    /// Returns the raw bytes of the label, this is good for writing to the wire.
    ///
    /// See [`Display`] for presentation version (unescaped from punycode, etc)
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Performs the equivelence operation disregarding case
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
}

impl AsRef<[u8]> for Label {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Borrow<[u8]> for Label {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl FromStr for Label {
    type Err = ProtoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.as_bytes() == WILDCARD {
            return Ok(Label(Rc::from(WILDCARD.to_vec())))
        }

        // if it's all ascii, don't perform the unicode conversion
        if s.is_ascii() {
            return Label::from_bytes(s.as_bytes())
        }

        match uts46::to_ascii(s, uts46::Flags{
            use_std3_ascii_rules: true, 
            transitional_processing: true, 
            verify_dns_length: true}) {
            Ok(puny) => {
                Ok(Label(Rc::from(puny.as_bytes())))
            }
            Err(e) => {
                debug!("Label contains invalid characters, treating as binary: {:?}", e);
                Ok(Label(Rc::from(s.as_bytes())))
            }
        }
    }
}

fn escape_non_ascii(byte: u8, f: &mut Formatter, first: bool) -> Result<(), fmt::Error> {
    let to_escape = |ch: u8| format!("\\{:03}", ch); 

    match char::from(byte) {
        ch if !ch.is_ascii() => f.write_str(&to_escape(byte))?,
        ch if ch.is_alphabetic() => f.write_char(ch)?,
        ch if !first && ch.is_numeric() => f.write_char(ch)?,
        ch @ '-' if !first => f.write_char(ch)?,
        ch @ '_' if first => f.write_char(ch)?,
        _ => f.write_str(&to_escape(byte))?,
    }

    Ok(())
}

impl Display for Label {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        if self.as_bytes().starts_with(IDNA_PREFIX) {
            // this should never be outside the ascii codes...
            let label = String::from_utf8_lossy(self.borrow());
            let (label, e) = uts46::to_unicode(&label, uts46::Flags{
                use_std3_ascii_rules: false, 
                transitional_processing: false, 
                verify_dns_length: false});

            
            if e.is_ok() {
                return f.write_str(&label)
            } else {
                debug!("xn-- prefixed string did not translate via IDNA properly: {:?}", e)
            }
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

impl Debug for Label {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        let label = String::from_utf8_lossy(self.borrow());
        f.write_str(&label)
    }
}

impl PartialEq<Label> for Label {
    fn eq(&self, other: &Self) -> bool {
        self.eq_ignore_ascii_case(other)
    }
}

impl PartialOrd<Label> for Label {
    fn partial_cmp(&self, other: &Label) -> Option<Ordering> {
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
pub struct CaseSensitive;

impl LabelCmp for CaseSensitive {
    fn cmp_u8(l: u8, r: u8) -> Ordering {
        l.cmp(&r)
    }
}

/// For case insensitive comparisons
pub struct CaseInsensitive;

impl LabelCmp for CaseInsensitive {
    fn cmp_u8(l: u8, r: u8) -> Ordering {
        l.to_ascii_lowercase().cmp(&r.to_ascii_lowercase())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoding() {
        assert_eq!(Label::from_str("abc").unwrap(), Label::from_bytes(b"abc").unwrap());
        assert_eq!(Label::from_str("ABC").unwrap(), Label::from_bytes(b"ABC").unwrap());
        assert_eq!(Label::from_str("🦀").unwrap(), Label::from_bytes(b"xn--zs9h").unwrap());
        assert_eq!(Label::from_str("rust-🦀-icon").unwrap(), Label::from_bytes(b"xn--rust--icon-9447i").unwrap());
    }

    #[test]
    fn test_decoding() {
        assert_eq!(Label::from_bytes(b"abc").unwrap().to_string(), "abc");
        assert_eq!(Label::from_bytes(b"xn--zs9h").unwrap().to_string(), "🦀");
        assert_eq!(Label::from_bytes(b"xn--rust--icon-9447i").unwrap().to_string(), "rust-🦀-icon");
    }

    #[test]
    fn test_to_lowercase() {
        assert_ne!(Label::from_str("ABC").unwrap().to_string(), "abc");
        assert_ne!(Label::from_str("abcDEF").unwrap().to_string(), "abcdef");
        assert_eq!(Label::from_str("ABC").unwrap().to_lowercase().to_string(), "abc");
        assert_eq!(Label::from_str("abcDEF").unwrap().to_lowercase().to_string(), "abcdef");
    }

    #[test]
    fn test_to_cmp_f() {
        assert_eq!(Label::from_str("ABC").unwrap().cmp_with_f::<CaseInsensitive>(&Label::from_str("abc").unwrap()), Ordering::Equal);
        assert_eq!(Label::from_str("abcDEF").unwrap().cmp_with_f::<CaseInsensitive>(&Label::from_str("abcdef").unwrap()), Ordering::Equal);
        assert_eq!(Label::from_str("ABC").unwrap().cmp_with_f::<CaseSensitive>(&Label::from_str("abc").unwrap()), Ordering::Less);
        assert_eq!(Label::from_str("abcDEF").unwrap().cmp_with_f::<CaseSensitive>(&Label::from_str("abcdef").unwrap()), Ordering::Less);
    }

    #[test]
    fn test_partial_cmp() {
        let comparisons: Vec<(Label, Label)> = vec![
            (
                Label::from_bytes(b"yljkjljk").unwrap(),
                Label::from_bytes(b"Z").unwrap(),
            ),
            (
                Label::from_bytes(b"Z").unwrap(),
                Label::from_bytes(b"zABC").unwrap(),
            ),
            (
                Label::from_bytes(&[001]).unwrap(),
                Label::from_bytes(b"*").unwrap(),
            ),
            (
                Label::from_bytes(b"*").unwrap(),
                Label::from_bytes(&[200]).unwrap(),
            ),
        ];

        for (left, right) in comparisons {
            println!("left: {}, right: {}", left, right);
            assert_eq!(left.cmp(&right), Ordering::Less);
        }
    }

    #[test]
    fn test_is_wildcard() {
        assert!(Label::from_bytes(b"*").unwrap().is_wildcard());
        assert!(Label::from_str("*").unwrap().is_wildcard());
        assert!(!Label::from_str("abc").unwrap().is_wildcard());
    }

    #[test]
    fn test_ascii_escape() {
        assert_eq!(Label::from_bytes(&[200]).unwrap().to_string(), "\\200");
        assert_eq!(Label::from_bytes(&[001]).unwrap().to_string(), "\\001");
        assert_eq!(Label::from_bytes(&[200]).unwrap().to_string(), "\\200");
        assert_eq!(Label::from_bytes(&[001]).unwrap().to_string(), "\\001");
    }
}