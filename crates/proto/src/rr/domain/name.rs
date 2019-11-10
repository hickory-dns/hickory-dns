// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! domain name, aka labels, implementation

use std::borrow::Borrow;
use std::char;
use std::cmp::{Ordering, PartialEq};
use std::fmt::{self, Write};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Index;
use std::slice::Iter;
use std::str::FromStr;

use crate::error::*;
use crate::rr::domain::label::{CaseInsensitive, CaseSensitive, IntoLabel, Label, LabelCmp};
use crate::rr::domain::usage::LOCALHOST as LOCALHOST_usage;
use crate::serialize::binary::*;
#[cfg(feature = "serde-config")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// Them should be through references. As a workaround the Strings are all Rc as well as the array
#[derive(Clone, Default, Debug, Eq)]
pub struct Name {
    is_fqdn: bool,
    labels: Vec<Label>,
}

impl Name {
    /// Create a new domain::Name, i.e. label
    pub fn new() -> Self {
        Default::default()
    }

    /// Returns the root label, i.e. no labels, can probably make this better in the future.
    pub fn root() -> Self {
        let mut this = Self::new();
        this.is_fqdn = true;
        this
    }

    /// Returns true if there are no labels, i.e. it's empty.
    ///
    /// In DNS the root is represented by `.`
    ///
    /// # Examples
    ///
    /// ```
    /// use trust_dns_proto::rr::domain::Name;
    ///
    /// let root = Name::root();
    /// assert_eq!(&root.to_string(), ".");
    /// ```
    pub fn is_root(&self) -> bool {
        self.labels.is_empty() && self.is_fqdn()
    }

    /// Returns true if the name is a fully qualified domain name.
    ///
    /// If this is true, it has effects like only querying for this single name, as opposed to building
    ///  up a search list in resolvers.
    ///
    /// *warning: this interface is unstable and may change in the future*
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::domain::Name;
    ///
    /// let name = Name::from_str("www").unwrap();
    /// assert!(!name.is_fqdn());
    ///
    /// let name = Name::from_str("www.example.com").unwrap();
    /// assert!(!name.is_fqdn());
    ///
    /// let name = Name::from_str("www.example.com.").unwrap();
    /// assert!(name.is_fqdn());
    /// ```
    pub fn is_fqdn(&self) -> bool {
        self.is_fqdn
    }

    /// Specifies this name is a fully qualified domain name
    ///
    /// *warning: this interface is unstable and may change in the future*
    pub fn set_fqdn(&mut self, val: bool) {
        self.is_fqdn = val
    }

    /// Returns an iterator over the labels
    pub fn iter(&self) -> LabelIter {
        LabelIter(self.labels.iter())
    }

    /// Appends the label to the end of this name
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::domain::Name;
    ///
    /// let name = Name::from_str("www.example").unwrap();
    /// let name = name.append_label("com").unwrap();
    /// assert_eq!(name, Name::from_str("www.example.com").unwrap());
    /// ```
    pub fn append_label<L: IntoLabel>(mut self, label: L) -> ProtoResult<Self> {
        self.labels.push(label.into_label()?);
        if self.labels.len() > 255 {
            return Err("labels exceed maximum length of 255".into());
        };
        Ok(self)
    }

    /// Creates a new Name from the specified labels
    ///
    /// # Arguments
    ///
    /// * `labels` - vector of items which will be stored as Strings.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::domain::Name;
    ///
    /// // From strings, uses utf8 conversion
    /// let from_labels = Name::from_labels(vec!["www", "example", "com"]).unwrap();
    /// assert_eq!(from_labels, Name::from_str("www.example.com").unwrap());
    ///
    /// // Force a set of bytes into labels (this is none-standard and potentially dangerous)
    /// let from_labels = Name::from_labels(vec!["bad chars".as_bytes(), "example".as_bytes(), "com".as_bytes()]).unwrap();
    /// assert_eq!(from_labels[0].as_bytes(), "bad chars".as_bytes());
    ///
    /// let root = Name::from_labels(Vec::<&str>::new()).unwrap();
    /// assert!(root.is_root());
    /// ```
    pub fn from_labels<I, L>(labels: I) -> ProtoResult<Self>
    where
        I: IntoIterator<Item = L>,
        L: IntoLabel,
    {
        let (labels, errors): (Vec<_>, Vec<_>) = labels
            .into_iter()
            .map(IntoLabel::into_label)
            .partition(Result::is_ok);
        let labels: Vec<_> = labels.into_iter().map(Result::unwrap).collect();
        let errors: Vec<_> = errors.into_iter().map(Result::unwrap_err).collect();

        if labels.len() > 255 {
            return Err("labels exceed maximum length of 255".into());
        };
        if !errors.is_empty() {
            return Err(format!("error converting some labels: {:?}", errors).into());
        };

        Ok(Name {
            is_fqdn: true,
            labels,
        })
    }

    /// Appends `other` to `self`, returning a new `Name`
    ///
    /// Carries forward `is_fqdn` from `other`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::domain::Name;
    ///
    /// let local = Name::from_str("www").unwrap();
    /// let domain = Name::from_str("example.com").unwrap();
    /// assert!(!domain.is_fqdn());
    ///
    /// let name = local.clone().append_name(&domain);
    /// assert_eq!(name, Name::from_str("www.example.com").unwrap());
    /// assert!(!name.is_fqdn());
    ///
    /// // see also `Name::append_domain`
    /// let domain = Name::from_str("example.com.").unwrap();
    /// assert!(domain.is_fqdn());
    /// let name = local.append_name(&domain);
    /// assert_eq!(name, Name::from_str("www.example.com.").unwrap());
    /// assert!(name.is_fqdn());
    /// ```
    pub fn append_name(mut self, other: &Self) -> Self {
        self.labels.reserve_exact(other.labels.len());
        for label in &other.labels {
            self.labels.push(label.clone());
        }

        self.is_fqdn = other.is_fqdn;
        self
    }

    /// Appends the `domain` to `self`, making the new `Name` an FQDN
    ///
    /// This is an alias for `append_name` with the added effect of marking the new `Name` as
    /// a fully-qualified-domain-name.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::domain::Name;
    ///
    /// let local = Name::from_str("www").unwrap();
    /// let domain = Name::from_str("example.com").unwrap();
    /// let name = local.append_domain(&domain);
    /// assert_eq!(name, Name::from_str("www.example.com").unwrap());
    /// assert!(name.is_fqdn())
    /// ```
    pub fn append_domain(self, domain: &Self) -> Self {
        let mut this = self.append_name(domain);
        this.set_fqdn(true);
        this
    }

    /// Creates a new Name with all labels lowercased
    ///
    /// # Examples
    ///
    /// ```
    /// use std::cmp::Ordering;
    /// use std::str::FromStr;
    ///
    /// use trust_dns_proto::rr::domain::{Label, Name};
    ///
    /// let example_com = Name::from_ascii("Example.Com").unwrap();
    /// assert_eq!(example_com.cmp_case(&Name::from_str("example.com").unwrap()), Ordering::Less);
    /// assert!(example_com.to_lowercase().eq_case(&Name::from_str("example.com").unwrap()));
    /// ```
    pub fn to_lowercase(&self) -> Self {
        let mut new_labels: Vec<Label> = Vec::with_capacity(self.labels.len());
        for label in &self.labels {
            new_labels.push(label.to_lowercase())
        }

        Name {
            is_fqdn: self.is_fqdn,
            labels: new_labels,
        }
    }

    /// Trims off the first part of the name, to help with searching for the domain piece
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::domain::Name;
    ///
    /// let example_com = Name::from_str("example.com.").unwrap();
    /// assert_eq!(example_com.base_name(), Name::from_str("com.").unwrap());
    /// assert_eq!(Name::from_str("com.").unwrap().base_name(), Name::root());
    /// assert_eq!(Name::root().base_name(), Name::root());
    /// ```
    pub fn base_name(&self) -> Name {
        let length = self.labels.len();
        if length > 0 {
            return self.trim_to(length - 1);
        }
        self.clone()
    }

    /// Trims to the number of labels specified
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::domain::Name;
    ///
    /// let example_com = Name::from_str("example.com.").unwrap();
    /// assert_eq!(example_com.trim_to(2), Name::from_str("example.com.").unwrap());
    /// assert_eq!(example_com.trim_to(1), Name::from_str("com.").unwrap());
    /// assert_eq!(example_com.trim_to(0), Name::root());
    /// assert_eq!(example_com.trim_to(3), Name::from_str("example.com.").unwrap());
    /// ```
    pub fn trim_to(&self, num_labels: usize) -> Name {
        if self.labels.len() >= num_labels {
            let trim = self.labels.len() - num_labels;
            Name {
                is_fqdn: self.is_fqdn,
                labels: self.labels[trim..].to_vec(),
            }
        } else {
            self.clone()
        }
    }

    /// same as `zone_of` allows for case sensitive call
    pub fn zone_of_case(&self, name: &Self) -> bool {
        let self_len = self.labels.len();
        let name_len = name.labels.len();
        if self_len == 0 {
            return true;
        }
        if name_len == 0 {
            // self_len != 0
            return false;
        }
        if self_len > name_len {
            return false;
        }

        let self_iter = self.iter().rev();
        let name_iter = name.iter().rev();

        let zip_iter = self_iter.zip(name_iter);

        for (self_label, name_label) in zip_iter {
            if self_label != name_label {
                return false;
            }
        }

        true
    }

    /// returns true if the name components of self are all present at the end of name
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::domain::Name;
    ///
    /// let name = Name::from_str("www.example.com").unwrap();
    /// let name = Name::from_str("www.example.com").unwrap();
    /// let zone = Name::from_str("example.com").unwrap();
    /// let another = Name::from_str("example.net").unwrap();
    /// assert!(zone.zone_of(&name));
    /// assert!(!name.zone_of(&zone));
    /// assert!(!another.zone_of(&name));
    /// ```
    pub fn zone_of(&self, name: &Self) -> bool {
        let self_lower = self.to_lowercase();
        let name_lower = name.to_lowercase();

        self_lower.zone_of_case(&name_lower)
    }

    /// Returns the number of labels in the name, discounting `*`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::domain::Name;
    ///
    /// let root = Name::root();
    /// assert_eq!(root.num_labels(), 0);
    ///
    /// let example_com = Name::from_str("example.com").unwrap();
    /// assert_eq!(example_com.num_labels(), 2);
    ///
    /// let star_example_com = Name::from_str("*.example.com.").unwrap();
    /// assert_eq!(star_example_com.num_labels(), 2);
    /// ```
    pub fn num_labels(&self) -> u8 {
        // it is illegal to have more than 256 labels.

        let num = self.labels.len() as u8;

        self.labels
            .first()
            .map(|l| if l.is_wildcard() { num - 1 } else { num })
            .unwrap_or(num)
    }

    /// returns the length in bytes of the labels. '.' counts as 1
    ///
    /// This can be used as an estimate, when serializing labels, they will often be compressed
    /// and/or escaped causing the exact length to be different.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::domain::Name;
    ///
    /// assert_eq!(Name::from_str("www.example.com.").unwrap().len(), 16);
    /// assert_eq!(Name::from_str(".").unwrap().len(), 1);
    /// assert_eq!(Name::root().len(), 1);
    /// ```
    pub fn len(&self) -> usize {
        let dots = if !self.labels.is_empty() {
            self.labels.len()
        } else {
            1
        };
        self.labels.iter().fold(dots, |acc, item| acc + item.len())
    }

    /// Returns whether the length of the labels, in bytes is 0. In practice, since '.' counts as
    /// 1, this is never the case so the method returns false.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// attempts to parse a name such as `"example.com."` or `"subdomain.example.com."`
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::domain::Name;
    ///
    /// let name = Name::from_str("example.com.").unwrap();
    /// assert_eq!(name.base_name(), Name::from_str("com.").unwrap());
    /// assert_eq!(name[0].to_string(), "example");
    /// ```
    pub fn parse(local: &str, origin: Option<&Self>) -> ProtoResult<Self> {
        Self::from_encoded_str::<LabelEncUtf8>(local, origin)
    }

    /// Will convert the string to a name only allowing ascii as valid input
    ///
    /// This method will also preserve the case of the name where that's desirable
    ///
    /// # Examples
    ///
    /// ```
    /// use trust_dns_proto::rr::Name;
    ///
    /// let bytes_name = Name::from_labels(vec!["WWW".as_bytes(), "example".as_bytes(), "COM".as_bytes()]).unwrap();
    /// let ascii_name = Name::from_ascii("WWW.example.COM.").unwrap();
    /// let lower_name = Name::from_ascii("www.example.com.").unwrap();
    ///
    /// assert!(bytes_name.eq_case(&ascii_name));
    /// assert!(!lower_name.eq_case(&ascii_name));
    ///
    /// // escaped values
    /// let bytes_name = Name::from_labels(vec!["email.name".as_bytes(), "example".as_bytes(), "com".as_bytes()]).unwrap();
    /// let name = Name::from_ascii("email\\.name.example.com.").unwrap();
    ///
    /// assert_eq!(bytes_name, name);
    ///
    /// let bytes_name = Name::from_labels(vec!["bad.char".as_bytes(), "example".as_bytes(), "com".as_bytes()]).unwrap();
    /// let name = Name::from_ascii("bad\\056char.example.com.").unwrap();
    ///
    /// assert_eq!(bytes_name, name);
    /// ```
    pub fn from_ascii<S: AsRef<str>>(name: S) -> ProtoResult<Self> {
        Self::from_encoded_str::<LabelEncAscii>(name.as_ref(), None)
    }

    // TODO: currently reserved to be private to the crate, due to confusion of IDNA vs. utf8 in https://tools.ietf.org/html/rfc6762#appendix-F
    /// Will convert the string to a name using IDNA, punycode, to encode the UTF8 as necessary
    ///
    /// When making names IDNA compatible, there is a side-effect of lowercasing the name.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::Name;
    ///
    /// let bytes_name = Name::from_labels(vec!["WWW".as_bytes(), "example".as_bytes(), "COM".as_bytes()]).unwrap();
    ///
    /// // from_str calls through to from_utf8
    /// let utf8_name = Name::from_str("WWW.example.COM.").unwrap();
    /// let lower_name = Name::from_str("www.example.com.").unwrap();
    ///
    /// assert!(!bytes_name.eq_case(&utf8_name));
    /// assert!(lower_name.eq_case(&utf8_name));
    /// ```
    pub fn from_utf8<S: AsRef<str>>(name: S) -> ProtoResult<Self> {
        Self::from_encoded_str::<LabelEncUtf8>(name.as_ref(), None)
    }

    /// First attempts to decode via `from_utf8`, if that fails IDNA checks, than falls back to
    /// ascii decoding.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::Name;
    ///
    /// // Ok, underscore in the beginning of a name
    /// assert!(Name::from_utf8("_allows.example.com.").is_ok());
    ///
    /// // Error, underscore in the end
    /// assert!(Name::from_utf8("dis_allowed.example.com.").is_err());
    ///
    /// // Ok, relaxed mode
    /// assert!(Name::from_str_relaxed("allow_in_.example.com.").is_ok());
    /// ```
    pub fn from_str_relaxed<S: AsRef<str>>(name: S) -> ProtoResult<Self> {
        let name = name.as_ref();
        Self::from_utf8(name).or_else(|_| Self::from_ascii(name))
    }

    fn from_encoded_str<E: LabelEnc>(local: &str, origin: Option<&Self>) -> ProtoResult<Self> {
        let mut name = Name::new();
        let mut label = String::new();

        let mut state = ParseState::Label;

        // short circuit root parse
        if local == "." {
            name.set_fqdn(true);
            return Ok(name);
        }

        // TODO: it would be nice to relocate this to Label, but that is hard because the label boundary can only be detected after processing escapes...
        // evaluate all characters
        for ch in local.chars() {
            match state {
                ParseState::Label => match ch {
                    '.' => {
                        name.labels.push(E::to_label(&label)?);
                        label.clear();
                    }
                    '\\' => state = ParseState::Escape1,
                    ch if !ch.is_control() && !ch.is_whitespace() => label.push(ch),
                    _ => return Err(format!("unrecognized char: {}", ch).into()),
                },
                ParseState::Escape1 => {
                    if ch.is_numeric() {
                        state =
                            ParseState::Escape2(ch.to_digit(8).ok_or_else(|| {
                                ProtoError::from(format!("illegal char: {}", ch))
                            })?);
                    } else {
                        // it's a single escaped char
                        label.push(ch);
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
                        let new: char = char::from_u32(val)
                            .ok_or_else(|| ProtoError::from(format!("illegal char: {}", ch)))?;
                        label.push(new);
                        state = ParseState::Label;
                    } else {
                        return Err(format!("unrecognized char: {}", ch).into());
                    }
                }
            }
        }

        if !label.is_empty() {
            name.labels.push(E::to_label(&label)?);
        }

        if local.ends_with('.') {
            name.set_fqdn(true);
        } else if let Some(other) = origin {
            return Ok(name.append_domain(other));
        }

        Ok(name)
    }

    /// Emits the canonical version of the name to the encoder.
    ///
    /// In canonical form, there will be no pointers written to the encoder (i.e. no compression).
    pub fn emit_as_canonical(&self, encoder: &mut BinEncoder, canonical: bool) -> ProtoResult<()> {
        let buf_len = encoder.len(); // lazily assert the size is less than 255...
                                     // lookup the label in the BinEncoder
                                     // if it exists, write the Pointer
        let labels: &[Label] = &self.labels;

        // start index of each label
        let mut labels_written: Vec<usize> = Vec::with_capacity(labels.len());

        if canonical {
            for label in labels {
                encoder.emit_character_data(label)?;
            }
        } else {
            // we're going to write out each label, tracking the indexes of the start to each label
            //   then we'll look to see if we can remove them and recapture the capacity in the buffer...
            for label in labels {
                if label.len() > 63 {
                    return Err(ProtoErrorKind::LabelBytesTooLong(label.len()).into());
                }

                labels_written.push(encoder.offset());
                encoder.emit_character_data(label)?;
            }

            // we've written all the labels to the buf, the current offset is the end
            let last_index = encoder.offset();

            // now search for other labels already stored matching from the beginning label, strip then to the end
            //   if it's not found, then store this as a new label
            for label_idx in &labels_written {
                let label_ptr: Option<u16> = encoder.get_label_pointer(*label_idx, last_index);

                // before we write the label, let's look for the current set of labels.
                if let Some(loc) = label_ptr {
                    // reset back to the beginning of this label, and then write the pointer...
                    encoder.set_offset(*label_idx);
                    encoder.trim();

                    // write out the pointer marker
                    //  or'd with the location which shouldn't be larger than this 2^14 or 16k
                    encoder.emit_u16(0xC000u16 | (loc & 0x3FFFu16))?;

                    // we found a pointer don't write more, break
                    return Ok(());
                } else {
                    // no existing label exists, store this new one.
                    encoder.store_label_pointer(*label_idx, last_index);
                }
            }
        }

        // if we're getting here, then we didn't write out a pointer and are ending the name
        // the end of the list of names
        encoder.emit(0)?;

        // the entire name needs to be less than 256.
        let length = encoder.len() - buf_len;
        if length > 255 {
            return Err(ProtoErrorKind::DomainNameTooLong(length).into());
        }

        Ok(())
    }

    /// Writes the labels, as lower case, to the encoder
    ///
    /// # Arguments
    ///
    /// * `encoder` - encoder for writing this name
    /// * `lowercase` - if true the name will be lowercased, otherwise it will not be changed when writing
    pub fn emit_with_lowercase(
        &self,
        encoder: &mut BinEncoder,
        lowercase: bool,
    ) -> ProtoResult<()> {
        let is_canonical_names = encoder.is_canonical_names();
        if lowercase {
            self.to_lowercase()
                .emit_as_canonical(encoder, is_canonical_names)
        } else {
            self.emit_as_canonical(encoder, is_canonical_names)
        }
    }

    /// compares with the other label, ignoring case
    fn cmp_with_f<F: LabelCmp>(&self, other: &Self) -> Ordering {
        if self.labels.is_empty() && other.labels.is_empty() {
            return Ordering::Equal;
        }

        // we reverse the iters so that we are comparing from the root/domain to the local...
        let self_labels = self.labels.iter().rev();
        let other_labels = other.labels.iter().rev();

        for (l, r) in self_labels.zip(other_labels) {
            match l.cmp_with_f::<F>(r) {
                Ordering::Equal => continue,
                not_eq => return not_eq,
            }
        }

        self.labels.len().cmp(&other.labels.len())
    }

    /// Case sensitive comparison
    pub fn cmp_case(&self, other: &Self) -> Ordering {
        self.cmp_with_f::<CaseSensitive>(other)
    }

    /// Compares the Names, in a case sensitive manner
    pub fn eq_case(&self, other: &Self) -> bool {
        self.cmp_with_f::<CaseSensitive>(other) == Ordering::Equal
    }

    /// Converts this name into an ascii safe string.
    ///
    /// If the name is an IDNA name, then the name labels will be returned with the `xn--` prefix.
    ///  see `to_utf8` or the `Display` impl for methods which convert labels to utf8.
    pub fn to_ascii(&self) -> String {
        let mut s = String::with_capacity(self.len());
        self.write_labels::<String, LabelEncAscii>(&mut s)
            .expect("string conversion of name should not fail");
        s
    }

    /// Converts the Name labels to the utf8 String form.
    ///
    /// This converts the name to an unescaped format, that could be used with parse. If, the name is
    ///  is followed by the final `.`, e.g. as in `www.example.com.`, which represents a fully
    ///  qualified Name.
    pub fn to_utf8(&self) -> String {
        format!("{}", self)
    }

    fn write_labels<W: Write, E: LabelEnc>(&self, f: &mut W) -> Result<(), fmt::Error> {
        let mut iter = self.labels.iter();
        if let Some(label) = iter.next() {
            E::write_label(f, label)?;
        }

        for label in iter {
            write!(f, ".")?;
            E::write_label(f, label)?;
        }

        // if it was the root name
        if self.is_root() || self.is_fqdn() {
            write!(f, ".")?;
        }
        Ok(())
    }

    /// Returns true if the `Name` is either localhost or in the localhost zone.
    ///
    /// # Example
    ///
    /// ```
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::Name;
    ///
    /// let name = Name::from_str("localhost").unwrap();
    /// assert!(name.is_localhost());
    ///
    /// let name = Name::from_str("localhost.").unwrap();
    /// assert!(name.is_localhost());
    ///
    /// let name = Name::from_str("my.localhost.").unwrap();
    /// assert!(name.is_localhost());
    /// ```
    pub fn is_localhost(&self) -> bool {
        LOCALHOST_usage.zone_of(self)
    }

    /// True if the first label of this name is the wildcard, i.e. '*'
    ///
    /// # Example
    ///
    /// ```
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::Name;
    ///
    /// let name = Name::from_str("www.example.com").unwrap();
    /// assert!(!name.is_wildcard());
    ///
    /// let name = Name::from_str("*.example.com").unwrap();
    /// assert!(name.is_wildcard());
    ///
    /// let name = Name::root();
    /// assert!(!name.is_wildcard());
    /// ```
    pub fn is_wildcard(&self) -> bool {
        self.labels.first().map_or(false, Label::is_wildcard)
    }

    /// Converts a name to a wildcard, by replacing the first label with `*`
    ///
    /// # Example
    ///
    /// ```
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::Name;
    ///
    /// let name = Name::from_str("www.example.com").unwrap().into_wildcard();
    /// assert_eq!(name, Name::from_str("*.example.com.").unwrap());
    ///
    /// // does nothing if the root
    /// let name = Name::root().into_wildcard();
    /// assert_eq!(name, Name::root());
    /// ```
    pub fn into_wildcard(mut self) -> Self {
        let wildcard = Label::wildcard();
        if let Some(first) = self.labels.first_mut() {
            *first = wildcard;
        }

        self
    }
}

trait LabelEnc {
    fn to_label(name: &str) -> ProtoResult<Label>;
    fn write_label<W: Write>(f: &mut W, label: &Label) -> Result<(), fmt::Error>;
}

struct LabelEncAscii;
impl LabelEnc for LabelEncAscii {
    fn to_label(name: &str) -> ProtoResult<Label> {
        Label::from_ascii(name)
    }

    fn write_label<W: Write>(f: &mut W, label: &Label) -> Result<(), fmt::Error> {
        label.write_ascii(f)
    }
}

struct LabelEncUtf8;
impl LabelEnc for LabelEncUtf8 {
    fn to_label(name: &str) -> ProtoResult<Label> {
        Label::from_utf8(name)
    }

    fn write_label<W: Write>(f: &mut W, label: &Label) -> Result<(), fmt::Error> {
        write!(f, "{}", label)
    }
}

/// An iterator over labels in a name
pub struct LabelIter<'a>(Iter<'a, Label>);

impl<'a> Iterator for LabelIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(Borrow::borrow)
    }
}

impl<'a> ExactSizeIterator for LabelIter<'a> {}
impl<'a> DoubleEndedIterator for LabelIter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back().map(Borrow::borrow)
    }
}

impl<'a> IntoIterator for &'a Name {
    type Item = &'a [u8];
    type IntoIter = LabelIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl From<IpAddr> for Name {
    fn from(addr: IpAddr) -> Name {
        match addr {
            IpAddr::V4(ip) => ip.into(),
            IpAddr::V6(ip) => ip.into(),
        }
    }
}

impl From<Ipv4Addr> for Name {
    fn from(addr: Ipv4Addr) -> Name {
        let octets = addr.octets();

        let mut labels =
            octets
                .iter()
                .rev()
                .fold(Vec::<Label>::with_capacity(6), |mut labels, o| {
                    let label: Label = format!("{}", o)
                        .as_bytes()
                        .into_label()
                        .expect("IP octet to label should never fail");
                    labels.push(label);
                    labels
                });

        labels.push(
            b"in-addr"
                .into_label()
                .expect("simple name should never fail"),
        );
        labels.push(b"arpa".into_label().expect("simple name should never fail"));

        Self::from_labels(labels).expect("a translation of Ipv4Addr should never fail")
    }
}

impl From<Ipv6Addr> for Name {
    fn from(addr: Ipv6Addr) -> Name {
        let segments = addr.segments();

        let mut labels =
            segments
                .iter()
                .rev()
                .fold(Vec::<Label>::with_capacity(34), |mut labels, o| {
                    labels.push(
                        format!("{:x}", (*o & 0x000F) as u8)
                            .as_bytes()
                            .into_label()
                            .expect("IP octet to label should never fail"),
                    );
                    labels.push(
                        format!("{:x}", (*o >> 4 & 0x000F) as u8)
                            .as_bytes()
                            .into_label()
                            .expect("IP octet to label should never fail"),
                    );
                    labels.push(
                        format!("{:x}", (*o >> 8 & 0x000F) as u8)
                            .as_bytes()
                            .into_label()
                            .expect("IP octet to label should never fail"),
                    );
                    labels.push(
                        format!("{:x}", (*o >> 12 & 0x000F) as u8)
                            .as_bytes()
                            .into_label()
                            .expect("IP octet to label should never fail"),
                    );
                    labels
                });

        labels.push(b"ip6".into_label().expect("simple name should never fail"));
        labels.push(b"arpa".into_label().expect("simple name should never fail"));

        Self::from_labels(labels).expect("a translation of Ipv6Addr should never fail")
    }
}

impl PartialEq<Name> for Name {
    fn eq(&self, other: &Self) -> bool {
        self.cmp_with_f::<CaseInsensitive>(other) == Ordering::Equal
    }
}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.is_fqdn.hash(state);

        // this needs to be CaseInsensitive like PartialEq
        for l in self.labels.iter().map(Label::to_lowercase) {
            l.hash(state);
        }
    }
}

enum ParseState {
    Label,
    Escape1,
    Escape2(u32),
    Escape3(u32, u32),
}

impl BinEncodable for Name {
    fn emit(&self, encoder: &mut BinEncoder) -> ProtoResult<()> {
        let is_canonical_names = encoder.is_canonical_names();
        self.emit_as_canonical(encoder, is_canonical_names)
    }
}

impl<'r> BinDecodable<'r> for Name {
    /// parses the chain of labels
    ///  this has a max of 255 octets, with each label being less than 63.
    ///  all names will be stored lowercase internally.
    /// This will consume the portions of the `Vec` which it is reading...
    fn read(decoder: &mut BinDecoder<'r>) -> ProtoResult<Name> {
        read_inner(decoder, None)
    }
}

fn read_inner<'r>(decoder: &mut BinDecoder<'r>, max_idx: Option<usize>) -> ProtoResult<Name> {
    let mut state: LabelParseState = LabelParseState::LabelLengthOrPointer;
    let mut labels: Vec<Label> = Vec::with_capacity(3); // most labels will be around three, e.g. www.example.com
    let name_start = decoder.index();
    let mut run_len = 0_usize;

    // assume all chars are utf-8. We're doing byte-by-byte operations, no endianess issues...
    // reserved: (1000 0000 aka 0800) && (0100 0000 aka 0400)
    // pointer: (slice == 1100 0000 aka C0) & C0 == true, then 03FF & slice = offset
    // label: 03FF & slice = length; slice.next(length) = label
    // root: 0000
    loop {
        // this protects against overlapping labels
        if let Some(max_idx) = max_idx {
            if decoder.index() >= max_idx {
                return Err(ProtoErrorKind::LabelOverlapsWithOther {
                    label: name_start,
                    other: max_idx,
                }
                .into());
            }
        }

        // enforce max length of name
        let cur_len = run_len + labels.len();
        if cur_len > 255 {
            return Err(ProtoErrorKind::DomainNameTooLong(cur_len).into());
        }

        state = match state {
            LabelParseState::LabelLengthOrPointer => {
                // determine what the next label is
                match decoder
                    .peek()
                    .map(Restrict::unverified /*verified in this usage*/)
                {
                    Some(0) | None => LabelParseState::Root,
                    Some(byte) if byte & 0b1100_0000 == 0b1100_0000 => LabelParseState::Pointer,
                    Some(byte) if byte & 0b1100_0000 == 0b0000_0000 => LabelParseState::Label,
                    Some(byte) => return Err(ProtoErrorKind::UnrecognizedLabelCode(byte).into()),
                }
            }
            // labels must have a maximum length of 63
            LabelParseState::Label => {
                let label = decoder
                    .read_character_data_max(Some(63))?
                    .verify_unwrap(|l| l.len() <= 63)
                    .map_err(|_| ProtoError::from("label exceeds maximum length of 63"))?;

                run_len += label.len();
                labels.push(label.into_label()?);

                // reset to collect more data
                LabelParseState::LabelLengthOrPointer
            }
            //         4.1.4. Message compression
            //
            // In order to reduce the size of messages, the domain system utilizes a
            // compression scheme which eliminates the repetition of domain names in a
            // message.  In this scheme, an entire domain name or a list of labels at
            // the end of a domain name is replaced with a pointer to a prior occurrence
            // of the same name.
            //
            // The pointer takes the form of a two octet sequence:
            //
            //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            //     | 1  1|                OFFSET                   |
            //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            //
            // The first two bits are ones.  This allows a pointer to be distinguished
            // from a label, since the label must begin with two zero bits because
            // labels are restricted to 63 octets or less.  (The 10 and 01 combinations
            // are reserved for future use.)  The OFFSET field specifies an offset from
            // the start of the message (i.e., the first octet of the ID field in the
            // domain header).  A zero offset specifies the first byte of the ID field,
            // etc.
            LabelParseState::Pointer => {
                let pointer_location = decoder.index();
                let location = decoder
                    .read_u16()?
                    .map(|u| {
                        // get rid of the two high order bits, they are markers for length or pointers
                        u & 0x3FFF
                    })
                    .verify_unwrap(|ptr| {
                        // all labels must appear "prior" to this Name
                        (*ptr as usize) < name_start
                    })
                    .map_err(|e| {
                        ProtoError::from(ProtoErrorKind::PointerNotPriorToLabel {
                            idx: pointer_location,
                            ptr: e,
                        })
                    })?;

                let mut pointer = decoder.clone(location);
                let pointed = read_inner(&mut pointer, Some(name_start))?;

                for l in &*pointed.labels {
                    if !l.is_empty() {
                        run_len += l.len();
                    }
                    labels.push(l.clone());
                }

                // Pointers always finish the name, break like Root.
                break;
            }
            LabelParseState::Root => {
                // need to pop() the 0 off the stack...
                decoder.pop()?;
                break;
            }
        }
    }

    run_len += if labels.is_empty() { 1 } else { labels.len() };
    let name = Name {
        is_fqdn: true,
        labels,
    };

    debug_assert_eq!(run_len, name.len());

    Ok(name)
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.write_labels::<fmt::Formatter, LabelEncUtf8>(f)
    }
}

impl Index<usize> for Name {
    type Output = Label;

    fn index(&self, _index: usize) -> &Label {
        &self.labels[_index]
    }
}

impl PartialOrd<Name> for Name {
    fn partial_cmp(&self, other: &Name) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Name {
    /// Case insensitive comparison, see [`Name::cmp_case`] for case sensitive comparisons
    ///
    /// RFC 4034                DNSSEC Resource Records               March 2005
    ///
    /// ```text
    /// 6.1.  Canonical DNS Name Order
    ///
    ///  For the purposes of DNS security, owner names are ordered by treating
    ///  individual labels as unsigned left-justified octet strings.  The
    ///  absence of a octet sorts before a zero value octet, and uppercase
    ///  US-ASCII letters are treated as if they were lowercase US-ASCII
    ///  letters.
    ///
    ///  To compute the canonical ordering of a set of DNS names, start by
    ///  sorting the names according to their most significant (rightmost)
    ///  labels.  For names in which the most significant label is identical,
    ///  continue sorting according to their next most significant label, and
    ///  so forth.
    ///
    ///  For example, the following names are sorted in canonical DNS name
    ///  order.  The most significant label is "example".  At this level,
    ///  "example" sorts first, followed by names ending in "a.example", then
    ///  by names ending "z.example".  The names within each level are sorted
    ///  in the same way.
    ///
    ///            example
    ///            a.example
    ///            yljkjljk.a.example
    ///            Z.a.example
    ///            zABC.a.EXAMPLE
    ///            z.example
    ///            \001.z.example
    ///            *.z.example
    ///            \200.z.example
    /// ```
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_with_f::<CaseInsensitive>(other)
    }
}

/// This is the list of states for the label parsing state machine
enum LabelParseState {
    LabelLengthOrPointer, // basically the start of the FSM
    Label,                // storing length of the label, must be < 63
    Pointer,              // location of pointer in slice,
    Root,                 // root is the end of the labels list, aka null
}

impl FromStr for Name {
    type Err = ProtoError;

    /// Uses the Name::from_utf8 conversion on this string, see [`from_ascii`] for ascii only, or for preserving case
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Name::from_str_relaxed(s)
    }
}

/// Conversion into a Name
pub trait IntoName: Sized {
    /// Convert this into Name
    fn into_name(self) -> ProtoResult<Name>;
}

impl<'a> IntoName for &'a str {
    /// Performs a utf8, IDNA or punycode, translation of the `str` into `Name`
    fn into_name(self) -> ProtoResult<Name> {
        Name::from_utf8(self)
    }
}

impl IntoName for String {
    /// Performs a utf8, IDNA or punycode, translation of the `String` into `Name`
    fn into_name(self) -> ProtoResult<Name> {
        Name::from_utf8(self)
    }
}

impl<T> IntoName for T
where
    T: Into<Name>,
{
    fn into_name(self) -> ProtoResult<Name> {
        Ok(self.into())
    }
}

#[cfg(feature = "serde-config")]
impl Serialize for Name {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde-config")]
impl<'de> Deserialize<'de> for Name {
    fn deserialize<D>(deserializer: D) -> Result<Name, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use std::cmp::Ordering;
    use std::str::FromStr;

    use super::*;

    use crate::serialize::binary::bin_tests::{test_emit_data_set, test_read_data_set};
    #[allow(clippy::useless_attribute)]
    #[allow(unused)]
    use crate::serialize::binary::*;

    fn get_data() -> Vec<(Name, Vec<u8>)> {
        vec![
            (Name::new(), vec![0]),                           // base case, only the root
            (Name::from_str("a").unwrap(), vec![1, b'a', 0]), // a single 'a' label
            (
                Name::from_str("a.bc").unwrap(),
                vec![1, b'a', 2, b'b', b'c', 0],
            ), // two labels, 'a.bc'
            (
                Name::from_str("a.♥").unwrap(),
                vec![1, b'a', 7, b'x', b'n', b'-', b'-', b'g', b'6', b'h', 0],
            ), // two labels utf8, 'a.♥'
        ]
    }

    #[test]
    fn test_num_labels() {
        assert_eq!(Name::from_str("*").unwrap().num_labels(), 0);
        assert_eq!(Name::from_str("a").unwrap().num_labels(), 1);
        assert_eq!(Name::from_str("*.b").unwrap().num_labels(), 1);
        assert_eq!(Name::from_str("a.b").unwrap().num_labels(), 2);
        assert_eq!(Name::from_str("*.b.c").unwrap().num_labels(), 2);
        assert_eq!(Name::from_str("a.b.c").unwrap().num_labels(), 3);
    }

    #[test]
    fn test_read() {
        test_read_data_set(get_data(), |ref mut d| Name::read(d));
    }

    #[test]
    fn test_write_to() {
        test_emit_data_set(get_data(), |e, n| n.emit(e));
    }

    #[test]
    fn test_pointer() {
        let mut bytes: Vec<u8> = Vec::with_capacity(512);

        let first = Name::from_str("ra.rb.rc").unwrap();
        let second = Name::from_str("rb.rc").unwrap();
        let third = Name::from_str("rc").unwrap();
        let fourth = Name::from_str("z.ra.rb.rc").unwrap();

        {
            let mut e = BinEncoder::new(&mut bytes);

            first.emit(&mut e).unwrap();
            assert_eq!(e.len(), 10); // should be 7 u8s...

            second.emit(&mut e).unwrap();
            // if this wrote the entire thing, then it would be +5... but a pointer should be +2
            assert_eq!(e.len(), 12);

            third.emit(&mut e).unwrap();
            assert_eq!(e.len(), 14);

            fourth.emit(&mut e).unwrap();
            assert_eq!(e.len(), 18);
        }

        // now read them back
        let mut d = BinDecoder::new(&bytes);

        let r_test = Name::read(&mut d).unwrap();
        assert_eq!(first, r_test);

        let r_test = Name::read(&mut d).unwrap();
        assert_eq!(second, r_test);

        let r_test = Name::read(&mut d).unwrap();
        assert_eq!(third, r_test);

        let r_test = Name::read(&mut d).unwrap();
        assert_eq!(fourth, r_test);
    }

    #[test]
    fn test_recursive_pointer() {
        // points to an invalid beginning label marker
        let bytes = vec![0xC0, 0x01];
        let mut d = BinDecoder::new(&bytes);

        assert!(Name::read(&mut d).is_err());

        // formerly a stack overflow, recursing back on itself
        let bytes = vec![0xC0, 0x00];
        let mut d = BinDecoder::new(&bytes);

        assert!(Name::read(&mut d).is_err());

        // formerly a stack overflow, recursing back on itself
        let bytes = vec![0x01, 0x41, 0xC0, 0x00];
        let mut d = BinDecoder::new(&bytes);

        assert!(Name::read(&mut d).is_err());

        // formerly a stack overflow, recursing by going past the end, then back to the beginning.
        //   this is disallowed based on the rule that all labels must be "prior" to the current label.
        let bytes = vec![0xC0, 0x02, 0xC0, 0x00];
        let mut d = BinDecoder::new(&bytes);

        assert!(Name::read(&mut d).is_err());
    }

    #[test]
    fn test_bin_overlap_enforced() {
        let mut bytes = Vec::with_capacity(512);
        let n = 31;
        for _ in 0..=5 {
            for _ in 0..=n {
                bytes.push(n);
            }
        }
        bytes.push(n + 1);
        for b in 0..n {
            bytes.push(1 + n + b);
        }
        bytes.extend_from_slice(&[1, 0]);
        for b in 0..n {
            bytes.extend_from_slice(&[0xC0, b]);
        }
        let mut d = BinDecoder::new(&bytes);
        d.read_slice(n as usize).unwrap();
        assert!(Name::read(&mut d).is_err());
    }

    #[test]
    fn test_bin_max_octets() {
        let mut bytes = Vec::with_capacity(512);
        for _ in 0..256 {
            bytes.extend_from_slice(&[1, b'a']);
        }
        bytes.push(0);

        let mut d = BinDecoder::new(&bytes);
        assert!(Name::read(&mut d).is_err());
    }

    #[test]
    fn test_base_name() {
        let zone = Name::from_str("example.com.").unwrap();

        assert_eq!(zone.base_name(), Name::from_str("com").unwrap());
        assert!(zone.base_name().base_name().is_root());
        assert!(zone.base_name().base_name().base_name().is_root());
    }

    #[test]
    fn test_zone_of() {
        let zone = Name::from_str("example.com").unwrap();
        let www = Name::from_str("www.example.com").unwrap();
        let none = Name::from_str("none.com").unwrap();
        let root = Name::root();

        assert!(zone.zone_of(&zone));
        assert!(zone.zone_of(&www));
        assert!(!zone.zone_of(&none));
        assert!(root.zone_of(&zone));
        assert!(!zone.zone_of(&root));
    }

    #[test]
    fn test_zone_of_case() {
        let zone = Name::from_ascii("examplE.cOm").unwrap();
        let www = Name::from_str("www.example.com").unwrap();
        let none = Name::from_str("none.com").unwrap();

        assert!(zone.zone_of(&zone));
        assert!(zone.zone_of(&www));
        assert!(!zone.zone_of(&none))
    }

    #[test]
    fn test_partial_cmp_eq() {
        let root = Some(Name::from_labels(Vec::<&str>::new()).unwrap());
        let comparisons: Vec<(Name, Name)> = vec![
            (root.clone().unwrap(), root.clone().unwrap()),
            (
                Name::parse("example.", root.as_ref()).unwrap(),
                Name::parse("example", root.as_ref()).unwrap(),
            ),
        ];

        for (left, right) in comparisons {
            println!("left: {}, right: {}", left, right);
            assert_eq!(left.partial_cmp(&right), Some(Ordering::Equal));
        }
    }

    #[test]
    fn test_partial_cmp() {
        let comparisons: Vec<(Name, Name)> = vec![
            (
                Name::from_str("example.").unwrap(),
                Name::from_str("a.example.").unwrap(),
            ),
            (
                Name::from_str("a.example.").unwrap(),
                Name::from_str("yljkjljk.a.example.").unwrap(),
            ),
            (
                Name::from_str("yljkjljk.a.example.").unwrap(),
                Name::from_ascii("Z.a.example.").unwrap(),
            ),
            (
                Name::from_ascii("Z.a.example.").unwrap(),
                Name::from_ascii("zABC.a.EXAMPLE").unwrap(),
            ),
            (
                Name::from_ascii("zABC.a.EXAMPLE.").unwrap(),
                Name::from_str("z.example.").unwrap(),
            ),
            (
                Name::from_str("z.example.").unwrap(),
                Name::from_labels(vec![&[1u8] as &[u8], b"z", b"example"]).unwrap(),
            ),
            (
                Name::from_labels(vec![&[1u8] as &[u8], b"z", b"example"]).unwrap(),
                Name::from_str("*.z.example.").unwrap(),
            ),
            (
                Name::from_str("*.z.example.").unwrap(),
                Name::from_labels(vec![&[200u8] as &[u8], b"z", b"example"]).unwrap(),
            ),
        ];

        for (left, right) in comparisons {
            println!("left: {}, right: {}", left, right);
            assert_eq!(left.cmp(&right), Ordering::Less);
        }
    }

    #[test]
    fn test_cmp_ignore_case() {
        let comparisons: Vec<(Name, Name)> = vec![
            (
                Name::from_ascii("ExAmPle.").unwrap(),
                Name::from_ascii("example.").unwrap(),
            ),
            (
                Name::from_ascii("A.example.").unwrap(),
                Name::from_ascii("a.example.").unwrap(),
            ),
        ];

        for (left, right) in comparisons {
            println!("left: {}, right: {}", left, right);
            assert_eq!(left, right);
        }
    }

    #[test]
    fn test_from_ipv4() {
        let ip = IpAddr::V4(Ipv4Addr::new(26, 3, 0, 103));
        let name = Name::from_str("103.0.3.26.in-addr.arpa").unwrap();

        assert_eq!(Into::<Name>::into(ip), name);
    }

    #[test]
    fn test_from_ipv6() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1));
        let name = Name::from_str(
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
        )
        .unwrap();

        assert_eq!(Into::<Name>::into(ip), name);
    }

    #[test]
    fn test_from_str() {
        assert_eq!(
            Name::from_str("www.example.com.").unwrap(),
            Name::from_labels(vec![b"www" as &[u8], b"example", b"com"]).unwrap()
        );
        assert_eq!(
            Name::from_str(".").unwrap(),
            Name::from_labels(Vec::<&str>::new()).unwrap()
        );
    }

    #[test]
    fn test_fqdn() {
        assert!(Name::root().is_fqdn());
        assert!(Name::from_str(".").unwrap().is_fqdn());
        assert!(Name::from_str("www.example.com.").unwrap().is_fqdn());
        assert!(Name::from_labels(vec![b"www" as &[u8], b"example", b"com"])
            .unwrap()
            .is_fqdn());

        assert!(!Name::new().is_fqdn());
        assert!(!Name::from_str("www.example.com").unwrap().is_fqdn());
        assert!(!Name::from_str("www.example").unwrap().is_fqdn());
        assert!(!Name::from_str("www").unwrap().is_fqdn());
    }

    #[test]
    fn test_to_string() {
        assert_eq!(
            Name::from_str("www.example.com.").unwrap().to_string(),
            "www.example.com."
        );
        assert_eq!(
            Name::from_str("www.example.com").unwrap().to_string(),
            "www.example.com"
        );
    }

    #[test]
    fn test_from_ascii() {
        let bytes_name = Name::from_labels(vec![b"WWW" as &[u8], b"example", b"COM"]).unwrap();
        let ascii_name = Name::from_ascii("WWW.example.COM.").unwrap();
        let lower_name = Name::from_ascii("www.example.com.").unwrap();

        assert!(bytes_name.eq_case(&ascii_name));
        assert!(!lower_name.eq_case(&ascii_name));
    }

    #[test]
    fn test_from_utf8() {
        let bytes_name = Name::from_labels(vec![b"WWW" as &[u8], b"example", b"COM"]).unwrap();
        let utf8_name = Name::from_utf8("WWW.example.COM.").unwrap();
        let lower_name = Name::from_utf8("www.example.com.").unwrap();

        assert!(!bytes_name.eq_case(&utf8_name));
        assert!(lower_name.eq_case(&utf8_name));
    }

    #[test]
    fn test_into_name() {
        let name = Name::from_utf8("www.example.com").unwrap();
        assert_eq!(Name::from_utf8("www.example.com").unwrap(), name);
        assert_eq!(
            Name::from_utf8("www.example.com").unwrap(),
            Name::from_utf8("www.example.com")
                .unwrap()
                .into_name()
                .unwrap()
        );
        assert_eq!(
            Name::from_utf8("www.example.com").unwrap(),
            "www.example.com".into_name().unwrap()
        );
        assert_eq!(
            Name::from_utf8("www.example.com").unwrap(),
            "www.example.com".to_string().into_name().unwrap()
        );
    }

    #[test]
    fn test_encoding() {
        assert_eq!(
            Name::from_ascii("WWW.example.COM.").unwrap().to_ascii(),
            "WWW.example.COM."
        );
        assert_eq!(
            Name::from_utf8("WWW.example.COM.").unwrap().to_ascii(),
            "www.example.com."
        );
        assert_eq!(
            Name::from_ascii("WWW.example.COM.").unwrap().to_utf8(),
            "WWW.example.COM."
        );
    }

    #[test]
    fn test_excessive_encoding_len() {
        use crate::error::ProtoErrorKind;

        // u16 max value is where issues start being tickled...
        let mut buf = Vec::with_capacity(u16::max_value() as usize);
        let mut encoder = BinEncoder::new(&mut buf);

        let mut result = Ok(());
        for i in 0..10000 {
            let name = Name::from_ascii(format!("name{}.example.com.", i)).unwrap();
            result = name.emit(&mut encoder);
            if let Err(..) = result {
                break;
            }
        }

        assert!(result.is_err());
        match *result.unwrap_err().kind() {
            ProtoErrorKind::MaxBufferSizeExceeded(_) => (),
            _ => panic!(),
        }
    }

    #[test]
    fn test_underscore() {
        Name::from_str("_begin.example.com").expect("failed at beginning");
        Name::from_str_relaxed("mid_dle.example.com").expect("failed in the middle");
        Name::from_str_relaxed("end_.example.com").expect("failed at the end");
    }
}
