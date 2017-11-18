/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! domain name, aka labels, implementaton

use std::char;
use std::cmp::{Ordering, PartialEq};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Index;
use std::str::FromStr;
use std::sync::Arc as Rc;

use serialize::binary::*;
use error::*;

/// TODO: all Names should be stored in a global "intern" space, and then everything that uses
///  them should be through references. As a workaround the Strings are all Rc as well as the array
/// TODO: Currently this probably doesn't support binary names, it would be nice to do that.
#[derive(Debug, Eq, Clone)]
pub struct Name {
    is_fqdn: bool,
    labels: Vec<Rc<String>>,
}

impl Name {
    /// Create a new domain::Name, i.e. label
    pub fn new() -> Self {
        Name {
            is_fqdn: false,
            labels: Vec::new(),
        }
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

    /// Appends the label to the end of this name
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::domain::Name;
    ///
    /// let name = Name::from_str("www.example").unwrap();
    /// let name = name.append_label("com");
    /// assert_eq!(name, Name::from_str("www.example.com").unwrap());
    /// ```
    pub fn append_label<S: Into<String>>(mut self, label: S) -> Self {
        self.labels.push(Rc::new(label.into()));
        assert!(self.labels.len() < 256); // TODO: should this be an Error?
        self
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
    /// let from_labels = Name::from_labels(vec!["www", "example", "com"]);
    /// assert_eq!(from_labels, Name::from_str("www.example.com").unwrap());
    ///
    /// let root = Name::from_labels::<String>(vec![]);
    /// assert!(root.is_root());
    /// ```
    pub fn from_labels<S: Into<String>>(labels: Vec<S>) -> Self {
        assert!(labels.len() < 256); // this should be an error
        Name {
            is_fqdn: true,
            labels: labels.into_iter().map(|s| Rc::new(s.into())).collect(),
        }
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
        for label in other.labels.iter() {
            self.labels.push(label.clone());
        }

        self.is_fqdn = other.is_fqdn;
        self
    }

    /// Appends the `domain` to `self`, making the new Name an FQDN
    ///
    /// This is an alias for append_name with the added effect of marking the new Name as
    ///  a fully-qualified-domain-name.
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
    /// use trust_dns_proto::rr::domain::Name;
    /// use std::cmp::Ordering;
    ///
    /// let example_com = Name::from_labels(vec!["Example", "Com"]);
    /// assert_eq!(example_com.cmp_with_case(&Name::from_labels(vec!["example", "com"]), false), Ordering::Less);
    /// assert_eq!(example_com.to_lowercase().cmp_with_case(&Name::from_labels(vec!["example", "com"]), false), Ordering::Equal);
    /// ```
    pub fn to_lowercase(&self) -> Self {
        let mut new_labels = Vec::with_capacity(self.labels.len());
        for label in self.labels.iter() {
            new_labels.push(label.to_lowercase());
        }

        let mut this = Self::from_labels(new_labels);
        this.is_fqdn = self.is_fqdn;
        this
    }

    /// Trims off the first part of the name, to help with searching for the domain piece
    ///
    /// # Examples
    ///
    /// ```
    /// use trust_dns_proto::rr::domain::Name;
    ///
    /// let example_com = Name::from_labels(vec!["example", "com"]);
    /// assert_eq!(example_com.base_name(), Name::from_labels(vec!["com"]));
    /// assert_eq!(Name::from_labels(vec!["com"]).base_name(), Name::root());
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
    /// use trust_dns_proto::rr::domain::Name;
    ///
    /// let example_com = Name::from_labels(vec!["example", "com"]);
    /// assert_eq!(example_com.trim_to(2), Name::from_labels(vec!["example", "com"]));
    /// assert_eq!(example_com.trim_to(1), Name::from_labels(vec!["com"]));
    /// assert_eq!(example_com.trim_to(0), Name::root());
    /// ```
    pub fn trim_to(&self, num_labels: usize) -> Name {
        if self.labels.len() >= num_labels {
            let trim = self.labels.len() - num_labels;
            Name {
                is_fqdn: self.is_fqdn,
                labels: self.labels[trim..].to_vec(),
            }
        } else {
            Self::root()
        }
    }

    /// returns true if the name components of self are all present at the end of name
    ///
    /// # Example
    ///
    /// ```rust
    /// use trust_dns_proto::rr::domain::Name;
    ///
    /// let name = Name::from_labels(vec!["www", "example", "com"]);
    /// let name = Name::from_labels(vec!["www", "example", "com"]);
    /// let zone = Name::from_labels(vec!["example", "com"]);
    /// let another = Name::from_labels(vec!["example", "net"]);
    /// assert!(zone.zone_of(&name));
    /// assert!(!another.zone_of(&name));
    /// ```
    pub fn zone_of(&self, name: &Self) -> bool {
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
        let self_lower = self.to_lowercase();
        let name_lower = name.to_lowercase();

        // TODO: there's probably a better way using iterators directly, but it wasn't obvious
        for i in 1..(self_len + 1) {
            if self_lower.labels.get(self_len - i) != name_lower.labels.get(name_len - i) {
                return false;
            }
        }

        return true;
    }

    /// Returns the number of labels in the name, discounting `*`.
    ///
    /// # Examples
    ///
    /// ```
    /// use trust_dns_proto::rr::domain::Name;
    ///
    /// let root = Name::root();
    /// assert_eq!(root.num_labels(), 0);
    ///
    /// let example_com = Name::from_labels(vec!["example", "com"]);
    /// assert_eq!(example_com.num_labels(), 2);
    ///
    /// let star_example_com = Name::from_labels(vec!["*", "example", "com"]);
    /// assert_eq!(star_example_com.num_labels(), 2);
    /// ```
    pub fn num_labels(&self) -> u8 {
        // it is illegal to have more than 256 labels.
        let num = self.labels.len() as u8;
        if num > 0 && self[0] == "*" {
            return num - 1;
        }

        num
    }

    /// returns the length in bytes of the labels. '.' counts as 1
    ///
    /// This can be used as an estimate, when serializing labels, they will often be compressed
    /// and/or escaped causing the exact length to be different.
    pub fn len(&self) -> usize {
        let dots = if self.labels.len() > 0 {
            self.labels.len()
        } else {
            1
        };
        self.labels.iter().fold(dots, |acc, item| acc + item.len())
    }

    /// attempts to parse a name such as `"example.com."` or `"subdomain.example.com."`
    ///
    /// # Examples
    ///
    /// ```rust
    /// use trust_dns_proto::rr::domain::Name;
    ///
    /// let name = Name::parse("example.com.", None).unwrap();
    /// assert_eq!(name.base_name(), Name::from_labels(vec!["com"]));
    /// assert_eq!(*name[0], String::from("example"));
    /// ```
    pub fn parse(local: &str, origin: Option<&Self>) -> ProtoResult<Self> {
        let mut name = Name::new();
        let mut label = String::new();

        let mut state = ParseState::Label;

        // short cirtuit root parse
        if local == "." {
            name.set_fqdn(true);
            return Ok(name);
        }

        // evaluate all characters
        for ch in local.chars() {
            match state {
                ParseState::Label => {
                    match ch {
                        '.' => {
                            name.labels.push(Rc::new(label.clone()));
                            label.clear();
                        }
                        '\\' => state = ParseState::Escape1,
                        ch if !ch.is_control() && !ch.is_whitespace() => label.push(ch),
                        _ => {
                            return Err(
                                ProtoErrorKind::Msg(format!("unrecognized char: {}", ch)).into(),
                            )
                        }
                    }
                }
                ParseState::Escape1 => {
                    if ch.is_numeric() {
                        state = ParseState::Escape2(try!(
                            ch.to_digit(10).ok_or(ProtoError::from(ProtoErrorKind::Msg(
                                format!("illegal char: {}", ch),
                            )))
                        ))
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
                            try!(ch.to_digit(10).ok_or(ProtoError::from(ProtoErrorKind::Msg(
                                format!("illegal char: {}", ch),
                            )))),
                        );
                    } else {
                        return try!(Err(
                            ProtoErrorKind::Msg(format!("unrecognized char: {}", ch)),
                        ));
                    }
                }
                ParseState::Escape3(i, ii) => {
                    if ch.is_numeric() {
                        let val: u32 = (i << 16) + (ii << 8) +
                            try!(ch.to_digit(10).ok_or(ProtoError::from(ProtoErrorKind::Msg(
                                format!("illegal char: {}", ch),
                            ))));
                        let new: char = try!(char::from_u32(val).ok_or(
                            ProtoError::from(ProtoErrorKind::Msg(
                                format!("illegal char: {}", ch),
                            )),
                        ));
                        label.push(new);
                        state = ParseState::Label;
                    } else {
                        return try!(Err(
                            ProtoErrorKind::Msg(format!("unrecognized char: {}", ch)),
                        ));
                    }
                }
            }
        }

        if !label.is_empty() {
            name.labels.push(Rc::new(label));
        }

        if local.ends_with('.') {
            name.set_fqdn(true);
        } else {
            if let Some(other) = origin {
                return Ok(name.append_domain(other));
            }
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
        let mut labels: &[Rc<String>] = &self.labels;

        if canonical {
            for label in labels {
                try!(encoder.emit_character_data(label));
            }
        } else {
            while let Some(label) = labels.first() {
                // before we write the label, let's look for the current set of labels.
                if let Some(loc) = encoder.get_label_pointer(labels) {
                    // write out the pointer marker
                    //  or'd with the location with shouldn't be larger than this 2^14 or 16k
                    try!(encoder.emit_u16(0xC000u16 | (loc & 0x3FFFu16)));

                    // we found a pointer don't write more, break
                    return Ok(());
                } else {
                    if label.len() > 63 {
                        return Err(ProtoErrorKind::LabelBytesTooLong(label.len()).into());
                    }

                    // to_owned is cloning the the vector, but the Rc's at least don't clone the strings.
                    encoder.store_label_pointer(labels.to_owned());
                    try!(encoder.emit_character_data(label));

                    // return the next parts of the labels
                    //  this should be safe, the labels.first() wouldn't have let us here if there wasn't
                    //  at least one item.
                    labels = &labels[1..];
                }
            }
        }

        // if we're getting here, then we didn't write out a pointer and are ending the name
        // the end of the list of names
        try!(encoder.emit(0));

        // the entire name needs to be less than 256.
        let length = encoder.len() - buf_len;
        if length > 255 {
            return Err(ProtoErrorKind::DomainNameTooLong(length).into());
        }

        Ok(())
    }

    /// Writes the labels, as lower case, to the encoder
    pub fn emit_with_lowercase(
        &self,
        encoder: &mut BinEncoder,
        lowercase: bool,
    ) -> ProtoResult<()> {
        let is_canonical_names = encoder.is_canonical_names();
        if lowercase {
            self.to_lowercase().emit_as_canonical(
                encoder,
                is_canonical_names,
            )
        } else {
            self.emit_as_canonical(encoder, is_canonical_names)
        }
    }

    /// compares with the other label, ignoring case
    pub fn cmp_with_case(&self, other: &Self, ignore_case: bool) -> Ordering {
        if self.labels.is_empty() && other.labels.is_empty() {
            return Ordering::Equal;
        }

        // we reverse the iters so that we are comparing from the root/domain to the local...
        let self_labels = self.labels.iter().rev();
        let other_labels = other.labels.iter().rev();

        for (l, r) in self_labels.zip(other_labels) {
            if ignore_case {
                match (*l).to_lowercase().cmp(&(*r).to_lowercase()) {
                    o @ Ordering::Less |
                    o @ Ordering::Greater => return o,
                    Ordering::Equal => continue,
                }
            } else {
                match l.cmp(r) {
                    o @ Ordering::Less |
                    o @ Ordering::Greater => return o,
                    Ordering::Equal => continue,
                }
            }
        }

        self.labels.len().cmp(&other.labels.len())
    }

    /// Converts the Name labels to the String form.
    ///
    /// This converts the name to an unescaped format, that could be used with parse. The name is
    ///  is followed by the final `.`, e.g. as in `www.example.com.`, which represents a fully
    ///  qualified Name.
    pub fn to_string(&self) -> String {
        format!("{}", self)
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

        let mut labels = octets.iter().rev().fold(
            Vec::with_capacity(6),
            |mut labels, o| {
                labels.push(format!("{}", o));
                labels
            },
        );

        labels.push("in-addr".to_string());
        labels.push("arpa".to_string());

        Self::from_labels(labels)
    }
}

impl From<Ipv6Addr> for Name {
    fn from(addr: Ipv6Addr) -> Name {
        let segments = addr.segments();

        let mut labels = segments.iter().rev().fold(
            Vec::with_capacity(34),
            |mut labels, o| {
                labels.push(format!("{:x}", (*o & 0x000F) as u8));
                labels.push(format!("{:x}", (*o >> 4 & 0x000F) as u8));
                labels.push(format!("{:x}", (*o >> 8 & 0x000F) as u8));
                labels.push(format!("{:x}", (*o >> 12 & 0x000F) as u8));
                labels
            },
        );

        labels.push("ip6".to_string());
        labels.push("arpa".to_string());

        Self::from_labels(labels)
    }
}


impl Hash for Name {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        for label in self.labels.iter() {
            state.write(label.to_lowercase().as_bytes());
        }
    }
}

impl PartialEq<Name> for Name {
    fn eq(&self, other: &Self) -> bool {
        self.cmp_with_case(other, true) == Ordering::Equal
    }
}

enum ParseState {
    Label,
    Escape1,
    Escape2(u32),
    Escape3(u32, u32),
}

impl BinSerializable<Name> for Name {
    /// parses the chain of labels
    ///  this has a max of 255 octets, with each label being less than 63.
    ///  all names will be stored lowercase internally.
    /// This will consume the portions of the Vec which it is reading...
    fn read(decoder: &mut BinDecoder) -> ProtoResult<Name> {
        let mut state: LabelParseState = LabelParseState::LabelLengthOrPointer;
        let mut labels: Vec<Rc<String>> = Vec::with_capacity(3); // most labels will be around three, e.g. www.example.com

        // assume all chars are utf-8. We're doing byte-by-byte operations, no endianess issues...
        // reserved: (1000 0000 aka 0800) && (0100 0000 aka 0400)
        // pointer: (slice == 1100 0000 aka C0) & C0 == true, then 03FF & slice = offset
        // label: 03FF & slice = length; slice.next(length) = label
        // root: 0000
        loop {
            state = match state {
                LabelParseState::LabelLengthOrPointer => {
                    // determine what the next label is
                    match decoder.peek() {
                        Some(0) | None => LabelParseState::Root,
                        Some(byte) if byte & 0b1100_0000 == 0b1100_0000 => LabelParseState::Pointer,
                        Some(byte) if byte & 0b1100_0000 == 0b0000_0000 => LabelParseState::Label,
                        Some(byte) => {
                            return Err(ProtoErrorKind::UnrecognizedLabelCode(byte).into())
                        }
                    }
                }
                LabelParseState::Label => {
                    labels.push(Rc::new(try!(decoder.read_character_data())));

                    // reset to collect more data
                    LabelParseState::LabelLengthOrPointer
                }
                //         4.1.4. Message compression
                //
                // In order to reduce the size of messages, the domain system utilizes a
                // compression scheme which eliminates the repetition of domain names in a
                // message.  In this scheme, an entire domain name or a list of labels at
                // the end of a domain name is replaced with a pointer to a prior occurance
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
                    let location = try!(decoder.read_u16()) & 0x3FFF; // get rid of the two high order bits
                    let mut pointer = decoder.clone(location);
                    let pointed = try!(Name::read(&mut pointer));

                    for l in &*pointed.labels {
                        labels.push(l.clone());
                    }

                    // Pointers always finish the name, break like Root.
                    break;
                }
                LabelParseState::Root => {
                    // need to pop() the 0 off the stack...
                    try!(decoder.pop());
                    break;
                }
            }
        }

        Ok(Name {
            is_fqdn: true,
            labels: labels,
        })
    }

    fn emit(&self, encoder: &mut BinEncoder) -> ProtoResult<()> {
        let is_canonical_names = encoder.is_canonical_names();
        self.emit_as_canonical(encoder, is_canonical_names)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut iter = self.labels.iter();
        if let Some(label) = iter.next() {
            write!(f, "{}", label)?;
        }

        for label in iter {
            write!(f, ".{}", label)?;
        }

        // if it was the root name
        if self.is_root() || self.is_fqdn() {
            try!(write!(f, "."));
        }
        Ok(())
    }
}

impl Index<usize> for Name {
    type Output = String;

    fn index<'a>(&'a self, _index: usize) -> &'a String {
        &*(self.labels[_index])
    }
}

impl PartialOrd<Name> for Name {
    fn partial_cmp(&self, other: &Name) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Name {
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
        self.cmp_with_case(other, true)
    }
}

/// This is the list of states for the label parsing state machine
enum LabelParseState {
    LabelLengthOrPointer, // basically the start of the FSM
    Label, // storing length of the label, must be < 63
    Pointer, // location of pointer in slice,
    Root, // root is the end of the labels list, aka null
}

impl FromStr for Name {
    type Err = ProtoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Name::parse(s, None)
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;
    use std::str::FromStr;

    use super::*;

    use serialize::binary::bin_tests::{test_read_data_set, test_emit_data_set};
    #[allow(unused)]
    use serialize::binary::*;

    fn get_data() -> Vec<(Name, Vec<u8>)> {
        vec![
      (Name::new(), vec![0]), // base case, only the root
      (Name::from_labels(vec!["a"]), vec![1,b'a',0]), // a single 'a' label
      (Name::from_labels(vec!["a","bc"]), vec![1,b'a',2,b'b',b'c',0]), // two labels, 'a.bc'
      (Name::from_labels(vec!["a","♥"]), vec![1,b'a',3,0xE2,0x99,0xA5,0]), // two labels utf8, 'a.♥'
    ]
    }

    #[test]
    fn test_num_labels() {
        assert_eq!(Name::from_labels(vec!["*"]).num_labels(), 0);
        assert_eq!(Name::from_labels(vec!["a"]).num_labels(), 1);
        assert_eq!(Name::from_labels(vec!["*", "b"]).num_labels(), 1);
        assert_eq!(Name::from_labels(vec!["a", "b"]).num_labels(), 2);
        assert_eq!(Name::from_labels(vec!["*", "b", "c"]).num_labels(), 2);
        assert_eq!(Name::from_labels(vec!["a", "b", "c"]).num_labels(), 3);
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

        let first = Name::from_labels(vec!["ra", "rb", "rc"]);
        let second = Name::from_labels(vec!["rb", "rc"]);
        let third = Name::from_labels(vec!["rc"]);
        let fourth = Name::from_labels(vec!["z", "ra", "rb", "rc"]);

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
    fn test_base_name() {
        let zone = Name::from_labels(vec!["example", "com"]);

        assert_eq!(zone.base_name(), Name::from_labels(vec!["com"]));
        assert!(zone.base_name().base_name().is_root());
        assert!(zone.base_name().base_name().base_name().is_root());
    }

    #[test]
    fn test_zone_of() {
        let zone = Name::from_labels(vec!["example", "com"]);
        let www = Name::from_labels(vec!["www", "example", "com"]);
        let none = Name::from_labels(vec!["none", "com"]);
        let root = Name::root();

        assert!(zone.zone_of(&zone));
        assert!(zone.zone_of(&www));
        assert!(!zone.zone_of(&none));
        assert!(root.zone_of(&zone));
        assert!(!zone.zone_of(&root));
    }

    #[test]
    fn test_zone_of_case() {
        let zone = Name::from_labels(vec!["examplE", "cOm"]);
        let www = Name::from_labels(vec!["www", "example", "com"]);
        let none = Name::from_labels(vec!["none", "com"]);

        assert!(zone.zone_of(&zone));
        assert!(zone.zone_of(&www));
        assert!(!zone.zone_of(&none))
    }

    #[test]
    fn test_partial_cmp_eq() {
        let root = Some(Name::from_labels(Vec::<String>::new()));
        let comparisons: Vec<(Name, Name)> = vec![
            (root.clone().unwrap(), root.clone().unwrap()),
            (
                Name::parse("example", root.as_ref()).unwrap(),
                Name::parse("example", root.as_ref()).unwrap()
            ),
        ];

        for (left, right) in comparisons {
            println!("left: {}, right: {}", left, right);
            assert_eq!(left.partial_cmp(&right), Some(Ordering::Equal));
        }
    }

    #[test]
    fn test_partial_cmp() {
        let root = Some(Name::from_labels(Vec::<String>::new()));
        let comparisons: Vec<(Name, Name)> =
            vec![
                (
                    Name::parse("example", root.as_ref()).unwrap(),
                    Name::parse("a.example", root.as_ref()).unwrap()
                ),
                (
                    Name::parse("a.example", root.as_ref()).unwrap(),
                    Name::parse("yljkjljk.a.example", root.as_ref()).unwrap()
                ),
                (
                    Name::parse("yljkjljk.a.example", root.as_ref()).unwrap(),
                    Name::parse("Z.a.example", root.as_ref()).unwrap()
                ),
                (
                    Name::parse("Z.a.example", root.as_ref()).unwrap(),
                    Name::parse("zABC.a.EXAMPLE", root.as_ref()).unwrap()
                ),
                (
                    Name::parse("zABC.a.EXAMPLE", root.as_ref()).unwrap(),
                    Name::parse("z.example", root.as_ref()).unwrap()
                ),
                (
                    Name::parse("z.example", root.as_ref()).unwrap(),
                    Name::parse("\\001.z.example", root.as_ref()).unwrap()
                ),
                (
                    Name::parse("\\001.z.example", root.as_ref()).unwrap(),
                    Name::parse("*.z.example", root.as_ref()).unwrap()
                ),
                (
                    Name::parse("*.z.example", root.as_ref()).unwrap(),
                    Name::parse("\\200.z.example", root.as_ref()).unwrap()
                ),
            ];

        for (left, right) in comparisons {
            println!("left: {}, right: {}", left, right);
            assert_eq!(left.cmp(&right), Ordering::Less);
        }
    }

    #[test]
    fn test_cmp_ignore_case() {
        let root = Some(Name::from_labels(Vec::<String>::new()));
        let comparisons: Vec<(Name, Name)> = vec![
            (
                Name::parse("ExAmPle", root.as_ref()).unwrap(),
                Name::parse("example", root.as_ref()).unwrap()
            ),
            (
                Name::parse("A.example", root.as_ref()).unwrap(),
                Name::parse("a.example", root.as_ref()).unwrap()
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
        let name = Name::from_labels(vec!["103", "0", "3", "26", "in-addr", "arpa"]);

        assert_eq!(Into::<Name>::into(ip), name);
    }

    #[test]
    fn test_from_ipv6() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1));
        let name = Name::from_labels(vec![
            "1",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "8",
            "b",
            "d",
            "0",
            "1",
            "0",
            "0",
            "2",
            "ip6",
            "arpa",
        ]);

        assert_eq!(Into::<Name>::into(ip), name);
    }

    #[test]
    fn test_from_str() {
        assert_eq!(
            Name::from_str("www.example.com.").unwrap(),
            Name::from_labels(vec!["www", "example", "com"])
        );
        assert_eq!(
            Name::from_str(".").unwrap(),
            Name::from_labels(Vec::<String>::new())
        );
    }

    #[test]
    fn test_fqdn() {
        assert!(Name::root().is_fqdn());
        assert!(Name::from_str(".").unwrap().is_fqdn());
        assert!(Name::from_str("www.example.com.").unwrap().is_fqdn());
        assert!(Name::from_labels(vec!["www", "example", "com"]).is_fqdn());

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
}
