// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! domain name, aka labels, implementation

#[cfg(feature = "serde")]
use alloc::string::{String, ToString};
use core::cmp::{Ordering, PartialEq};
use core::fmt;
use core::hash::{Hash, Hasher};
use core::ops::Deref;
use core::str::FromStr;

use crate::error::*;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::rr::Name;
use crate::serialize::binary::*;

/// TODO: all LowerNames should be stored in a global "intern" space, and then everything that uses
///  them should be through references. As a workaround the Strings are all Rc as well as the array
#[derive(Default, Debug, Eq, Clone)]
pub struct LowerName(Name);

impl LowerName {
    /// Create a new domain::LowerName, i.e. label
    pub fn new(name: &Name) -> Self {
        Self(name.to_lowercase())
    }

    /// Returns true if there are no labels, i.e. it's empty.
    ///
    /// In DNS the root is represented by `.`
    ///
    /// # Examples
    ///
    /// ```
    /// use hickory_proto::rr::{LowerName, Name};
    ///
    /// let root = LowerName::from(Name::root());
    /// assert_eq!(&root.to_string(), ".");
    /// ```
    pub fn is_root(&self) -> bool {
        self.0.is_root()
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
    /// use hickory_proto::rr::{LowerName, Name};
    ///
    /// let name = LowerName::from(Name::from_str("www").unwrap());
    /// assert!(!name.is_fqdn());
    ///
    /// let name = LowerName::from(Name::from_str("www.example.com").unwrap());
    /// assert!(!name.is_fqdn());
    ///
    /// let name = LowerName::from(Name::from_str("www.example.com.").unwrap());
    /// assert!(name.is_fqdn());
    /// ```
    pub fn is_fqdn(&self) -> bool {
        self.0.is_fqdn()
    }

    /// Trims off the first part of the name, to help with searching for the domain piece
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    /// use hickory_proto::rr::{LowerName, Name};
    ///
    /// let example_com = LowerName::from(Name::from_str("example.com").unwrap());
    /// assert_eq!(example_com.base_name(), LowerName::from(Name::from_str("com.").unwrap()));
    /// assert_eq!(LowerName::from(Name::from_str("com.").unwrap().base_name()), LowerName::from(Name::root()));
    /// assert_eq!(LowerName::from(Name::root().base_name()), LowerName::from(Name::root()));
    /// ```
    pub fn base_name(&self) -> Self {
        Self(self.0.base_name())
    }

    /// returns true if the name components of self are all present at the end of name
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use hickory_proto::rr::{LowerName, Name};
    ///
    /// let name = LowerName::from(Name::from_str("www.example.com").unwrap());
    /// let zone = LowerName::from(Name::from_str("example.com").unwrap());
    /// let another = LowerName::from(Name::from_str("example.net").unwrap());
    /// assert!(zone.zone_of(&name));
    /// assert!(!another.zone_of(&name));
    /// ```
    pub fn zone_of(&self, name: &Self) -> bool {
        self.0.zone_of_case(&name.0)
    }

    /// Returns the number of labels in the name, discounting `*`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    /// use hickory_proto::rr::{LowerName, Name};
    ///
    /// let root = LowerName::from(Name::root());
    /// assert_eq!(root.num_labels(), 0);
    ///
    /// let example_com = LowerName::from(Name::from_str("example.com").unwrap());
    /// assert_eq!(example_com.num_labels(), 2);
    ///
    /// let star_example_com = LowerName::from(Name::from_str("*.example.com").unwrap());
    /// assert_eq!(star_example_com.num_labels(), 2);
    /// ```
    pub fn num_labels(&self) -> u8 {
        self.0.num_labels()
    }

    /// returns the length in bytes of the labels. '.' counts as 1
    ///
    /// This can be used as an estimate, when serializing labels, they will often be compressed
    /// and/or escaped causing the exact length to be different.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the name is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Emits the canonical version of the name to the encoder.
    ///
    /// In canonical form, there will be no pointers written to the encoder (i.e. no compression).
    pub fn emit_as_canonical(
        &self,
        encoder: &mut BinEncoder<'_>,
        canonical: bool,
    ) -> ProtoResult<()> {
        self.0.emit_as_canonical(encoder, canonical)
    }

    /// Pass through for Name::is_wildcard
    pub fn is_wildcard(&self) -> bool {
        self.0.is_wildcard()
    }

    /// Replaces the first label with the wildcard character, "*"
    pub fn into_wildcard(self) -> Self {
        let name = self.0.into_wildcard();
        Self(name)
    }
}

impl Hash for LowerName {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        for label in &self.0 {
            state.write(label);
        }
    }
}

impl PartialEq<Self> for LowerName {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_case(&other.0)
    }
}

impl BinEncodable for LowerName {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        let is_canonical_names = encoder.is_canonical_names();
        self.emit_as_canonical(encoder, is_canonical_names)
    }
}

impl fmt::Display for LowerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl PartialOrd<Self> for LowerName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LowerName {
    /// Given two lower cased names, this performs a case sensitive comparison.
    ///
    /// ```text
    /// RFC 4034                DNSSEC Resource Records               March 2005
    ///
    /// 6.1.  Canonical DNS LowerName Order
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
        self.0.cmp_case(&other.0)
    }
}

impl From<Name> for LowerName {
    fn from(name: Name) -> Self {
        Self::new(&name)
    }
}

impl<'a> From<&'a Name> for LowerName {
    fn from(name: &'a Name) -> Self {
        Self::new(name)
    }
}

impl From<LowerName> for Name {
    fn from(name: LowerName) -> Self {
        name.0
    }
}

impl<'a> From<&'a LowerName> for Name {
    fn from(name: &'a LowerName) -> Self {
        name.0.clone()
    }
}

impl Deref for LowerName {
    type Target = Name;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'r> BinDecodable<'r> for LowerName {
    /// parses the chain of labels
    ///  this has a max of 255 octets, with each label being less than 63.
    ///  all names will be stored lowercase internally.
    /// This will consume the portions of the Vec which it is reading...
    fn read(decoder: &mut BinDecoder<'r>) -> ProtoResult<Self> {
        let name = Name::read(decoder)?;
        Ok(Self(name.to_lowercase()))
    }
}

impl FromStr for LowerName {
    type Err = ProtoError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Name::from_str(name).map(Self::from)
    }
}

#[cfg(feature = "serde")]
impl Serialize for LowerName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for LowerName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

#[test]
fn test_name_lowername_roundtrip() {
    // Test that roundtrip conversions from Name <-> LowerName <-> Name are
    // equal and preserve is_fqdn.
    let fqdn_name = Name::from_ascii("example.com.").unwrap();
    let relative_name = Name::from_ascii("example.com").unwrap();

    let fqdn_lname = LowerName::from(fqdn_name.clone());
    let relative_lname = LowerName::from(relative_name.clone());

    let fqdn_rt_name: Name = fqdn_lname.into();
    let relative_rt_name: Name = relative_lname.into();

    assert_eq!(fqdn_name, fqdn_rt_name);
    assert_eq!(relative_name, relative_rt_name);
    assert!(fqdn_rt_name != relative_rt_name);
}
