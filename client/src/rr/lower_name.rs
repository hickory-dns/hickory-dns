// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! domain name, aka labels, implementaton

use std::borrow::Borrow;
use std::cmp::{Ordering, PartialEq};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Index;

use rr::Name;
use serialize::binary::*;
use trust_dns_proto::error::*;

/// TODO: all LowerNames should be stored in a global "intern" space, and then everything that uses
///  them should be through references. As a workaround the Strings are all Rc as well as the array
/// TODO: Currently this probably doesn't support binary names, it would be nice to do that.
#[derive(Default, Debug, Eq, Clone)]
pub struct LowerName(Name);

impl LowerName {
    /// Create a new domain::LowerName, i.e. label
    pub fn new(name: &Name) -> Self {
        LowerName(name.to_lowercase())
    }

    /// Returns true if there are no labels, i.e. it's empty.
    ///
    /// In DNS the root is represented by `.`
    ///
    /// # Examples
    ///
    /// ```
    /// use trust_dns::rr::{LowerName, Name};
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
    /// use trust_dns::rr::{LowerName, Name};
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
    /// use trust_dns::rr::{LowerName, Name};
    ///
    /// let example_com = LowerName::from(Name::from_labels(vec!["example", "com"]));
    /// assert_eq!(example_com.base_name(), LowerName::from(Name::from_labels(vec!["com"])));
    /// assert_eq!(LowerName::from(Name::from_labels(vec!["com"]).base_name()), LowerName::from(Name::root()));
    /// assert_eq!(LowerName::from(Name::root().base_name()), LowerName::from(Name::root()));
    /// ```
    pub fn base_name(&self) -> LowerName {
        LowerName(self.0.base_name())
    }

    /// returns true if the name components of self are all present at the end of name
    ///
    /// # Example
    ///
    /// ```rust
    /// use trust_dns::rr::{LowerName, Name};
    ///
    /// let name = LowerName::from(Name::from_labels(vec!["www", "example", "com"]));
    /// let zone = LowerName::from(Name::from_labels(vec!["example", "com"]));
    /// let another = LowerName::from(Name::from_labels(vec!["example", "net"]));
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
    /// use trust_dns::rr::{LowerName, Name};
    ///
    /// let root = LowerName::from(Name::root());
    /// assert_eq!(root.num_labels(), 0);
    ///
    /// let example_com = LowerName::from(Name::from_labels(vec!["example", "com"]));
    /// assert_eq!(example_com.num_labels(), 2);
    ///
    /// let star_example_com = LowerName::from(Name::from_labels(vec!["*", "example", "com"]));
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

    /// Emits the canonical version of the name to the encoder.
    ///
    /// In canonical form, there will be no pointers written to the encoder (i.e. no compression).
    pub fn emit_as_canonical(&self, encoder: &mut BinEncoder, canonical: bool) -> ProtoResult<()> {
        self.0.emit_as_canonical(encoder, canonical)
    }
    
    // /// Converts the LowerName labels to the String form.
    // ///
    // /// This converts the name to an unescaped format, that could be used with parse. The name is
    // ///  is followed by the final `.`, e.g. as in `www.example.com.`, which represents a fully
    // ///  qualified LowerName.
    // pub fn to_string(&self) -> String {
    //     self.0.to_string()
    // }
}

impl Hash for LowerName {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        for label in &self.0 {
            state.write(label.as_bytes());
        }
    }
}

impl PartialEq<LowerName> for LowerName {
    fn eq(&self, other: &Self) -> bool {
        self.0.cmp_with_case(&other.0, false) == Ordering::Equal
    }
}

impl BinEncodable for LowerName {
    fn emit(&self, encoder: &mut BinEncoder) -> ProtoResult<()> {
        let is_canonical_names = encoder.is_canonical_names();
        self.emit_as_canonical(encoder, is_canonical_names)
    }
}

impl fmt::Display for LowerName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut iter = self.0.iter();
        if let Some(label) = iter.next() {
            write!(f, "{}", label)?;
        }

        for label in iter {
            write!(f, ".{}", label)?;
        }

        // if it was the root name
        if self.is_root() || self.is_fqdn() {
            write!(f, ".")?;
        }
        Ok(())
    }
}

impl Index<usize> for LowerName {
    type Output = str;

    fn index(&self, _index: usize) -> &str {
        &(self.0[_index])
    }
}

impl PartialOrd<LowerName> for LowerName {
    fn partial_cmp(&self, other: &LowerName) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LowerName {
    /// RFC 4034                DNSSEC Resource Records               March 2005
    ///
    /// ```text
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
        self.0.cmp_with_case(&other.0, false)
    }
}

impl From<Name> for LowerName {
    fn from(name: Name) -> Self {
        LowerName::new(&name)
    }
}

impl<'a> From<&'a Name> for LowerName {
    fn from(name: &'a Name) -> Self {
        LowerName::new(name)
    }
}

impl From<LowerName> for Name {
    fn from(name: LowerName) -> Self {
        name.0
    }
}

impl Borrow<Name> for LowerName {
    fn borrow(&self) -> &Name {
        &self.0
    }
}

impl<'r> BinDecodable<'r> for LowerName {
    /// parses the chain of labels
    ///  this has a max of 255 octets, with each label being less than 63.
    ///  all names will be stored lowercase internally.
    /// This will consume the portions of the Vec which it is reading...
    fn read(decoder: &mut BinDecoder<'r>) -> ProtoResult<LowerName> {
        let name = Name::read(decoder)?;
        Ok(LowerName(name.to_lowercase()))
    }
}