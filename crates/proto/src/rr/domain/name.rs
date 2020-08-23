// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! domain name, aka labels, implementation

use std::borrow::{Borrow, Cow};
use std::cmp::{Ordering, PartialEq};
use std::fmt::{self, Write};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Index;
use std::str::FromStr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
#[cfg(feature = "serde-config")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::error::*;
use crate::rr::domain::label::{
    CaseInsensitive, CaseSensitive, DnsLabel, IntoLabel, Label, LabelCmp, LabelRef,
};
use crate::rr::domain::parse::*;
use crate::rr::domain::usage::LOCALHOST as LOCALHOST_usage;
use crate::rr::domain::CowName;
use crate::serialize::binary::*;

/// An object safe trait for all domain Names
pub trait DnsName {
    /// An iterator over all the labels in the name
    fn labels(&self) -> LabelIter;

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
    /// use trust_dns_proto::rr::domain::{DnsName, NameRef};
    ///
    /// let name = NameRef::from_ascii("www").unwrap();
    /// assert!(!name.is_fqdn());
    ///
    /// let name = NameRef::from_ascii("www.example.com").unwrap();
    /// assert!(!name.is_fqdn());
    ///
    /// let name = NameRef::from_ascii("www.example.com.").unwrap();
    /// assert!(name.is_fqdn());
    /// ```
    #[inline]
    fn is_fqdn(&self) -> bool {
        self.labels()
            .into_iter_with_root()
            .last()
            .map(|l| l.is_empty() || l.is_root())
            .unwrap_or(false)
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
    /// use trust_dns_proto::rr::domain::{NameRef, DnsName};
    ///
    /// assert_eq!(NameRef::from_ascii("www.example.com.").unwrap().len(), 16);
    /// assert_eq!(NameRef::from_ascii(".").unwrap().len(), 1);
    /// assert_eq!(NameRef::root().len(), 1);
    /// ```
    #[inline]
    fn len(&self) -> usize {
        let len = self.labels().fold(
            0,
            |acc, label| acc + 1 /*for the label*/ + label.len(), /*length of the label*/
        );

        if len == 0 {
            // for the root, base, name
            1
        } else {
            len
        }
    }

    /// Returns whether the length of the labels, in bytes is 0. In practice, since '.' counts as
    /// 1, this is never the case so the method returns false.
    #[inline]
    fn is_empty(&self) -> bool {
        false
    }

    /// Returns the number of labels in the name, discounting `*`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::domain::{DnsName, Name};
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
    #[inline]
    fn num_labels(&self) -> u8 {
        // it is illegal to have more than 256 labels.
        let num = self.labels().count() as u8;

        if self.is_wildcard() {
            num.saturating_sub(1)
        } else {
            num
        }
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
    #[inline]
    fn is_root(&self) -> bool {
        self.num_labels() == 0 && self.is_fqdn()
    }

    /// Return a Borrowed version of the DnsName
    fn borrowed_name<'a>(&'a self) -> &'a BorrowedName;

    /// Converts this to the Name (owned) variant
    #[inline]
    fn to_name(&self) -> Name {
        let mut name = Name::default();
        for l in self.labels().into_iter_with_root() {
            name.push_label(l.as_bytes());
        }

        debug_assert_eq!(self.is_fqdn(), name.is_fqdn());
        name
    }

    /// Emits the canonical version of the name to the encoder.
    ///
    /// In canonical form, there will be no pointers written to the encoder (i.e. no compression).
    #[inline]
    fn emit_as_canonical(&self, encoder: &mut BinEncoder, canonical: bool) -> ProtoResult<()> {
        let buf_len = encoder.len(); // lazily assert the size is less than 255...
                                     // lookup the label in the BinEncoder
                                     // if it exists, write the Pointer

        let num_labels = self.num_labels() as usize;
        let labels = self.labels();

        // start index of each label
        let mut labels_written: Vec<usize> = Vec::with_capacity(num_labels);

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

    /// Encode the labels to `Write` using the `LabelEnc` for style.
    #[inline]
    fn write_labels<W: Write, E: LabelEnc>(&self, f: &mut W) -> Result<(), fmt::Error>
    where
        Self: Sized,
    {
        let mut iter = self.labels();
        if let Some(label) = iter.next() {
            E::write_label(f, &label)?;
        }

        for label in iter {
            write!(f, ".")?;
            E::write_label(f, &label)?;
        }

        // if it was the root name
        if self.is_root() || self.is_fqdn() {
            write!(f, ".")?;
        }
        Ok(())
    }

    /// Case sensitive comparison
    #[inline]
    fn cmp_case(&self, other: &impl DnsName) -> Ordering
    where
        Self: Sized,
    {
        cmp_with_f::<CaseSensitive, _, _>(self, other)
    }

    /// Compares the Names, in a case sensitive manner
    #[inline]
    fn eq_case(&self, other: &impl DnsName) -> bool
    where
        Self: Sized,
    {
        cmp_with_f::<CaseSensitive, _, _>(self, other) == Ordering::Equal
    }

    /// Converts this name into an ascii safe string.
    ///
    /// If the name is an IDNA name, then the name labels will be returned with the `xn--` prefix.
    ///  see `to_utf8` or the `Display` impl for methods which convert labels to utf8.
    #[inline]
    fn to_ascii(&self) -> String {
        let mut s = String::with_capacity(self.len());
        write_labels::<_, LabelEncAscii, _>(&mut s, self)
            .expect("string conversion of name should not fail");
        s
    }

    /// Converts the Name labels to the utf8 String form.
    ///
    /// This converts the name to an unescaped format, that could be used with parse. If, the name is
    ///  is followed by the final `.`, e.g. as in `www.example.com.`, which represents a fully
    ///  qualified Name.
    #[inline]
    fn to_utf8(&self) -> String {
        let mut s = String::with_capacity(self.len());
        write_labels::<_, LabelEncUtf8, _>(&mut s, self)
            .expect("string conversion of name should not fail");
        s
    }

    /// Converts a *.arpa Name in a PTR record back into an IpNet if possible.
    fn parse_arpa_name(&self) -> Result<IpNet, ProtoError> {
        if !self.is_fqdn() {
            return Err("PQDN cannot be valid arpa name".into());
        }
        let mut iter = self.labels().rev();
        let first = iter
            .next()
            .ok_or_else(|| ProtoError::from("not an arpa address"))?;
        if !"arpa".eq_ignore_ascii_case(std::str::from_utf8(first.as_bytes())?) {
            return Err("not an arpa address".into());
        }
        let second = iter
            .next()
            .ok_or_else(|| ProtoError::from("invalid arpa address"))?;
        let mut prefix_len: u8 = 0;
        match &std::str::from_utf8(second.as_bytes())?.to_ascii_lowercase()[..] {
            "in-addr" => {
                let mut octets: [u8; 4] = [0; 4];
                for octet in octets.iter_mut() {
                    match iter.next() {
                        Some(label) => *octet = std::str::from_utf8(label.as_bytes())?.parse()?,
                        None => break,
                    }
                    prefix_len += 8;
                }
                if iter.next().is_some() {
                    return Err("unrecognized in-addr.arpa.".into());
                }
                Ok(IpNet::V4(
                    Ipv4Net::new(octets.into(), prefix_len).expect("Ipv4Net::new"),
                ))
            }
            "ip6" => {
                let mut address: u128 = 0;
                while prefix_len < 128 {
                    match iter.next() {
                        Some(label) => {
                            if label.len() == 1 {
                                prefix_len += 4;
                                let hex =
                                    u8::from_str_radix(std::str::from_utf8(label.as_bytes())?, 16)?;
                                address |= u128::from(hex) << (128 - prefix_len);
                            } else {
                                return Err("invalid label length for ip6.arpa".into());
                            }
                        }
                        None => break,
                    }
                }
                if iter.next().is_some() {
                    return Err("unrecognized ip6.arpa.".into());
                }
                Ok(IpNet::V6(
                    Ipv6Net::new(address.into(), prefix_len).expect("Ipv6Net::new"),
                ))
            }
            _ => Err("unrecognized arpa address".into()),
        }
    }

    /// Determines if this Name is lowercase, in DNS terms this is limited to ascii characters
    #[inline]
    fn is_lowercase(&self) -> bool {
        self.labels().all(|l| l.is_lowercase())
    }

    /// Creates a new Name with all labels lowercased
    ///
    /// # Examples
    ///
    /// ```
    /// use std::cmp::Ordering;
    /// use std::str::FromStr;
    ///
    /// use trust_dns_proto::rr::domain::{Label, Name, DnsName};
    ///
    /// let example_com = Name::from_ascii("Example.Com").unwrap();
    /// assert_eq!(example_com.cmp_case(&Name::from_str("example.com").unwrap()), Ordering::Less);
    /// assert!(example_com.to_lowercase().eq_case(&Name::from_str("example.com").unwrap()));
    /// ```
    #[inline]
    fn to_lowercase<'a>(&'a self) -> CowName<'a> {
        if self.is_lowercase() {
            CowName::BorrowedName(self.borrowed_name())
        } else {
            let mut name = self.to_name();
            name.make_lowercase();

            CowName::Owned(name)
        }
    }

    /// returns true if the name components of self are all present at the end of name
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::domain::{DnsName, Name};
    ///
    /// let name = Name::from_str("www.example.com").unwrap();
    /// let name = Name::from_str("www.example.com").unwrap();
    /// let zone = Name::from_str("example.com").unwrap();
    /// let another = Name::from_str("example.net").unwrap();
    /// assert!(zone.zone_of(&name));
    /// assert!(!name.zone_of(&zone));
    /// assert!(!another.zone_of(&name));
    /// ```
    #[inline]
    fn zone_of(&self, name: &impl DnsName) -> bool
    where
        Self: Sized,
    {
        let self_lower = self.to_lowercase();
        let name_lower = name.to_lowercase();

        self_lower.zone_of_case(&name_lower)
    }

    /// same as `zone_of` allows for case sensitive call
    #[inline]
    fn zone_of_case(&self, name: &impl DnsName) -> bool
    where
        Self: Sized,
    {
        let self_len = self.num_labels();
        let name_len = name.num_labels();
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

        let self_iter = self.labels().rev();
        let name_iter = name.labels().rev();

        let zip_iter = self_iter.zip(name_iter);

        for (self_label, name_label) in zip_iter {
            if self_label != name_label {
                return false;
            }
        }

        true
    }

    /// Writes the labels, as lower case, to the encoder
    ///
    /// # Arguments
    ///
    /// * `encoder` - encoder for writing this name
    /// * `lowercase` - if true the name will be lowercased, otherwise it will not be changed when writing
    #[inline]
    fn emit_with_lowercase(&self, encoder: &mut BinEncoder, lowercase: bool) -> ProtoResult<()> {
        let is_canonical_names = encoder.is_canonical_names();
        if lowercase {
            self.to_lowercase()
                .emit_as_canonical(encoder, is_canonical_names)
        } else {
            self.emit_as_canonical(encoder, is_canonical_names)
        }
    }

    /// Returns true if the `Name` is either localhost or in the localhost zone.
    ///
    /// # Example
    ///
    /// ```
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::{DnsName, Name};
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
    #[inline]
    fn is_localhost(&self) -> bool
    where
        Self: Sized,
    {
        LOCALHOST_usage.zone_of(self)
    }

    /// True if the first label of this name is the wildcard, i.e. '*'
    ///
    /// # Example
    ///
    /// ```
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::{DnsName, Name};
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
    #[inline]
    fn is_wildcard(&self) -> bool {
        self.labels().next().map_or(false, |l| l.is_wildcard())
    }

    /// Converts a name to a wildcard, by replacing the first label with `*`
    ///
    /// # Example
    ///
    /// ```
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::{DnsName, Name, NameRef};
    ///
    /// let name = Name::from_str("www.example.com").unwrap();
    /// let name = name.into_wildcard();
    /// assert_eq!(name, Name::from_str("*.example.com.").unwrap());
    ///
    /// // does nothing if the root
    /// let name = NameRef::root();
    /// let name = name.into_wildcard();
    /// assert_eq!(name, Name::root());
    /// ```
    #[inline]
    fn into_wildcard<'a>(&'a self) -> CowName<'a> {
        // nothing to do if it already is the wildcard, or for root
        if self.is_wildcard() || self.is_root() {
            return self.borrowed_name().into();
        }

        // let mut name = Name::with_capacity(self.len());
        let mut name = Name::new();
        let wildcard = LabelRef::wildcard();

        name.push_label(wildcard.as_bytes());
        for label in self.labels().into_iter_with_root().skip(1) {
            name.push_label(label.as_bytes());
        }

        debug_assert_eq!(self.is_fqdn(), name.is_fqdn());
        name.into()
    }
}

// /// Encode the labels to `Write` using the `LabelEnc` for style.
// pub(crate) fn write_labels<W: Write, E: LabelEnc>(
//     f: &mut W,
//     labels: LabelIter,
//     is_root: bool,
//     is_fqdn: bool,
// ) -> Result<(), fmt::Error> {
//     let mut iter = labels;
//     if let Some(label) = iter.next() {
//         E::write_label(f, &label)?;
//     }

//     for label in iter {
//         write!(f, ".")?;
//         E::write_label(f, &label)?;
//     }

//     // if it was the root name
//     if is_root || is_fqdn {
//         write!(f, ".")?;
//     }
//     Ok(())
// }

pub(crate) fn write_labels<W: Write, E: LabelEnc, D: DnsName + ?Sized>(
    f: &mut W,
    name: &D,
) -> Result<(), fmt::Error> {
    let mut iter = name.labels();

    if let Some(label) = iter.next() {
        E::write_label(f, &label)?;
    }

    for label in iter {
        write!(f, ".")?;
        E::write_label(f, &label)?;
    }

    // if it was the root name
    if name.is_root() || name.is_fqdn() {
        write!(f, ".")?;
    }
    Ok(())
}

impl<'a> fmt::Display for &'a dyn DnsName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_labels::<fmt::Formatter, LabelEncUtf8, _>(f, *self)
    }
}

/// Case (optionally) insensitive comparison, see [`Name::cmp_case`] for case sensitive comparisons
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
pub(crate) fn cmp_with_f<F: LabelCmp, D1: DnsName + ?Sized, D2: DnsName + ?Sized>(
    this: &D1,
    other: &D2,
) -> Ordering {
    // we reverse the iters so that we are comparing from the root/domain to the local...
    let self_labels = this.labels().rev();
    let other_labels = other.labels().rev();

    let self_len = self_labels.len();
    let other_len = other_labels.len();

    for (l, r) in self_labels.zip(other_labels) {
        match l.cmp_with_f::<F>(&r) {
            Ordering::Equal => continue,
            not_eq => return not_eq,
        }
    }

    // not using "num_labels" here because that doesn't include wildcard in the count
    self_len.cmp(&other_len)
}

impl<N: DnsName + ?Sized> BinEncodable for N {
    fn emit(&self, encoder: &mut BinEncoder) -> ProtoResult<()> {
        let is_canonical_names = encoder.is_canonical_names();
        self.emit_as_canonical(encoder, is_canonical_names)
    }
}

impl<'a> ToOwned for BorrowedName<'a> {
    type Owned = Name;

    fn to_owned(&self) -> Self::Owned {
        self.to_name()
    }
}

impl<'a> Hash for BorrowedName<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.is_fqdn().hash(state);

        // this needs to be CaseInsensitive like PartialEq
        for l in self.labels() {
            let l: Cow<[u8]> = if l.is_lowercase() {
                Cow::Borrowed(l.as_bytes())
            } else {
                let mut l = l.to_label();
                l.make_lowercase();
                Cow::Owned(l.as_bytes().to_vec())
            };

            l.hash(state);
        }
    }
}

/// A reference to a different name type.
///
/// This is useful for comparing names in things like HashMaps
#[derive(Eq)]
#[repr(transparent)]
pub struct BorrowedName<'a>
where
    Self: 'a,
{
    labels: [&'a [u8]],
}

impl<'a> BorrowedName<'a>
where
    Self: 'a,
{
    /// Not on safety here, this mimics the the Path::new function in terms of pointer and reference conversion.
    ///
    /// It relies on the fact that BorrowedName is `repr(transparent)` over an array of array of labels.
    #[inline]
    #[allow(unsafe_code)]
    fn new(labels: &'a [&'a [u8]]) -> &'a BorrowedName<'a> {
        unsafe { std::mem::transmute(labels) }
    }
}

impl<'a> DnsName for BorrowedName<'a>
where
    Self: 'a,
{
    #[inline]
    fn labels(&self) -> LabelIter {
        LabelIter::from_borrowed(self)
    }

    #[inline]
    fn borrowed_name(&self) -> &BorrowedName {
        self
    }
}

impl<'a> fmt::Display for BorrowedName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_labels::<fmt::Formatter, LabelEncUtf8, _>(f, self)
    }
}

impl<'a, D: DnsName + ?Sized> PartialEq<D> for BorrowedName<'a> {
    #[inline]
    fn eq(&self, other: &D) -> bool {
        cmp_with_f::<CaseInsensitive, _, _>(self, other) == Ordering::Equal
    }
}

impl<'a, D: DnsName + ?Sized> PartialOrd<D> for BorrowedName<'a> {
    #[inline]
    fn partial_cmp(&self, other: &D) -> Option<Ordering> {
        Some(cmp_with_f::<CaseInsensitive, _, _>(self, other))
    }
}

impl<'a> Ord for BorrowedName<'a> {
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
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_with_f::<CaseInsensitive, _, _>(self, other)
    }
}

/// A Zero cost name referring to bytes owned by &str for example.
///
/// Note on storage: for fully-qualified-domain-names, fqdn, the final label will be a `.` or an empty array of bytes.
#[derive(Clone, Eq)]
pub struct NameRef<'a> {
    labels: Vec<&'a [u8]>,
}

impl<'a> DnsName for NameRef<'a> {
    #[inline]
    fn labels(&self) -> LabelIter {
        LabelIter::from_ref(self)
    }

    #[inline]
    fn borrowed_name<'b>(&'b self) -> &'b BorrowedName<'b> {
        BorrowedName::new(&self.labels)
    }
}

impl<'a> Borrow<BorrowedName<'a>> for NameRef<'a> {
    #[allow(unsafe_code)]
    fn borrow(&self) -> &BorrowedName<'a> {
        // This is a simple coercion from the concrete type to a trait object.
        unsafe { std::mem::transmute(BorrowedName::new(&self.labels)) }
    }
}

impl NameRef<'static> {
    /// Return the root label, i.e. `.`
    pub fn root() -> Self {
        NameRef {
            labels: vec![super::label::ROOT_LABEL],
        }
    }

    // /// get the internal name
    // pub fn as_bytes(&self) -> &[u8] {
    //     // this name may be longer than the ones captured (due to from_unparsed_slice)
    //     let start = self.label_offsets.first().map_or(0, |(start, _)| *start);
    //     let end = self.label_offsets.last().map_or(0, |(_, end)| *end);
    //     &self.name[start..end]
    // }
}

impl<'a> NameRef<'a> {
    /// Allocates a new slice, but no labels are defined
    pub(super) fn from_unparsed_slice(_slice: &'a [u8]) -> Self {
        NameRef { labels: vec![] }
    }

    /// Will convert the string to a name only allowing ascii as valid input
    ///
    /// This method will also preserve the case of the name where that's desirable
    ///
    /// # Examples
    ///
    /// ```
    /// use trust_dns_proto::rr::domain::{DnsName, NameRef};
    ///
    /// let ascii_name = NameRef::from_ascii("WWW.example.COM.").unwrap();
    /// let lower_name = NameRef::from_ascii("www.example.com.").unwrap();
    ///
    /// assert!(!lower_name.eq_case(&ascii_name));
    ///
    /// // escaped values are illegal for NameRef (require allocation)
    /// let name = NameRef::from_ascii("email\\.name.example.com.");
    ///
    /// assert!(name.is_err());
    ///
    /// // same here
    /// let name = NameRef::from_ascii("bad\\056char.example.com.");
    ///
    /// assert!(name.is_err());
    /// ```
    pub fn from_ascii(name: &'a str) -> ProtoResult<Self> {
        let cow = super::parse::from_encoded_str::<LabelEncAscii, Name>(name, None)?;
        cow.to_ref()
            .ok_or_else(|| ProtoError::from("non-basic ascii string"))
    }

    /// Pushes the new label, returns error if the label is not contained in the same slice as internal
    pub(super) fn push_label(&mut self, label: &'a [u8]) {
        debug_assert!(!label.is_empty(), "label must not be empty");
        self.labels.push(label);
    }

    /// Specifies this name is a fully qualified domain name
    ///
    /// *warning: this interface is unstable and may change in the future*
    pub(super) fn set_fqdn(&mut self, val: bool) {
        if val {
            // set the domain name
            if self
                .labels
                .last()
                .map(|l| l.as_ref() != super::label::ROOT_LABEL)
                .unwrap_or(true)
            {
                self.push_label(super::label::ROOT_LABEL);
            }
        } else {
            if self.is_fqdn() {
                self.labels.pop();
            }
        }
    }
}

impl<'a, D: DnsName + ?Sized> PartialEq<D> for NameRef<'a> {
    #[inline]
    fn eq(&self, other: &D) -> bool {
        cmp_with_f::<CaseInsensitive, _, _>(self, other) == Ordering::Equal
    }
}

impl<'a, D: DnsName + ?Sized> PartialOrd<D> for NameRef<'a> {
    #[inline]
    fn partial_cmp(&self, other: &D) -> Option<Ordering> {
        Some(cmp_with_f::<CaseInsensitive, _, _>(self, other))
    }
}

impl<'a> Ord for NameRef<'a> {
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
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_with_f::<CaseInsensitive, _, _>(self, other)
    }
}

impl<'a> fmt::Debug for NameRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_labels::<fmt::Formatter, LabelEncUtf8, _>(f, self)
    }
}

impl<'a> fmt::Display for NameRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_labels::<fmt::Formatter, LabelEncUtf8, _>(f, self)
    }
}

/// Them should be through references. As a workaround the Strings are all Rc as well as the array
#[derive(Clone, Default, Eq)]
pub struct Name {
    labels: Vec<Box<[u8]>>,
}

impl DnsName for Name {
    #[inline]
    fn labels(&self) -> LabelIter {
        LabelIter::new(self)
    }

    #[inline]
    #[allow(unsafe_code)]
    fn borrowed_name(&self) -> &BorrowedName {
        let labels = self.labels.as_slice();
        let labels = unsafe { std::mem::transmute(labels) };

        BorrowedName::new(labels)
    }
}

impl<'a> Borrow<BorrowedName<'a>> for Name {
    #[allow(unsafe_code)]
    fn borrow(&self) -> &BorrowedName<'a> {
        let labels = self.labels.as_slice();
        let labels = unsafe { std::mem::transmute(labels) };

        BorrowedName::new(labels)
    }
}

impl Name {
    /// Create a new domain::Name, i.e. label
    pub fn new() -> Self {
        Default::default()
    }

    /// Specifies this name is a fully qualified domain name
    ///
    /// *warning: this interface is unstable and may change in the future*
    pub(super) fn set_fqdn(&mut self, val: bool) {
        if val {
            // set the domain name
            if !self.is_fqdn() {
                self.push_label(super::label::ROOT_LABEL);
            }
        } else {
            if self.is_fqdn() {
                self.labels.pop();
            }
        }
    }

    // /// Same as default, but with capacity reserved of len
    // pub fn with_capacity(size: usize) -> Self {
    //     Name {
    //         is_fqdn: false,
    //         name: Vec::with_capacity(size),
    //         label_offsets: Default::default(),
    //     }
    // }

    // /// Return this Name as bytes
    // pub fn as_bytes(&self) -> &[u8] {
    //     &self.name
    // }

    /// Returns the root label, i.e. no labels, can probably make this better in the future.
    pub fn root() -> Self {
        let mut this = Self::new();
        this.set_fqdn(true);
        this
    }

    /// Returns an iterator over the labels
    pub fn iter(&self) -> LabelIter {
        LabelIter::new(self)
    }

    pub(super) fn push_label<I: Into<Box<[u8]>>>(&mut self, label: I) {
        let label = label.into();
        debug_assert!(!label.is_empty(), "label can not be empty");

        if !label.is_empty() {
            self.labels.push(label);
        }
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
        self.push_label(label.into_label()?.as_bytes());
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
    /// use trust_dns_proto::rr::domain::{DnsLabel, Name, DnsName};
    ///
    /// // From strings, uses utf8 conversion
    /// let from_labels = Name::from_labels(vec!["www", "example", "com"]).unwrap();
    /// assert_eq!(from_labels, Name::from_str("www.example.com").unwrap());
    ///
    /// // Force a set of bytes into labels (this is none-standard and potentially dangerous)
    /// let from_labels = Name::from_labels(vec!["bad chars".as_bytes(), "example".as_bytes(), "com".as_bytes()]).unwrap();
    /// assert_eq!(from_labels[0], *b"bad chars");
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
        let errors: Vec<_> = errors.into_iter().map(Result::unwrap_err).collect();

        if labels.len() > 255 {
            return Err("labels exceed maximum length of 255".into());
        };
        if !errors.is_empty() {
            return Err(format!("error converting some labels: {:?}", errors).into());
        };

        // get the name and the label offsets
        let mut name: Name =
            labels
                .into_iter()
                .map(Result::unwrap)
                .fold(Name::new(), |mut name, label| {
                    name.push_label(label.as_bytes());
                    name
                });
        name.set_fqdn(true);

        Ok(name)
    }

    /// Appends `other` to `self`, returning a new `Name`
    ///
    /// Carries forward `is_fqdn` from `other`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::domain::{DnsName, Name};
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
    pub fn append_name(mut self, other: &impl DnsName) -> Self {
        for label in other.labels().into_iter_with_root() {
            self.push_label(label.as_bytes());
        }

        debug_assert_eq!(self.is_fqdn(), other.is_fqdn());
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
    /// use trust_dns_proto::rr::domain::{DnsName, Name};
    ///
    /// let local = Name::from_str("www").unwrap();
    /// let domain = Name::from_str("example.com").unwrap();
    /// let name = local.append_domain(&domain);
    /// assert_eq!(name, Name::from_str("www.example.com").unwrap());
    /// assert!(name.is_fqdn())
    /// ```
    pub fn append_domain(self, domain: &impl DnsName) -> Self {
        let mut this = self.append_name(domain);
        this.push_label(super::label::ROOT_LABEL);
        this
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
    /// use trust_dns_proto::rr::domain::{DnsName, Name};
    ///
    /// let mut name = Name::from_str("www").unwrap();
    /// let domain = Name::from_str("example.com").unwrap();
    /// name.append_domain2(&domain);
    /// assert_eq!(name, Name::from_str("www.example.com").unwrap());
    /// assert!(name.is_fqdn())
    /// ```
    pub fn append_domain2<D: DnsName + ?Sized>(&mut self, domain: &D) {
        for label in domain.labels() {
            self.push_label(label.as_bytes());
        }

        self.push_label(super::label::ROOT_LABEL);
    }

    /// Makes this name lowercased, in place
    ///
    /// # Examples
    ///
    /// ```
    /// use std::cmp::Ordering;
    /// use std::str::FromStr;
    ///
    /// use trust_dns_proto::rr::domain::{Label, Name, DnsName};
    ///
    /// let mut example_com = Name::from_ascii("Example.Com").unwrap().to_name();
    /// assert_eq!(example_com.cmp_case(&Name::from_str("example.com").unwrap()), Ordering::Less);
    /// example_com.make_lowercase();
    /// assert!(example_com.eq_case(&Name::from_str("example.com").unwrap()));
    /// ```
    pub fn make_lowercase(&mut self) {
        self.labels
            .iter_mut()
            .for_each(|label| label.make_ascii_lowercase());
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
    pub fn base_name(&self) -> Self {
        let sub = if self.is_fqdn() { 2 } else { 1 };

        let length = self.labels.len();
        if length >= sub {
            return self.trim_to(length - sub);
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
        let mut name = Name::default();
        let skip_first = (self.num_labels() as usize).saturating_sub(num_labels);

        for label in self.iter().into_iter_with_root().skip(skip_first) {
            name.push_label(label.as_bytes());
        }

        debug_assert_eq!(self.is_fqdn(), name.is_fqdn());
        name
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
        let dots = self.labels().count();

        // this would be root
        if dots == 0 {
            return 1;
        };

        self.labels().fold(dots, |acc, label| acc + label.len())
    }

    /// attempts to parse a name such as `"example.com."` or `"subdomain.example.com."`
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::domain::{Name, DnsLabel};
    ///
    /// let name = Name::from_str("example.com.").unwrap();
    /// assert_eq!(name.base_name(), Name::from_str("com.").unwrap());
    /// assert_eq!(name[0], *b"example");
    /// ```
    pub fn parse<'a, 'b: 'a, D: DnsName + ?Sized>(
        local: &'a str,
        // TODO: change D to BorrowedName
        origin: Option<&'b D>,
    ) -> ProtoResult<Self> {
        Self::from_encoded_str::<LabelEncUtf8, D>(local, origin).map(Into::into)
    }

    /// Will convert the string to a name only allowing ascii as valid input
    ///
    /// This method will also preserve the case of the name where that's desirable
    ///
    /// # Examples
    ///
    /// ```
    /// use trust_dns_proto::rr::{DnsName, Name};
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
    pub fn from_ascii<'a>(name: &'a str) -> ProtoResult<CowName<'a>> {
        Self::from_encoded_str::<LabelEncAscii, Name>(name.as_ref(), None)
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
    /// use trust_dns_proto::rr::{DnsName, Name};
    ///
    /// let bytes_name = Name::from_labels(vec!["WWW".as_bytes(), "example".as_bytes(), "COM".as_bytes()]).unwrap();
    ///
    /// // from_str calls through to from_utf8
    /// let utf8_name = Name::from_str("WWW.example.COM.").unwrap();
    /// let lower_name = Name::from_str("www.example.com.").unwrap();
    ///
    /// assert!(bytes_name.eq_case(&utf8_name));
    /// assert!(!lower_name.eq_case(&utf8_name));
    /// ```
    pub fn from_utf8<'a>(name: &'a str) -> ProtoResult<CowName<'a>> {
        Self::from_encoded_str::<LabelEncUtf8, Name>(name.as_ref(), None)
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
    /// // Ok, underscore in the end
    /// assert!(Name::from_utf8("dis_allowed.example.com.").is_ok());
    ///
    /// // Ok, relaxed mode
    /// assert!(Name::from_str_relaxed("allow_in_.example.com.").is_ok());
    /// ```
    pub fn from_str_relaxed(name: &str) -> ProtoResult<Self> {
        Self::from_utf8(name)
            .or_else(|_| Self::from_ascii(name))
            .map(Into::into)
    }

    fn from_encoded_str<'a, 'b: 'a, E: super::parse::LabelEnc, D: DnsName + ?Sized>(
        local: &'a str,
        origin: Option<&'b D>,
    ) -> ProtoResult<CowName<'a>> {
        super::parse::from_encoded_str::<E, D>(local, origin)
    }
}

/// An iterator over labels in a name
pub struct LabelIter<'a> {
    labels: std::slice::Iter<'a, &'a [u8]>,
    len: usize,
}

impl<'a> LabelIter<'a> {
    #[inline]
    fn from_borrowed(name: &'a BorrowedName<'a>) -> LabelIter<'a> {
        // Warning, do not call is_fqdn here, as that uses labels (which this function is called in)
        let len = if name
            .labels
            .last()
            .map_or(false, |l| *l == super::label::ROOT_LABEL)
        {
            name.labels.len().saturating_sub(1)
        } else {
            name.labels.len()
        };

        Self {
            labels: name.labels.iter(),
            len,
        }
    }

    #[inline]
    fn from_ref(name: &'a NameRef<'a>) -> LabelIter<'a> {
        Self::from_borrowed(name.borrowed_name())
    }

    #[inline]
    fn new(name: &'a Name) -> LabelIter<'a> {
        Self::from_borrowed(name.borrowed_name())
    }

    fn into_iter_with_root(self) -> WithRootLabelIter<'a> {
        WithRootLabelIter::from(self.labels)
    }
}

impl<'a> Iterator for LabelIter<'a> {
    type Item = LabelRef<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.labels.next().map(|l| LabelRef::from_unchecked(*l)) {
                Some(l) if !l.is_root() => return Some(l),
                None => return None,
                _ => continue,
            }
        }
    }
}

impl<'a> ExactSizeIterator for LabelIter<'a> {
    fn len(&self) -> usize {
        self.len
    }
}

impl<'a> DoubleEndedIterator for LabelIter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        loop {
            match self
                .labels
                .next_back()
                .map(|l| LabelRef::from_unchecked(*l))
            {
                Some(l) if !l.is_root() => return Some(l),
                None => return None,
                _ => continue,
            }
        }
    }
}

struct WithRootLabelIter<'a> {
    labels: std::slice::Iter<'a, &'a [u8]>,
}

impl<'a> WithRootLabelIter<'a> {
    fn from(labels: std::slice::Iter<'a, &'a [u8]>) -> Self {
        WithRootLabelIter { labels }
    }
}

impl<'a> Iterator for WithRootLabelIter<'a> {
    type Item = LabelRef<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.labels.next().map(|l| LabelRef::from_unchecked(l))
    }
}

impl<'a> IntoIterator for &'a Name {
    type Item = LabelRef<'a>;
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

impl<D: DnsName + ?Sized> PartialEq<D> for Name {
    fn eq(&self, other: &D) -> bool {
        cmp_with_f::<CaseInsensitive, _, _>(self, other) == Ordering::Equal
    }
}

impl Hash for Name {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.is_fqdn().hash(state);

        // this needs to be CaseInsensitive like PartialEq
        for l in self.iter() {
            let l: Cow<[u8]> = if l.is_lowercase() {
                Cow::Borrowed(l.as_bytes())
            } else {
                let mut l = l.to_label();
                l.make_lowercase();
                Cow::Owned(l.as_bytes().to_vec())
            };

            l.hash(state);
        }
    }
}

impl<'r> BinDecodable<'r> for Name {
    /// parses the chain of labels
    ///  this has a max of 255 octets, with each label being less than 63.
    ///  all names will be stored lowercase internally.
    /// This will consume the portions of the `Vec` which it is reading...
    #[inline]
    fn read(decoder: &mut BinDecoder<'r>) -> ProtoResult<Name> {
        read_inner(decoder, None)
    }
}

fn read_inner<'r>(decoder: &mut BinDecoder<'r>, max_idx: Option<usize>) -> ProtoResult<Name> {
    let mut state: LabelParseState = LabelParseState::LabelLengthOrPointer;
    let mut labels: Name = Name::default(); // most labels will be around three, e.g. www.example.com
    let name_start = decoder.index();

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
        if labels.len() > 255 {
            return Err(ProtoErrorKind::DomainNameTooLong(labels.len()).into());
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

                labels.push_label(label.into_label()?.as_bytes());

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

                for l in pointed.iter() {
                    labels.push_label(l.as_bytes());
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

    // enforce max length of name
    if labels.len() > 255 {
        return Err(ProtoErrorKind::DomainNameTooLong(labels.len()).into());
    }

    let mut name = labels;
    name.set_fqdn(true);

    Ok(name)
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_labels::<fmt::Formatter, LabelEncUtf8, _>(f, self)
    }
}

impl Index<usize> for Name {
    type Output = [u8];

    fn index(&self, index: usize) -> &[u8] {
        &self.labels[index]
    }
}

impl<D: DnsName + ?Sized> PartialOrd<D> for Name {
    #[inline]
    fn partial_cmp(&self, other: &D) -> Option<Ordering> {
        Some(cmp_with_f::<CaseInsensitive, _, _>(self, other))
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
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_with_f::<CaseInsensitive, _, _>(self, other)
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
        Name::from_str_relaxed(s).map(|n| n.into())
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
        Name::from_utf8(self).map(|n| n.into())
    }
}

impl IntoName for String {
    /// Performs a utf8, IDNA or punycode, translation of the `String` into `Name`
    fn into_name(self) -> ProtoResult<Name> {
        Name::from_utf8(&self).map(|n| n.into())
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

    #[test]
    fn test_dns_name_is_object_safe() {
        let name = NameRef {
            labels: vec![b"www", b"."],
        };
        let dyn_name = &name as &dyn DnsName;

        assert_eq!(name.labels().next().unwrap().as_bytes(), b"www");
        assert_eq!(dyn_name.labels().next().unwrap().as_bytes(), b"www");
    }

    #[test]
    fn test_hash_mappable_name() {}

    #[test]
    fn test_labels_iter() {
        let name = Name::from_str("www.example.com.").unwrap();
        let mut iter = name.labels();

        assert_eq!(LabelRef::from_unchecked(b"www"), iter.next().unwrap());
        assert_eq!(LabelRef::from_unchecked(b"example"), iter.next().unwrap());
        assert_eq!(LabelRef::from_unchecked(b"com"), iter.next().unwrap());
    }

    #[test]
    fn test_labels_rev_iter() {
        let name = Name::from_str("www.example.com.").unwrap();
        let mut iter = name.labels().rev();

        assert_eq!(LabelRef::from_unchecked(b"com"), iter.next().unwrap());
        assert_eq!(LabelRef::from_unchecked(b"example"), iter.next().unwrap());
        assert_eq!(LabelRef::from_unchecked(b"www"), iter.next().unwrap());
    }

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
    fn test_name_ref_push_label() {
        use crate::rr::domain::NameRef;

        let label = b"www.example.com.";
        let mut name = NameRef::from_unparsed_slice(label);
        assert!(name.labels().next().is_none());

        name.push_label(&label[0..3]);
        assert_eq!(
            name.labels().next().expect("should be www").as_bytes(),
            b"www"
        );
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
    fn test_wildcard_equality() {
        use std::cmp::PartialOrd;

        assert!(Name::from_ascii("*.example.com.").unwrap().is_wildcard());
        assert!(!Name::from_ascii("www.example.com.").unwrap().is_wildcard());
        assert_eq!(
            Name::from_ascii("*.example.com").unwrap(),
            Name::from_ascii("*.example.com").unwrap()
        );
        assert_ne!(
            Name::from_ascii("*.example.com").unwrap(),
            Name::from_ascii("www.example.com").unwrap()
        );
        assert_ne!(
            Name::from_ascii("*.example.com").unwrap(),
            Name::from_ascii("example.com").unwrap()
        );
        assert_eq!(
            Name::from_ascii("example.com")
                .unwrap()
                .partial_cmp(&Name::from_ascii("*.example.com").unwrap()),
            Some(Ordering::Less)
        );
        assert_eq!(
            Name::from_ascii("*.example.com")
                .unwrap()
                .partial_cmp(&Name::from_ascii("www.example.com").unwrap()),
            Some(Ordering::Less)
        );
        assert_eq!(
            Name::from_ascii("*.example.com")
                .unwrap()
                .partial_cmp(&Name::from_ascii("*.multi.example.com").unwrap()),
            Some(Ordering::Less)
        );
        assert_eq!(
            Name::from_ascii("*.example.com")
                .unwrap()
                .partial_cmp(&Name::from_ascii("label.multi.example.com").unwrap()),
            Some(Ordering::Less)
        );
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
    fn test_pointer_with_pointer_ending_labels() {
        let mut bytes: Vec<u8> = Vec::with_capacity(512);

        let first = Name::from_str("ra.rb.rc").unwrap();
        let second = Name::from_str("ra.rc").unwrap();
        let third = Name::from_str("ra.rc").unwrap();

        {
            let mut e = BinEncoder::new(&mut bytes);

            first.emit(&mut e).unwrap();
            assert_eq!(e.len(), 10);

            second.emit(&mut e).unwrap();
            // +5 with the first +3 being the text form of "ra" and +2 for the pointer to "rc".
            assert_eq!(e.len(), 15);

            // +2 with the pointer to "ra.rc" as previously seen.
            third.emit(&mut e).unwrap();
            assert_eq!(e.len(), 17);
        }

        // now read them back
        let mut d = BinDecoder::new(&bytes);

        let r_test = Name::read(&mut d).unwrap();
        assert_eq!(first, r_test);

        let r_test = Name::read(&mut d).unwrap();
        assert_eq!(second, r_test);

        let r_test = Name::read(&mut d).unwrap();
        assert_eq!(third, r_test);
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
                Name::parse("example.", root.as_ref().map(|r| r as &dyn DnsName))
                    .unwrap()
                    .to_name(),
                Name::parse("example", root.as_ref().map(|r| r as &dyn DnsName))
                    .unwrap()
                    .to_name(),
            ),
        ];

        for (left, right) in comparisons {
            println!("left: {}, right: {}", left, right);
            assert_eq!(left.partial_cmp(&right), Some(Ordering::Equal));
        }
    }

    #[test]
    fn test_partial_cmp() {
        let comparisons: Vec<(CowName, CowName)> = vec![
            (
                Name::from_str("example.").unwrap().into(),
                Name::from_str("a.example.").unwrap().into(),
            ),
            (
                Name::from_str("a.example.").unwrap().into(),
                Name::from_str("yljkjljk.a.example.").unwrap().into(),
            ),
            (
                Name::from_str("yljkjljk.a.example.").unwrap().into(),
                Name::from_ascii("Z.a.example.").unwrap().into(),
            ),
            (
                Name::from_ascii("Z.a.example.").unwrap().into(),
                Name::from_ascii("zABC.a.EXAMPLE").unwrap().into(),
            ),
            (
                Name::from_ascii("zABC.a.EXAMPLE.").unwrap().into(),
                Name::from_str("z.example.").unwrap().into(),
            ),
            (
                Name::from_str("z.example.").unwrap().into(),
                Name::from_labels(vec![&[1u8] as &[u8], b"z", b"example"])
                    .unwrap()
                    .into(),
            ),
            (
                Name::from_labels(vec![&[1u8] as &[u8], b"z", b"example"])
                    .unwrap()
                    .into(),
                Name::from_str("*.z.example.").unwrap().into(),
            ),
            (
                Name::from_str("*.z.example.").unwrap().into(),
                Name::from_labels(vec![&[200u8] as &[u8], b"z", b"example"])
                    .unwrap()
                    .into(),
            ),
        ];

        for (left, right) in comparisons {
            println!("left: {}, right: {}", left, right);
            assert!(left < right);
        }
    }

    #[test]
    fn test_cmp_ignore_case() {
        let comparisons: Vec<(CowName, CowName)> = vec![
            (
                Name::from_ascii("ExAmPle.").unwrap().into(),
                Name::from_ascii("example.").unwrap().into(),
            ),
            (
                Name::from_ascii("A.example.").unwrap().into(),
                Name::from_ascii("a.example.").unwrap().into(),
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
        assert!(!dbg!(lower_name).eq_case(&dbg!(ascii_name)));
    }

    #[test]
    fn test_from_utf8() {
        let bytes_name = Name::from_labels(vec![b"WWW" as &[u8], b"example", b"COM"]).unwrap();
        let utf8_name = Name::from_utf8("WWW.example.COM.").unwrap();
        let lower_name = Name::from_utf8("www.example.com.").unwrap();

        assert!(bytes_name.eq_case(&utf8_name));
        assert!(!lower_name.eq_case(&utf8_name));
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
            "WWW.example.COM."
        );
        assert_eq!(
            Name::from_ascii("WWW.example.COM.").unwrap().to_utf8(),
            "WWW.example.COM."
        );
        assert_eq!(
            Name::from_ascii("email\\.name.example.com.")
                .unwrap()
                .to_utf8(),
            "email\\.name.example.com."
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
            let name = Name::from_ascii(&format!("name{}.example.com.", i))
                .unwrap()
                .to_name();
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

    #[test]
    fn test_parse_arpa_name() {
        assert!(Name::from_ascii("168.192.in-addr.arpa")
            .unwrap()
            .parse_arpa_name()
            .is_err());
        assert!(Name::from_ascii("host.example.com.")
            .unwrap()
            .parse_arpa_name()
            .is_err());
        assert!(Name::from_ascii("caffee.ip6.arpa.")
            .unwrap()
            .parse_arpa_name()
            .is_err());
        assert!(Name::from_ascii(
            "1.4.3.3.7.0.7.3.0.E.2.A.8.9.1.3.1.3.D.8.0.3.A.5.8.8.B.D.0.1.0.0.2.ip6.arpa."
        )
        .unwrap()
        .parse_arpa_name()
        .is_err());
        assert!(Name::from_ascii("caffee.in-addr.arpa.")
            .unwrap()
            .parse_arpa_name()
            .is_err());
        assert!(Name::from_ascii("1.2.3.4.5.in-addr.arpa.")
            .unwrap()
            .parse_arpa_name()
            .is_err());
        assert!(Name::from_ascii("1.2.3.4.home.arpa.")
            .unwrap()
            .parse_arpa_name()
            .is_err());
        assert_eq!(
            Name::from_ascii("168.192.in-addr.arpa.")
                .unwrap()
                .parse_arpa_name()
                .unwrap(),
            IpNet::V4(Ipv4Net::new("192.168.0.0".parse().unwrap(), 16).unwrap())
        );
        assert_eq!(
            Name::from_ascii("1.0.168.192.in-addr.arpa.")
                .unwrap()
                .parse_arpa_name()
                .unwrap(),
            IpNet::V4(Ipv4Net::new("192.168.0.1".parse().unwrap(), 32).unwrap())
        );
        assert_eq!(
            Name::from_ascii("0.1.0.0.2.ip6.arpa.")
                .unwrap()
                .parse_arpa_name()
                .unwrap(),
            IpNet::V6(Ipv6Net::new("2001::".parse().unwrap(), 20).unwrap())
        );
        assert_eq!(
            Name::from_ascii("D.0.1.0.0.2.ip6.arpa.")
                .unwrap()
                .parse_arpa_name()
                .unwrap(),
            IpNet::V6(Ipv6Net::new("2001:d00::".parse().unwrap(), 24).unwrap())
        );
        assert_eq!(
            Name::from_ascii("B.D.0.1.0.0.2.ip6.arpa.")
                .unwrap()
                .parse_arpa_name()
                .unwrap(),
            IpNet::V6(Ipv6Net::new("2001:db0::".parse().unwrap(), 28).unwrap())
        );
        assert_eq!(
            Name::from_ascii("8.B.D.0.1.0.0.2.ip6.arpa.")
                .unwrap()
                .parse_arpa_name()
                .unwrap(),
            IpNet::V6(Ipv6Net::new("2001:db8::".parse().unwrap(), 32).unwrap())
        );
        assert_eq!(
            Name::from_ascii(
                "4.3.3.7.0.7.3.0.E.2.A.8.9.1.3.1.3.D.8.0.3.A.5.8.8.B.D.0.1.0.0.2.ip6.arpa."
            )
            .unwrap()
            .parse_arpa_name()
            .unwrap(),
            IpNet::V6(
                Ipv6Net::new("2001:db8:85a3:8d3:1319:8a2e:370:7334".parse().unwrap(), 128).unwrap()
            )
        );
    }
}
