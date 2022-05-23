/*
 * Copyright (C) 2016 Benjamin Fry <benjaminfry@me.com>
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

//! public key record data for signing zone records
#![allow(clippy::use_self)]

use std::fmt;

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use crate::error::*;
use crate::rr::dnssec::Algorithm;
use crate::rr::record_data::RData;
use crate::serialize::binary::*;

/// [RFC 2535](https://tools.ietf.org/html/rfc2535#section-3), Domain Name System Security Extensions, March 1999
///
/// ```text
/// 3. The KEY Resource Record
///
///    The KEY resource record (RR) is used to store a public key that is
///    associated with a Domain Name System (DNS) name.  This can be the
///    public key of a zone, a user, or a host or other end entity. Security
///    aware DNS implementations MUST be designed to handle at least two
///    simultaneously valid keys of the same type associated with the same
///    name.
///
///    The type number for the KEY RR is 25.
///
///    A KEY RR is, like any other RR, authenticated by a SIG RR.  KEY RRs
///    must be signed by a zone level key.
///
/// 3.1 KEY RDATA format
///
///    The RDATA for a KEY RR consists of flags, a protocol octet, the
///    algorithm number octet, and the public key itself.  The format is as
///    follows:
///
///                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |             flags             |    protocol   |   algorithm   |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |                                                               /
///    /                          public key                           /
///    /                                                               /
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
///
///    The KEY RR is not intended for storage of certificates and a separate
///    certificate RR has been developed for that purpose, defined in [RFC
///    2538].
///
///    The meaning of the KEY RR owner name, flags, and protocol octet are
///    described in Sections 3.1.1 through 3.1.5 below.  The flags and
///    algorithm must be examined before any data following the algorithm
///    octet as they control the existence and format of any following data.
///    The algorithm and public key fields are described in Section 3.2.
///    The format of the public key is algorithm dependent.
///
///    KEY RRs do not specify their validity period but their authenticating
///    SIG RR(s) do as described in Section 4 below.
///
/// 3.1.1 Object Types, DNS Names, and Keys
///
///    The public key in a KEY RR is for the object named in the owner name.
///
///    A DNS name may refer to three different categories of things.  For
///    example, foo.host.example could be (1) a zone, (2) a host or other
///    end entity , or (3) the mapping into a DNS name of the user or
///    account foo@host.example.  Thus, there are flag bits, as described
///    below, in the KEY RR to indicate with which of these roles the owner
///    name and public key are associated.  Note that an appropriate zone
///    KEY RR MUST occur at the apex node of a secure zone and zone KEY RRs
///    occur only at delegation points.
///
/// 3.1.2 The KEY RR Flag Field
///
///    In the "flags" field:
///
///      0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
///    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
///    |  A/C  | Z | XT| Z | Z | NAMTYP| Z | Z | Z | Z |      SIG      |
///    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
///
///    Bit 0 and 1 are the key "type" bits whose values have the following
///    meanings:
///
///            10: Use of the key is prohibited for authentication.
///            01: Use of the key is prohibited for confidentiality.
///            00: Use of the key for authentication and/or confidentiality
///                is permitted. Note that DNS security makes use of keys
///                for authentication only. Confidentiality use flagging is
///                provided for use of keys in other protocols.
///                Implementations not intended to support key distribution
///                for confidentiality MAY require that the confidentiality
///                use prohibited bit be on for keys they serve.
///            11: If both bits are one, the "no key" value, there is no key
///                information and the RR stops after the algorithm octet.
///                By the use of this "no key" value, a signed KEY RR can
///                authenticatably assert that, for example, a zone is not
///                secured.  See section 3.4 below.
///
///    Bits 2 is reserved and must be zero.
///
///    Bits 3 is reserved as a flag extension bit.  If it is a one, a second
///           16 bit flag field is added after the algorithm octet and
///           before the key data.  This bit MUST NOT be set unless one or
///           more such additional bits have been defined and are non-zero.
///
///    Bits 4-5 are reserved and must be zero.
///
///    Bits 6 and 7 form a field that encodes the name type. Field values
///    have the following meanings:
///
///            00: indicates that this is a key associated with a "user" or
///                "account" at an end entity, usually a host.  The coding
///                of the owner name is that used for the responsible
///                individual mailbox in the SOA and RP RRs: The owner name
///                is the user name as the name of a node under the entity
///                name.  For example, "j_random_user" on
///                host.subdomain.example could have a public key associated
///                through a KEY RR with name
///                j_random_user.host.subdomain.example.  It could be used
///                in a security protocol where authentication of a user was
///                desired.  This key might be useful in IP or other
///                security for a user level service such a telnet, ftp,
///                rlogin, etc.
///            01: indicates that this is a zone key for the zone whose name
///                is the KEY RR owner name.  This is the public key used
///                for the primary DNS security feature of data origin
///                authentication.  Zone KEY RRs occur only at delegation
///                points.
///            10: indicates that this is a key associated with the non-zone
///                "entity" whose name is the RR owner name.  This will
///                commonly be a host but could, in some parts of the DNS
///                tree, be some other type of entity such as a telephone
///                number [RFC 1530] or numeric IP address.  This is the
///                public key used in connection with DNS request and
///                transaction authentication services.  It could also be
///                used in an IP-security protocol where authentication at
///                the host, rather than user, level was desired, such as
///                routing, NTP, etc.
///            11: reserved.
///
///    Bits 8-11 are reserved and must be zero.
///
///    Bits 12-15 are the "signatory" field.  If non-zero, they indicate
///               that the key can validly sign things as specified in DNS
///               dynamic update [RFC 2137].  Note that zone keys (see bits
///               6 and 7 above) always have authority to sign any RRs in
///               the zone regardless of the value of the signatory field.
/// ```
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct KEY {
    key_trust: KeyTrust,
    key_usage: KeyUsage,
    signatory: UpdateScope,
    protocol: Protocol,
    algorithm: Algorithm,
    public_key: Vec<u8>,
}

/// Specifies in what contexts this key may be trusted for use
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum KeyTrust {
    /// Use of the key is prohibited for authentication
    NotAuth,
    /// Use of the key is prohibited for confidentiality
    NotPrivate,
    /// Use of the key for authentication and/or confidentiality is permitted
    AuthOrPrivate,
    /// If both bits are one, the "no key" value, (revocation?)
    DoNotTrust,
}

impl Default for KeyTrust {
    fn default() -> Self {
        Self::AuthOrPrivate
    }
}

impl From<u16> for KeyTrust {
    fn from(flags: u16) -> Self {
        // we only care about the first two bits, zero out the rest
        match flags & 0b1100_0000_0000_0000 {
            // 10: Use of the key is prohibited for authentication.
            0b1000_0000_0000_0000 => Self::NotAuth,
            // 01: Use of the key is prohibited for confidentiality.
            0b0100_0000_0000_0000 => Self::NotPrivate,
            // 00: Use of the key for authentication and/or confidentiality
            0b0000_0000_0000_0000 => Self::AuthOrPrivate,
            // 11: If both bits are one, the "no key" value, there is no key
            0b1100_0000_0000_0000 => Self::DoNotTrust,
            _ => panic!("All other bit fields should have been cleared"),
        }
    }
}

impl From<KeyTrust> for u16 {
    fn from(key_trust: KeyTrust) -> Self {
        match key_trust {
            // 10: Use of the key is prohibited for authentication.
            KeyTrust::NotAuth => 0b1000_0000_0000_0000,
            // 01: Use of the key is prohibited for confidentiality.
            KeyTrust::NotPrivate => 0b0100_0000_0000_0000,
            // 00: Use of the key for authentication and/or confidentiality
            KeyTrust::AuthOrPrivate => 0b0000_0000_0000_0000,
            // 11: If both bits are one, the "no key" value, there is no key
            KeyTrust::DoNotTrust => 0b1100_0000_0000_0000,
        }
    }
}

#[test]
fn test_key_trust() {
    assert_eq!(
        KeyTrust::NotAuth,
        KeyTrust::from(u16::from(KeyTrust::NotAuth))
    );
    assert_eq!(
        KeyTrust::NotPrivate,
        KeyTrust::from(u16::from(KeyTrust::NotPrivate))
    );
    assert_eq!(
        KeyTrust::AuthOrPrivate,
        KeyTrust::from(u16::from(KeyTrust::AuthOrPrivate))
    );
    assert_eq!(
        KeyTrust::DoNotTrust,
        KeyTrust::from(u16::from(KeyTrust::DoNotTrust))
    );
}

/// Declares what this key is for
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
pub enum KeyUsage {
    /// key associated with a "user" or "account" at an end entity, usually a host
    Host,
    /// zone key for the zone whose name is the KEY RR owner name
    #[deprecated = "For Zone signing DNSKEY should be used"]
    Zone,
    /// associated with the non-zone "entity" whose name is the RR owner name
    Entity,
    /// Reserved
    Reserved,
}

impl Default for KeyUsage {
    fn default() -> Self {
        Self::Entity
    }
}

impl From<u16> for KeyUsage {
    fn from(flags: u16) -> Self {
        // we only care about the 6&7 two bits, zero out the rest
        match flags & 0b0000_0011_0000_0000 {
            // 00: indicates that this is a key associated with a "user" or
            0b0000_0000_0000_0000 => Self::Host,
            // 01: indicates that this is a zone key for the zone whose name
            0b0000_0001_0000_0000 => Self::Zone,
            // 10: indicates that this is a key associated with the non-zone
            0b0000_0010_0000_0000 => Self::Entity,
            // 11: reserved.
            0b0000_0011_0000_0000 => Self::Reserved,
            _ => panic!("All other bit fields should have been cleared"),
        }
    }
}

impl From<KeyUsage> for u16 {
    fn from(key_usage: KeyUsage) -> Self {
        match key_usage {
            // 00: indicates that this is a key associated with a "user" or
            KeyUsage::Host => 0b0000_0000_0000_0000,
            // 01: indicates that this is a zone key for the zone whose name
            KeyUsage::Zone => 0b0000_0001_0000_0000,
            // 10: indicates that this is a key associated with the non-zone
            KeyUsage::Entity => 0b0000_0010_0000_0000,
            // 11: reserved.
            KeyUsage::Reserved => 0b0000_0011_0000_0000,
        }
    }
}

#[test]

fn test_key_usage() {
    assert_eq!(KeyUsage::Host, KeyUsage::from(u16::from(KeyUsage::Host)));
    assert_eq!(KeyUsage::Zone, KeyUsage::from(u16::from(KeyUsage::Zone)));
    assert_eq!(
        KeyUsage::Entity,
        KeyUsage::from(u16::from(KeyUsage::Entity))
    );
    assert_eq!(
        KeyUsage::Reserved,
        KeyUsage::from(u16::from(KeyUsage::Reserved))
    );
}

/// [RFC 2137](https://tools.ietf.org/html/rfc2137#section-3.1), Secure Domain Name System Dynamic Update, April 1997
///
/// ```text
/// 3.1.1 Update Key Name Scope
///
///    The owner name of any update authorizing KEY RR must (1) be the same
///    as the owner name of any RRs being added or deleted or (2) a wildcard
///    name including within its extended scope (see section 3.3) the name
///    of any RRs being added or deleted and those RRs must be in the same
///    zone.
///
/// 3.1.2 Update Key Class Scope
///
///    The class of any update authorizing KEY RR must be the same as the
///    class of any RR's being added or deleted.
///
/// 3.1.3 Update Key Signatory Field
///
///    The four bit "signatory field" (see RFC 2065) of any update
///    authorizing KEY RR must be non-zero.  The bits have the meanings
///    described below for non-zone keys (see section 3.2 for zone type
///    keys).
///
///            UPDATE KEY RR SIGNATORY FIELD BITS
///
///          0           1           2           3
///    +-----------+-----------+-----------+-----------+
///    |   zone    |  strong   |  unique   |  general  |
///    +-----------+-----------+-----------+-----------+
///
///    Bit 0, zone control - If nonzero, this key is authorized to attach,
///         detach, and move zones by creating and deleting NS, glue A, and
///         zone KEY RR(s).  If zero, the key can not authorize any update
///         that would effect such RRs.  This bit is meaningful for both
///         type A and type B dynamic secure zones.
///
///         NOTE:  do not confuse the "zone" signatory field bit with the
///         "zone" key type bit.
///
///    Bit 1, strong update - If nonzero, this key is authorized to add and
///         delete RRs even if there are other RRs with the same owner name
///         and class that are authenticated by a SIG signed with a
///         different dynamic update KEY. If zero, the key can only
///         authorize updates where any existing RRs of the same owner and
///         class are authenticated by a SIG using the same key.  This bit
///         is meaningful only for type A dynamic zones and is ignored in
///         type B dynamic zones.
///
///         Keeping this bit zero on multiple KEY RRs with the same or
///         nested wild card owner names permits multiple entities to exist
///         that can create and delete names but can not effect RRs with
///         different owner names from any they created.  In effect, this
///         creates two levels of dynamic update key, strong and weak, where
///         weak keys are limited in interfering with each other but a
///         strong key can interfere with any weak keys or other strong
///         keys.
///
///    Bit 2, unique name update - If nonzero, this key is authorized to add
///         and update RRs for only a single owner name.  If there already
///         exist RRs with one or more names signed by this key, they may be
///         updated but no new name created until the number of existing
///         names is reduced to zero.  This bit is meaningful only for mode
///         A dynamic zones and is ignored in mode B dynamic zones. This bit
///         is meaningful only if the owner name is a wildcard.  (Any
///         dynamic update KEY with a non-wildcard name is, in effect, a
///         unique name update key.)
///
///         This bit can be used to restrict a KEY from flooding a zone with
///         new names.  In conjunction with a local administratively imposed
///         limit on the number of dynamic RRs with a particular name, it
///         can completely restrict a KEY from flooding a zone with RRs.
///
///    Bit 3, general update - The general update signatory field bit has no
///         special meaning.  If the other three bits are all zero, it must
///         be one so that the field is non-zero to designate that the key
///         is an update key.  The meaning of all values of the signatory
///         field with the general bit and one or more other signatory field
///         bits on is reserved.
///
///    All the signatory bit update authorizations described above only
///    apply if the update is within the name and class scope as per
///    sections 3.1.1 and 3.1.2.
/// ```
///
/// [RFC 3007](https://tools.ietf.org/html/rfc3007#section-1.5), Secure Dynamic Update, November 2000
///
/// ```text
///    [RFC2535, section 3.1.2] defines the signatory field of a key as the
///    final 4 bits of the flags field, but does not define its value.  This
///    proposal leaves this field undefined.  Updating [RFC2535], this field
///    SHOULD be set to 0 in KEY records, and MUST be ignored.
///
/// ```
#[deprecated = "Deprecated by RFC3007"]
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone, Copy)]
pub struct UpdateScope {
    /// this key is authorized to attach,
    ///   detach, and move zones by creating and deleting NS, glue A, and
    ///   zone KEY RR(s)
    pub zone: bool,
    /// this key is authorized to add and
    ///   delete RRs even if there are other RRs with the same owner name
    ///   and class that are authenticated by a SIG signed with a
    ///   different dynamic update KEY
    pub strong: bool,
    /// this key is authorized to add and update RRs for only a single owner name
    pub unique: bool,
    /// The general update signatory field bit has no special meaning, (true if the others are false)
    pub general: bool,
}

impl From<u16> for UpdateScope {
    fn from(flags: u16) -> Self {
        // we only care about the final four bits, zero out the rest
        Self {
            //    Bit 0, zone control - If nonzero, this key is authorized to attach,
            zone: flags & 0b0000_0000_0000_1000 != 0,
            //    Bit 1, strong update - If nonzero, this key is authorized to add and
            strong: flags & 0b0000_0000_0000_0100 != 0,
            //    Bit 2, unique name update - If nonzero, this key is authorized to add
            unique: flags & 0b0000_0000_0000_0010 != 0,
            //    Bit 3, general update - The general update signatory field bit has no
            general: flags & 0b0000_0000_0000_0001 != 0,
        }
    }
}

impl From<UpdateScope> for u16 {
    fn from(update_scope: UpdateScope) -> Self {
        let mut flags = 0_u16;

        if update_scope.zone {
            flags |= 0b0000_0000_0000_1000;
        }

        if update_scope.strong {
            flags |= 0b0000_0000_0000_0100;
        }

        if update_scope.unique {
            flags |= 0b0000_0000_0000_0010;
        }

        if update_scope.general {
            flags |= 0b0000_0000_0000_0001;
        }

        flags
    }
}

#[test]
fn test_update_scope() {
    assert_eq!(
        UpdateScope::default(),
        UpdateScope::from(u16::from(UpdateScope::default()))
    );

    let update_scope = UpdateScope {
        zone: true,
        strong: true,
        unique: true,
        general: true,
    };
    assert_eq!(update_scope, UpdateScope::from(u16::from(update_scope)));

    let update_scope = UpdateScope {
        zone: true,
        strong: false,
        unique: true,
        general: false,
    };
    assert_eq!(update_scope, UpdateScope::from(u16::from(update_scope)));

    let update_scope = UpdateScope {
        zone: false,
        strong: true,
        unique: false,
        general: true,
    };
    assert_eq!(update_scope, UpdateScope::from(u16::from(update_scope)));

    let update_scope = UpdateScope {
        zone: false,
        strong: true,
        unique: true,
        general: false,
    };
    assert_eq!(update_scope, UpdateScope::from(u16::from(update_scope)));

    let update_scope = UpdateScope {
        zone: true,
        strong: false,
        unique: false,
        general: true,
    };
    assert_eq!(update_scope, UpdateScope::from(u16::from(update_scope)));
}

/// [RFC 2535](https://tools.ietf.org/html/rfc2535#section-3.1.3), Domain Name System Security Extensions, March 1999
///
/// ```text
/// 3.1.3 The Protocol Octet
///
///    It is anticipated that keys stored in DNS will be used in conjunction
///    with a variety of Internet protocols.  It is intended that the
///    protocol octet and possibly some of the currently unused (must be
///    zero) bits in the KEY RR flags as specified in the future will be
///    used to indicate a key's validity for different protocols.
///
///    The following values of the Protocol Octet are reserved as indicated:
///
///         VALUE   Protocol
///
///           0      -reserved
///           1     TLS
///           2     email
///           3     dnssec
///           4     IPSEC
///          5-254   - available for assignment by IANA
///          255     All
///
///    In more detail:
///         1 is reserved for use in connection with TLS.
///         2 is reserved for use in connection with email.
///         3 is used for DNS security.  The protocol field SHOULD be set to
///           this value for zone keys and other keys used in DNS security.
///           Implementations that can determine that a key is a DNS
///           security key by the fact that flags label it a zone key or the
///           signatory flag field is non-zero are NOT REQUIRED to check the
///           protocol field.
///         4 is reserved to refer to the Oakley/IPSEC [RFC 2401] protocol
///           and indicates that this key is valid for use in conjunction
///           with that security standard.  This key could be used in
///           connection with secured communication on behalf of an end
///           entity or user whose name is the owner name of the KEY RR if
///           the entity or user flag bits are set.  The presence of a KEY
///           resource with this protocol value is an assertion that the
///           host speaks Oakley/IPSEC.
///         255 indicates that the key can be used in connection with any
///           protocol for which KEY RR protocol octet values have been
///           defined.  The use of this value is discouraged and the use of
///           different keys for different protocols is encouraged.
/// ```
///
/// [RFC3445](https://tools.ietf.org/html/rfc3445#section-4), Limiting the KEY Resource Record (RR), December 2002
///
/// ```text
/// All Protocol Octet values except DNSSEC (3) are eliminated
/// ```
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Protocol {
    /// Not in use
    #[deprecated = "Deprecated by RFC3445"]
    Reserved,
    /// Reserved for use with TLS
    #[deprecated = "Deprecated by RFC3445"]
    TLS,
    /// Reserved for use with email
    #[deprecated = "Deprecated by RFC3445"]
    Email,
    /// Reserved for use with DNSSec (Trust-DNS only supports DNSKEY with DNSSec)
    DNSSec,
    /// Reserved to refer to the Oakley/IPSEC
    #[deprecated = "Deprecated by RFC3445"]
    IPSec,
    /// Undefined
    #[deprecated = "Deprecated by RFC3445"]
    Other(u8),
    /// the key can be used in connection with any protocol
    #[deprecated = "Deprecated by RFC3445"]
    All,
}

impl Default for Protocol {
    fn default() -> Self {
        Self::DNSSec
    }
}

impl From<u8> for Protocol {
    fn from(field: u8) -> Self {
        match field {
            0 => Self::Reserved,
            1 => Self::TLS,
            2 => Self::Email,
            3 => Self::DNSSec,
            4 => Self::IPSec,
            255 => Self::All,
            _ => Self::Other(field),
        }
    }
}

impl From<Protocol> for u8 {
    fn from(protocol: Protocol) -> Self {
        match protocol {
            Protocol::Reserved => 0,
            Protocol::TLS => 1,
            Protocol::Email => 2,
            Protocol::DNSSec => 3,
            Protocol::IPSec => 4,
            Protocol::All => 255,
            Protocol::Other(field) => field,
        }
    }
}

impl KEY {
    /// Construct a new KEY RData
    ///
    /// # Arguments
    ///
    /// * `key_trust` - declare the security level of this key
    /// * `key_usage` - what type of thing is this key associated to
    /// * `revoke` - this key has been revoked
    /// * `algorithm` - specifies the algorithm which this Key uses to sign records
    /// * `public_key` - the public key material, in native endian, the emitter will perform any necessary conversion
    ///
    /// # Return
    ///
    /// A new KEY RData for use in a Resource Record
    pub fn new(
        key_trust: KeyTrust,
        key_usage: KeyUsage,
        signatory: UpdateScope,
        protocol: Protocol,
        algorithm: Algorithm,
        public_key: Vec<u8>,
    ) -> Self {
        Self {
            key_trust,
            key_usage,
            signatory,
            protocol,
            algorithm,
            public_key,
        }
    }

    /// Returns the trust level of the key
    pub fn key_trust(&self) -> KeyTrust {
        self.key_trust
    }

    /// Returns the entity type using this key
    pub fn key_usage(&self) -> KeyUsage {
        self.key_usage
    }

    /// Returns the signatory information of the KEY
    pub fn signatory(&self) -> UpdateScope {
        self.signatory
    }

    /// Returns true if the key_trust is DoNotTrust
    pub fn revoke(&self) -> bool {
        self.key_trust == KeyTrust::DoNotTrust
    }

    /// Returns the protocol which this key can be used with
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// [RFC 4034, DNSSEC Resource Records, March 2005](https://tools.ietf.org/html/rfc4034#section-2.1.3)
    ///
    /// ```text
    /// 2.1.3.  The Algorithm Field
    ///
    ///    The Algorithm field identifies the public key's cryptographic
    ///    algorithm and determines the format of the Public Key field.  A list
    ///    of DNSSEC algorithm types can be found in Appendix A.1
    /// ```
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// [RFC 4034, DNSSEC Resource Records, March 2005](https://tools.ietf.org/html/rfc4034#section-2.1.4)
    ///
    /// ```text
    /// 2.1.4.  The Public Key Field
    ///
    ///    The Public Key Field holds the public key material.  The format
    ///    depends on the algorithm of the key being stored and is described in
    ///    separate documents.
    /// ```
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Output the encoded form of the flags
    pub fn flags(&self) -> u16 {
        let mut flags: u16 = 0;
        flags |= u16::from(self.key_trust);
        flags |= u16::from(self.key_usage);
        flags |= u16::from(self.signatory);

        flags
    }

    // /// Creates a message digest for this KEY record.
    // ///
    // /// ```text
    // /// 5.1.4.  The Digest Field
    // ///
    // ///    The DS record refers to a KEY RR by including a digest of that
    // ///    KEY RR.
    // ///
    // ///    The digest is calculated by concatenating the canonical form of the
    // ///    fully qualified owner name of the KEY RR with the KEY RDATA,
    // ///    and then applying the digest algorithm.
    // ///
    // ///      digest = digest_algorithm( KEY owner name | KEY RDATA);
    // ///
    // ///       "|" denotes concatenation
    // ///
    // ///      KEY RDATA = Flags | Protocol | Algorithm | Public Key.
    // ///
    // ///    The size of the digest may vary depending on the digest algorithm and
    // ///    KEY RR size.  As of the time of this writing, the only defined
    // ///    digest algorithm is SHA-1, which produces a 20 octet digest.
    // /// ```
    // ///
    // /// # Arguments
    // ///
    // /// * `name` - the label of of the KEY record.
    // /// * `digest_type` - the `DigestType` with which to create the message digest.
    // pub fn to_digest(&self, name: &Name, digest_type: DigestType) -> ProtoResult<Vec<u8>> {
    //     let mut buf: Vec<u8> = Vec::new();
    //     {
    //         let mut encoder: BinEncoder = BinEncoder::new(&mut buf);
    //         encoder.set_canonical_names(true);
    //         if let Err(e) = name.emit(&mut encoder)
    //                .and_then(|_| emit(&mut encoder, self)) {
    //             warn!("error serializing KEY: {}", e);
    //             return Err(format!("error serializing KEY: {}", e).into());
    //         }
    //     }

    //     digest_type.hash(&buf).map_err(|e| e.into())
    // }
}

impl From<KEY> for RData {
    fn from(key: KEY) -> Self {
        Self::DNSSEC(super::DNSSECRData::KEY(key))
    }
}

/// Read the RData from the given Decoder
pub fn read(decoder: &mut BinDecoder<'_>, rdata_length: Restrict<u16>) -> ProtoResult<KEY> {
    //      0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
    //    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    //    |  A/C  | Z | XT| Z | Z | NAMTYP| Z | Z | Z | Z |      SIG      |
    //    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    let flags: u16 = decoder
        .read_u16()?
        .verify_unwrap(|flags| {
            //    Bits 2 is reserved and must be zero.
            //    Bits 4-5 are reserved and must be zero.
            //    Bits 8-11 are reserved and must be zero.
            flags & 0b0010_1100_1111_0000 == 0
        })
        .map_err(|_| ProtoError::from("flag 2, 4-5, and 8-11 are reserved, must be zero"))?;

    let key_trust = KeyTrust::from(flags);
    let extended_flags: bool = flags & 0b0001_0000_0000_0000 != 0;
    let key_usage = KeyUsage::from(flags);
    let signatory = UpdateScope::from(flags);

    if extended_flags {
        // TODO: add an optional field to return the raw u16?
        return Err("extended flags currently not supported".into());
    }

    // TODO: protocol my be infallible
    let protocol = Protocol::from(decoder.read_u8()?.unverified(/*Protocol is verified as safe*/));

    let algorithm: Algorithm = Algorithm::read(decoder)?;

    // the public key is the left-over bytes minus 4 for the first fields
    // TODO: decode the key here?
    let key_len = rdata_length
        .map(|u| u as usize)
        .checked_sub(4)
        .map_err(|_| ProtoError::from("invalid rdata length in KEY"))?
        .unverified(/*used only as length safely*/);
    let public_key: Vec<u8> =
        decoder.read_vec(key_len)?.unverified(/*the byte array will fail in usage if invalid*/);

    Ok(KEY::new(
        key_trust, key_usage, signatory, protocol, algorithm, public_key,
    ))
}

/// Write the RData from the given Decoder
pub fn emit(encoder: &mut BinEncoder<'_>, rdata: &KEY) -> ProtoResult<()> {
    encoder.emit_u16(rdata.flags())?;
    encoder.emit(u8::from(rdata.protocol))?;
    rdata.algorithm().emit(encoder)?;
    encoder.emit_vec(rdata.public_key())?;

    Ok(())
}

/// Note that KEY is a deprecated type in DNS
///
/// [RFC 2535](https://tools.ietf.org/html/rfc2535#section-7.1), Domain Name System Security Extensions, March 1999
///
/// ```text
/// 7.1 Presentation of KEY RRs
///
///    KEY RRs may appear as single logical lines in a zone data master file
///    [RFC 1033].
///
///    The flag field is represented as an unsigned integer or a sequence of
///    mnemonics as follows separated by instances of the verticle bar ("|")
///    character:
///
///      BIT  Mnemonic  Explanation
///     0-1           key type
///         NOCONF    =1 confidentiality use prohibited
///         NOAUTH    =2 authentication use prohibited
///         NOKEY     =3 no key present
///     2   FLAG2     - reserved
///     3   EXTEND    flags extension
///     4   FLAG4     - reserved
///     5   FLAG5     - reserved
///     6-7           name type
///         USER      =0 (default, may be omitted)
///         ZONE      =1
///         HOST      =2 (host or other end entity)
///         NTYP3     - reserved
///     8   FLAG8     - reserved
///     9   FLAG9     - reserved
///    10   FLAG10    - reserved
///    11   FLAG11    - reserved
///    12-15          signatory field, values 0 to 15
///             can be represented by SIG0, SIG1, ... SIG15
///
///    No flag mnemonic need be present if the bit or field it represents is
///    zero.
///
///    The protocol octet can be represented as either an unsigned integer
///    or symbolicly.  The following initial symbols are defined:
///
///         000    NONE
///         001    TLS
///         002    EMAIL
///         003    DNSSEC
///         004    IPSEC
///         255    ALL
///
///    Note that if the type flags field has the NOKEY value, nothing
///    appears after the algorithm octet.
///
///    The remaining public key portion is represented in base 64 (see
///    Appendix A) and may be divided up into any number of white space
///    separated substrings, down to single base 64 digits, which are
///    concatenated to obtain the full signature.  These substrings can span
///    lines using the standard parenthesis.
///
///    Note that the public key may have internal sub-fields but these do
///    not appear in the master file representation.  For example, with
///    algorithm 1 there is a public exponent size, then a public exponent,
///    and then a modulus.  With algorithm 254, there will be an OID size,
///    an OID, and algorithm dependent information. But in both cases only a
///    single logical base 64 string will appear in the master file.
/// ```
impl fmt::Display for KEY {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{flags} {proto} {alg} {key}",
            flags = self.flags(),
            proto = u8::from(self.protocol),
            alg = self.algorithm,
            key = data_encoding::BASE64.encode(&self.public_key)
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;

    #[test]
    fn test() {
        let rdata = KEY::new(
            KeyTrust::default(),
            KeyUsage::default(),
            UpdateScope::default(),
            Protocol::default(),
            Algorithm::RSASHA256,
            vec![0, 1, 2, 3, 4, 5, 6, 7],
        );

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        assert!(emit(&mut encoder, &rdata).is_ok());
        let bytes = encoder.into_bytes();

        println!("bytes: {:?}", bytes);

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let restrict = Restrict::new(bytes.len() as u16);
        let read_rdata = read(&mut decoder, restrict).expect("Decoding error");
        assert_eq!(rdata, read_rdata);
        // #[cfg(any(feature = "openssl", feature = "ring"))]
        // assert!(rdata
        //             .to_digest(&Name::parse("www.example.com.", None).unwrap(),
        //                        DigestType::SHA256)
        //             .is_ok());
    }
}
