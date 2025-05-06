// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! signer is a structure for performing many of the signing processes of the DNSSEC specification
use alloc::{boxed::Box, vec::Vec};
use core::time::Duration;

use tracing::debug;

use super::{DnsSecResult, SigningKey};
use crate::{
    dnssec::{
        TBS,
        rdata::{DNSKEY, DNSSECRData, KEY, SIG},
        tbs,
    },
    error::{ProtoErrorKind, ProtoResult},
    op::{Message, MessageSignature, MessageSigner, MessageVerifier},
    rr::{
        Record, {DNSClass, Name, RData, RecordType},
    },
    serialize::binary::{BinEncodable, BinEncoder},
};

/// Use for performing signing and validation of DNSSEC based components. The SigSigner can be used for singing requests and responses with SIG0, or DNSSEC RRSIG records. The format is based on the SIG record type.
///
/// TODO: warning this struct and it's impl are under high volatility, expect breaking changes
///
/// [RFC 4035](https://tools.ietf.org/html/rfc4035), DNSSEC Protocol Modifications, March 2005
///
/// ```text
/// 5.3.  Authenticating an RRset with an RRSIG RR
///
///    A validator can use an RRSIG RR and its corresponding DNSKEY RR to
///    attempt to authenticate RRsets.  The validator first checks the RRSIG
///    RR to verify that it covers the RRset, has a valid time interval, and
///    identifies a valid DNSKEY RR.  The validator then constructs the
///    canonical form of the signed data by appending the RRSIG RDATA
///    (excluding the Signature Field) with the canonical form of the
///    covered RRset.  Finally, the validator uses the public key and
///    signature to authenticate the signed data.  Sections 5.3.1, 5.3.2,
///    and 5.3.3 describe each step in detail.
///
/// 5.3.1.  Checking the RRSIG RR Validity
///
///    A security-aware resolver can use an RRSIG RR to authenticate an
///    RRset if all of the following conditions hold:
///
///    o  The RRSIG RR and the RRset MUST have the same owner name and the
///       same class.
///
///    o  The RRSIG RR's Signer's Name field MUST be the name of the zone
///       that contains the RRset.
///
///    o  The RRSIG RR's Type Covered field MUST equal the RRset's type.
///
///    o  The number of labels in the RRset owner name MUST be greater than
///       or equal to the value in the RRSIG RR's Labels field.
///
///    o  The validator's notion of the current time MUST be less than or
///       equal to the time listed in the RRSIG RR's Expiration field.
///
///    o  The validator's notion of the current time MUST be greater than or
///       equal to the time listed in the RRSIG RR's Inception field.
///
///    o  The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST
///       match the owner name, algorithm, and key tag for some DNSKEY RR in
///       the zone's apex DNSKEY RRset.
///
///    o  The matching DNSKEY RR MUST be present in the zone's apex DNSKEY
///       RRset, and MUST have the Zone Flag bit (DNSKEY RDATA Flag bit 7)
///       set.
///
///    It is possible for more than one DNSKEY RR to match the conditions
///    above.  In this case, the validator cannot predetermine which DNSKEY
///    RR to use to authenticate the signature, and it MUST try each
///    matching DNSKEY RR until either the signature is validated or the
///    validator has run out of matching public keys to try.
///
///    Note that this authentication process is only meaningful if the
///    validator authenticates the DNSKEY RR before using it to validate
///    signatures.  The matching DNSKEY RR is considered to be authentic if:
///
///    o  the apex DNSKEY RRset containing the DNSKEY RR is considered
///       authentic; or
///
///    o  the RRset covered by the RRSIG RR is the apex DNSKEY RRset itself,
///       and the DNSKEY RR either matches an authenticated DS RR from the
///       parent zone or matches a trust anchor.
///
/// 5.3.2.  Reconstructing the Signed Data
///
///    Once the RRSIG RR has met the validity requirements described in
///    Section 5.3.1, the validator has to reconstruct the original signed
///    data.  The original signed data includes RRSIG RDATA (excluding the
///    Signature field) and the canonical form of the RRset.  Aside from
///    being ordered, the canonical form of the RRset might also differ from
///    the received RRset due to DNS name compression, decremented TTLs, or
///    wildcard expansion.  The validator should use the following to
///    reconstruct the original signed data:
///
///          signed_data = RRSIG_RDATA | RR(1) | RR(2)...  where
///
///             "|" denotes concatenation
///
///             RRSIG_RDATA is the wire format of the RRSIG RDATA fields
///                with the Signature field excluded and the Signer's Name
///                in canonical form.
///
///             RR(i) = name | type | class | OrigTTL | RDATA length | RDATA
///
///                name is calculated according to the function below
///
///                class is the RRset's class
///
///                type is the RRset type and all RRs in the class
///
///                OrigTTL is the value from the RRSIG Original TTL field
///
///                All names in the RDATA field are in canonical form
///
///                The set of all RR(i) is sorted into canonical order.
///
///             To calculate the name:
///                let rrsig_labels = the value of the RRSIG Labels field
///
///                let fqdn = RRset's fully qualified domain name in
///                                canonical form
///
///                let fqdn_labels = Label count of the fqdn above.
///
///                if rrsig_labels = fqdn_labels,
///                    name = fqdn
///
///                if rrsig_labels < fqdn_labels,
///                   name = "*." | the rightmost rrsig_label labels of the
///                                 fqdn
///
///                if rrsig_labels > fqdn_labels
///                   the RRSIG RR did not pass the necessary validation
///                   checks and MUST NOT be used to authenticate this
///                   RRset.
///
///    The canonical forms for names and RRsets are defined in [RFC4034].
///
///    NSEC RRsets at a delegation boundary require special processing.
///    There are two distinct NSEC RRsets associated with a signed delegated
///    name.  One NSEC RRset resides in the parent zone, and specifies which
///    RRsets are present at the parent zone.  The second NSEC RRset resides
///    at the child zone and identifies which RRsets are present at the apex
///    in the child zone.  The parent NSEC RRset and child NSEC RRset can
///    always be distinguished as only a child NSEC RR will indicate that an
///    SOA RRset exists at the name.  When reconstructing the original NSEC
///    RRset for the delegation from the parent zone, the NSEC RRs MUST NOT
///    be combined with NSEC RRs from the child zone.  When reconstructing
///    the original NSEC RRset for the apex of the child zone, the NSEC RRs
///    MUST NOT be combined with NSEC RRs from the parent zone.
///
///    Note that each of the two NSEC RRsets at a delegation point has a
///    corresponding RRSIG RR with an owner name matching the delegated
///    name, and each of these RRSIG RRs is authoritative data associated
///    with the same zone that contains the corresponding NSEC RRset.  If
///    necessary, a resolver can tell these RRSIG RRs apart by checking the
///    Signer's Name field.
///
/// 5.3.3.  Checking the Signature
///
///    Once the resolver has validated the RRSIG RR as described in Section
///    5.3.1 and reconstructed the original signed data as described in
///    Section 5.3.2, the validator can attempt to use the cryptographic
///    signature to authenticate the signed data, and thus (finally!)
///    authenticate the RRset.
///
///    The Algorithm field in the RRSIG RR identifies the cryptographic
///    algorithm used to generate the signature.  The signature itself is
///    contained in the Signature field of the RRSIG RDATA, and the public
///    key used to verify the signature is contained in the Public Key field
///    of the matching DNSKEY RR(s) (found in Section 5.3.1).  [RFC4034]
///    provides a list of algorithm types and provides pointers to the
///    documents that define each algorithm's use.
///
///    Note that it is possible for more than one DNSKEY RR to match the
///    conditions in Section 5.3.1.  In this case, the validator can only
///    determine which DNSKEY RR is correct by trying each matching public
///    key until the validator either succeeds in validating the signature
///    or runs out of keys to try.
///
///    If the Labels field of the RRSIG RR is not equal to the number of
///    labels in the RRset's fully qualified owner name, then the RRset is
///    either invalid or the result of wildcard expansion.  The resolver
///    MUST verify that wildcard expansion was applied properly before
///    considering the RRset to be authentic.  Section 5.3.4 describes how
///    to determine whether a wildcard was applied properly.
///
///    If other RRSIG RRs also cover this RRset, the local resolver security
///    policy determines whether the resolver also has to test these RRSIG
///    RRs and how to resolve conflicts if these RRSIG RRs lead to differing
///    results.
///
///    If the resolver accepts the RRset as authentic, the validator MUST
///    set the TTL of the RRSIG RR and each RR in the authenticated RRset to
///    a value no greater than the minimum of:
///
///    o  the RRset's TTL as received in the response;
///
///    o  the RRSIG RR's TTL as received in the response;
///
///    o  the value in the RRSIG RR's Original TTL field; and
///
///    o  the difference of the RRSIG RR's Signature Expiration time and the
///       current time.
///
/// 5.3.4.  Authenticating a Wildcard Expanded RRset Positive Response
///
///    If the number of labels in an RRset's owner name is greater than the
///    Labels field of the covering RRSIG RR, then the RRset and its
///    covering RRSIG RR were created as a result of wildcard expansion.
///    Once the validator has verified the signature, as described in
///    Section 5.3, it must take additional steps to verify the non-
///    existence of an exact match or closer wildcard match for the query.
///    Section 5.4 discusses these steps.
///
///    Note that the response received by the resolver should include all
///    NSEC RRs needed to authenticate the response (see Section 3.1.3).
/// ```
pub struct SigSigner {
    // TODO: this should really be a trait and generic struct over KEY and DNSKEY
    key_rdata: RData,
    key: Box<dyn SigningKey>,
    signer_name: Name,
    sig_duration: Duration,
    is_zone_signing_key: bool,
}

impl SigSigner {
    /// Version of Signer for verifying RRSIGs and SIG0 records.
    ///
    /// # Arguments
    ///
    /// * `key_rdata` - the DNSKEY and public key material
    /// * `key` - the private key for signing, unless validating, where just the public key is necessary
    /// * `signer_name` - name in the zone to which this DNSKEY is bound
    /// * `sig_duration` - time period for which this key is valid, 0 when verifying
    /// * `is_zone_update_auth` - this key may be used for updating the zone
    pub fn dnssec(
        key_rdata: DNSKEY,
        key: Box<dyn SigningKey>,
        signer_name: Name,
        sig_duration: Duration,
    ) -> Self {
        Self {
            is_zone_signing_key: key_rdata.zone_key(),
            key_rdata: key_rdata.into(),
            key,
            signer_name,
            sig_duration,
        }
    }

    /// Version of Signer for verifying RRSIGs and SIG0 records.
    ///
    /// # Arguments
    ///
    /// * `key_rdata` - the KEY and public key material
    /// * `key` - the private key for signing, unless validating, where just the public key is necessary
    /// * `signer_name` - name in the zone to which this DNSKEY is bound
    /// * `is_zone_update_auth` - this key may be used for updating the zone
    pub fn sig0(key_rdata: KEY, key: Box<dyn SigningKey>, signer_name: Name) -> Self {
        Self {
            key_rdata: key_rdata.into(),
            key,
            signer_name,
            sig_duration: Duration::ZERO,
            is_zone_signing_key: false,
        }
    }

    /// Version of Signer for signing RRSIGs and SIG0 records.
    #[deprecated(note = "use SIG0 or DNSSEC constructors")]
    pub fn new(
        key: Box<dyn SigningKey>,
        signer_name: Name,
        sig_duration: Duration,
        is_zone_signing_key: bool,
        _: bool,
    ) -> Self {
        let pub_key = key.to_public_key().expect("key is not a private key");
        let dnskey = DNSKEY::from_key(&pub_key);

        Self {
            key_rdata: dnskey.into(),
            key,
            signer_name,
            sig_duration,
            is_zone_signing_key,
        }
    }

    /// Return the key used for validation/signing
    pub fn key(&self) -> &dyn SigningKey {
        &*self.key
    }

    /// Returns the duration that this signature is valid for
    pub fn sig_duration(&self) -> Duration {
        self.sig_duration
    }

    /// A hint to the DNSKey associated with this Signer can be used to sign/validate records in the zone
    pub fn is_zone_signing_key(&self) -> bool {
        self.is_zone_signing_key
    }

    /// Signs a hash.
    ///
    /// This will panic if the `key` is not a private key and can be used for signing.
    ///
    /// # Arguments
    ///
    /// * `hash` - the hashed resource record set, see `rrset_tbs`.
    ///
    /// # Return value
    ///
    /// The signature, ready to be stored in an `RData::RRSIG`.
    pub fn sign(&self, tbs: &TBS) -> ProtoResult<Vec<u8>> {
        self.key
            .sign(tbs)
            .map_err(|e| ProtoErrorKind::Msg(format!("signing error: {e}")).into())
    }

    /// The name of the signing entity, e.g. the DNS server name.
    ///
    /// This should match the name on key in the zone.
    pub fn signer_name(&self) -> &Name {
        &self.signer_name
    }

    // TODO: move this to DNSKEY/KEY?
    /// The key tag is calculated as a hash to more quickly lookup a DNSKEY.
    ///
    /// ```text
    /// RFC 2535                DNS Security Extensions               March 1999
    ///
    /// 4.1.6 Key Tag Field
    ///
    ///  The "key Tag" is a two octet quantity that is used to efficiently
    ///  select between multiple keys which may be applicable and thus check
    ///  that a public key about to be used for the computationally expensive
    ///  effort to check the signature is possibly valid.  For algorithm 1
    ///  (MD5/RSA) as defined in [RFC 2537], it is the next to the bottom two
    ///  octets of the public key modulus needed to decode the signature
    ///  field.  That is to say, the most significant 16 of the least
    ///  significant 24 bits of the modulus in network (big endian) order. For
    ///  all other algorithms, including private algorithms, it is calculated
    ///  as a simple checksum of the KEY RR as described in Appendix C.
    ///
    /// Appendix C: Key Tag Calculation
    ///
    ///  The key tag field in the SIG RR is just a means of more efficiently
    ///  selecting the correct KEY RR to use when there is more than one KEY
    ///  RR candidate available, for example, in verifying a signature.  It is
    ///  possible for more than one candidate key to have the same tag, in
    ///  which case each must be tried until one works or all fail.  The
    ///  following reference implementation of how to calculate the Key Tag,
    ///  for all algorithms other than algorithm 1, is in ANSI C.  It is coded
    ///  for clarity, not efficiency.  (See section 4.1.6 for how to determine
    ///  the Key Tag of an algorithm 1 key.)
    ///
    ///  /* assumes int is at least 16 bits
    ///     first byte of the key tag is the most significant byte of return
    ///     value
    ///     second byte of the key tag is the least significant byte of
    ///     return value
    ///     */
    ///
    ///  int keytag (
    ///
    ///          unsigned char key[],  /* the RDATA part of the KEY RR */
    ///          unsigned int keysize, /* the RDLENGTH */
    ///          )
    ///  {
    ///  long int    ac;    /* assumed to be 32 bits or larger */
    ///
    ///  for ( ac = 0, i = 0; i < keysize; ++i )
    ///      ac += (i&1) ? key[i] : key[i]<<8;
    ///  ac += (ac>>16) & 0xFFFF;
    ///  return ac & 0xFFFF;
    ///  }
    /// ```
    pub fn calculate_key_tag(&self) -> ProtoResult<u16> {
        let mut bytes: Vec<u8> = Vec::with_capacity(512);
        {
            let mut e = BinEncoder::new(&mut bytes);
            self.key_rdata.emit(&mut e)?;
        }
        Ok(DNSKEY::calculate_key_tag_internal(&bytes))
    }

    /// Signs the given message, returning the signature bytes.
    ///
    /// # Arguments
    ///
    /// * `message` - the message to sign
    ///
    /// [rfc2535](https://tools.ietf.org/html/rfc2535#section-4.1.8.1), Domain Name System Security Extensions, 1999
    ///
    /// ```text
    /// 4.1.8.1 Calculating Transaction and Request SIGs
    ///
    ///  A response message from a security aware server may optionally
    ///  contain a special SIG at the end of the additional information
    ///  section to authenticate the transaction.
    ///
    ///  This SIG has a "type covered" field of zero, which is not a valid RR
    ///  type.  It is calculated by using a "data" (see Section 4.1.8) of the
    ///  entire preceding DNS reply message, including DNS header but not the
    ///  IP header and before the reply RR counts have been adjusted for the
    ///  inclusion of any transaction SIG, concatenated with the entire DNS
    ///  query message that produced this response, including the query's DNS
    ///  header and any request SIGs but not its IP header.  That is
    ///
    ///  data = full response (less transaction SIG) | full query
    ///
    ///  Verification of the transaction SIG (which is signed by the server
    ///  host key, not the zone key) by the requesting resolver shows that the
    ///  query and response were not tampered with in transit, that the
    ///  response corresponds to the intended query, and that the response
    ///  comes from the queried server.
    ///
    ///  A DNS request may be optionally signed by including one or more SIGs
    ///  at the end of the query. Such SIGs are identified by having a "type
    ///  covered" field of zero. They sign the preceding DNS request message
    ///  including DNS header but not including the IP header or any request
    ///  SIGs at the end and before the request RR counts have been adjusted
    ///  for the inclusions of any request SIG(s).
    ///
    ///  WARNING: Request SIGs are unnecessary for any currently defined
    ///  request other than update [RFC 2136, 2137] and will cause some old
    ///  DNS servers to give an error return or ignore a query.  However, such
    ///  SIGs may in the future be needed for other requests.
    ///
    ///  Except where needed to authenticate an update or similar privileged
    ///  request, servers are not required to check request SIGs.
    /// ```
    ///  ---
    ///
    /// NOTE: In classic RFC style, this is unclear, it implies that each SIG record is not included in
    ///  the Additional record count, but this makes it more difficult to process and calculate more
    ///  than one SIG0 record. Annoyingly, it means that the Header is signed with different material
    ///  (i.e. additional record count - #SIG0 records), so the exact header sent is NOT the header
    ///  being verified.
    ///
    ///  ---
    pub fn sign_message(&self, message: &Message, pre_sig0: &SIG) -> ProtoResult<Vec<u8>> {
        tbs::message_tbs(message, pre_sig0).and_then(|tbs| self.sign(&tbs))
    }

    /// Extracts a public KEY from this Signer
    pub fn to_dnskey(&self) -> DnsSecResult<DNSKEY> {
        // TODO: this interface should allow for setting if this is a secure entry point vs. ZSK
        let pub_key = self.key.to_public_key()?;
        Ok(DNSKEY::new(self.is_zone_signing_key, true, false, pub_key))
    }

    /// Test that this key is capable of signing and verifying data
    pub fn test_key(&self) -> DnsSecResult<()> {
        // use proto::rr::dnssec::PublicKey;

        // // TODO: why doesn't this work for ecdsa_256 and 384?
        // let test_data = TBS::from(b"DEADBEEF" as &[u8]);

        // let signature = self.sign(&test_data).map_err(|e| {println!("failed to sign, {:?}", e); e})?;
        // let pk = self.key.to_public_key()?;
        // pk.verify(self.algorithm, test_data.as_ref(), &signature).map_err(|e| {println!("failed to verify, {:?}", e); e})?;

        Ok(())
    }
}

impl MessageSigner for SigSigner {
    fn sign_message(
        &self,
        message: &Message,
        current_time: u32,
    ) -> ProtoResult<(MessageSignature, Option<MessageVerifier>)> {
        debug!("signing message: {message:?}");
        let key_tag: u16 = self.calculate_key_tag()?;

        // this is based on RFCs 2535, 2931 and 3007

        // The owner name SHOULD be root (a single zero octet).
        let name = Name::root();
        // The TTL fields SHOULD be zero
        let ttl = 0;

        let num_labels = name.num_labels();

        let expiration_time: u32 = current_time + (5 * 60); // +5 minutes in seconds

        let pre_sig0 = SIG::new(
            // type covered in SIG(0) is 0 which is what makes this SIG0 vs a standard SIG
            RecordType::ZERO,
            self.key.algorithm(),
            num_labels,
            // see above, original_ttl is meaningless, The TTL fields SHOULD be zero
            0,
            // recommended time is +5 minutes from now, to prevent timing attacks, 2 is probably good
            expiration_time,
            // current time, this should be UTC
            // unsigned numbers of seconds since the start of 1 January 1970, GMT
            current_time,
            key_tag,
            // can probably get rid of this clone if the ownership is correct
            self.signer_name().clone(),
            Vec::new(),
        );
        let signature: Vec<u8> = self.sign_message(message, &pre_sig0)?;
        let rdata = RData::DNSSEC(DNSSECRData::SIG(pre_sig0.set_sig(signature)));

        // 'For all SIG(0) RRs, the owner name, class, TTL, and original TTL, are
        //  meaningless.' - 2931
        let mut sig0 = Record::from_rdata(name, ttl, rdata);

        // The CLASS field SHOULD be ANY
        sig0.set_dns_class(DNSClass::ANY);

        Ok((MessageSignature::Sig0(sig0), None))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    #[cfg(feature = "std")]
    use std::println;

    use rustls_pki_types::PrivatePkcs8KeyDer;

    use super::*;
    use crate::dnssec::{
        Algorithm, PublicKey, SigningKey, TBS, Verifier,
        crypto::RsaSigningKey,
        rdata::{DNSSECRData, KEY, RRSIG, SIG, key::KeyUsage},
    };
    use crate::op::{Message, MessageSignature, Query};
    use crate::rr::rdata::{CNAME, NS};
    use crate::rr::{DNSClass, Name, RData, Record, RecordType};

    fn assert_send_and_sync<T: Send + Sync>() {}

    #[test]
    fn test_send_and_sync() {
        assert_send_and_sync::<SigSigner>();
    }

    fn pre_sig0(signer: &SigSigner, inception_time: u32, expiration_time: u32) -> SIG {
        SIG::new(
            // type covered in SIG(0) is 0 which is what makes this SIG0 vs a standard SIG
            RecordType::ZERO,
            signer.key().algorithm(),
            0,
            // see above, original_ttl is meaningless, The TTL fields SHOULD be zero
            0,
            // recommended time is +5 minutes from now, to prevent timing attacks, 2 is probably good
            expiration_time,
            // current time, this should be UTC
            // unsigned numbers of seconds since the start of 1 January 1970, GMT
            inception_time,
            signer.calculate_key_tag().unwrap(),
            // can probably get rid of this clone if the ownership is correct
            signer.signer_name().clone(),
            Vec::new(),
        )
    }

    #[test]
    fn test_sign_and_verify_message_sig0() {
        let origin: Name = Name::parse("example.com.", None).unwrap();
        let mut question: Message = Message::new();
        let mut query: Query = Query::new();
        query.set_name(origin);
        question.add_query(query);

        let key =
            RsaSigningKey::from_pkcs8(&PrivatePkcs8KeyDer::from(RSA_KEY), Algorithm::RSASHA256)
                .unwrap();
        let pub_key = key.to_public_key().unwrap();
        let sig0key = KEY::new_sig0key(&pub_key);
        let signer = SigSigner::sig0(sig0key.clone(), Box::new(key), Name::root());

        let pre_sig0 = pre_sig0(&signer, 0, 300);
        let sig = signer.sign_message(&question, &pre_sig0).unwrap();
        #[cfg(feature = "std")]
        println!("sig: {sig:?}");

        assert!(!sig.is_empty());

        assert!(sig0key.verify_message(&question, &sig, &pre_sig0).is_ok());

        // now test that the sig0 record works correctly.
        assert_eq!(question.signature(), &MessageSignature::Unsigned);
        question.finalize(&signer, 0).expect("should have signed");
        assert!(matches!(question.signature(), MessageSignature::Sig0(_)));

        let sig = signer.sign_message(&question, &pre_sig0);
        #[cfg(feature = "std")]
        println!("sig after sign: {sig:?}");

        let MessageSignature::Sig0(sig) = question.signature() else {
            panic!(
                "expected sig0 signature after sign, not {:?}",
                question.signature()
            );
        };

        let RData::DNSSEC(DNSSECRData::SIG(sig)) = sig.data() else {
            panic!(
                "expected DNSSECRdata::SIG from Sig0 RR, not {:?}",
                sig.data()
            );
        };

        assert!(sig0key.verify_message(&question, sig.sig(), sig).is_ok());
    }

    #[test]
    #[allow(deprecated)]
    fn test_sign_and_verify_rrset() {
        let key =
            RsaSigningKey::from_pkcs8(&PrivatePkcs8KeyDer::from(RSA_KEY), Algorithm::RSASHA256)
                .unwrap();
        let pub_key = key.to_public_key().unwrap();
        let sig0key = KEY::new_sig0key_with_usage(&pub_key, KeyUsage::Zone);
        let signer = SigSigner::sig0(sig0key, Box::new(key), Name::root());

        let origin: Name = Name::parse("example.com.", None).unwrap();
        let rrsig = Record::from_rdata(
            origin.clone(),
            86400,
            RRSIG::new(
                RecordType::NS,
                Algorithm::RSASHA256,
                origin.num_labels(),
                86400,
                5,
                0,
                signer.calculate_key_tag().unwrap(),
                origin.clone(),
                vec![],
            ),
        );

        let rrset = vec![
            Record::from_rdata(
                origin.clone(),
                86400,
                RData::NS(NS(Name::parse("a.iana-servers.net.", None).unwrap())),
            )
            .set_dns_class(DNSClass::IN)
            .clone(),
            Record::from_rdata(
                origin,
                86400,
                RData::NS(NS(Name::parse("b.iana-servers.net.", None).unwrap())),
            )
            .set_dns_class(DNSClass::IN)
            .clone(),
        ];

        let tbs = TBS::from_rrsig(&rrsig, rrset.iter()).unwrap();
        let sig = signer.sign(&tbs).unwrap();

        let pub_key = signer.key().to_public_key().unwrap();
        assert!(pub_key.verify(tbs.as_ref(), &sig).is_ok());
    }

    #[test]
    #[allow(deprecated)]
    fn test_calculate_key_tag_pem() {
        let key =
            RsaSigningKey::from_pkcs8(&PrivatePkcs8KeyDer::from(RSA_KEY), Algorithm::RSASHA256)
                .unwrap();
        let pub_key = key.to_public_key().unwrap();
        let sig0key = KEY::new_sig0key_with_usage(&pub_key, KeyUsage::Zone);
        let signer = SigSigner::sig0(sig0key, Box::new(key), Name::root());
        let key_tag = signer.calculate_key_tag().unwrap();

        assert_eq!(key_tag, 3256);
    }

    #[test]
    fn test_rrset_tbs() {
        let key =
            RsaSigningKey::from_pkcs8(&PrivatePkcs8KeyDer::from(RSA_KEY), Algorithm::RSASHA256)
                .unwrap();
        let pub_key = key.to_public_key().unwrap();
        let sig0key = KEY::new_sig0key(&pub_key);
        let signer = SigSigner::sig0(sig0key, Box::new(key), Name::root());

        let origin = Name::parse("example.com.", None).unwrap();
        let rrsig = Record::from_rdata(
            origin.clone(),
            86400,
            RRSIG::new(
                RecordType::NS,
                Algorithm::RSASHA256,
                origin.num_labels(),
                86400,
                5,
                0,
                signer.calculate_key_tag().unwrap(),
                origin.clone(),
                vec![],
            ),
        );
        let rrset = vec![
            Record::from_rdata(
                origin.clone(),
                86400,
                RData::NS(NS(Name::parse("a.iana-servers.net.", None).unwrap())),
            )
            .set_dns_class(DNSClass::IN)
            .clone(),
            Record::from_rdata(
                origin.clone(),
                86400,
                RData::NS(NS(Name::parse("b.iana-servers.net.", None).unwrap())),
            )
            .set_dns_class(DNSClass::IN)
            .clone(),
        ];

        let tbs = TBS::from_rrsig(&rrsig, rrset.iter()).unwrap();
        assert!(!tbs.as_ref().is_empty());

        let rrset = vec![
            Record::from_rdata(
                origin.clone(),
                86400,
                RData::CNAME(CNAME(Name::parse("a.iana-servers.net.", None).unwrap())),
            )
            .set_dns_class(DNSClass::IN)
            .clone(), // different type
            Record::from_rdata(
                Name::parse("www.example.com.", None).unwrap(),
                86400,
                RData::NS(NS(Name::parse("a.iana-servers.net.", None).unwrap())),
            )
            .set_dns_class(DNSClass::IN)
            .clone(), // different name
            Record::from_rdata(
                origin.clone(),
                86400,
                RData::NS(NS(Name::parse("a.iana-servers.net.", None).unwrap())),
            )
            .set_dns_class(DNSClass::CH)
            .clone(), // different class
            Record::from_rdata(
                origin.clone(),
                86400,
                RData::NS(NS(Name::parse("a.iana-servers.net.", None).unwrap())),
            )
            .set_dns_class(DNSClass::IN)
            .clone(),
            Record::from_rdata(
                origin,
                86400,
                RData::NS(NS(Name::parse("b.iana-servers.net.", None).unwrap())),
            )
            .set_dns_class(DNSClass::IN)
            .clone(),
        ];

        let filtered_tbs = TBS::from_rrsig(&rrsig, rrset.iter()).unwrap();
        assert!(!filtered_tbs.as_ref().is_empty());
        assert_eq!(tbs.as_ref(), filtered_tbs.as_ref());
    }

    const RSA_KEY: &[u8] = include_bytes!("../../tests/test-data/rsa-2048-private-key-1.pk8");
}
