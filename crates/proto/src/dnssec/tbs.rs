// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! hash functions for DNSSEC operations

use alloc::{borrow::ToOwned, vec::Vec};
use time::OffsetDateTime;

use super::Algorithm;
use crate::{
    error::{ProtoError, ProtoResult},
    rr::{DNSClass, Name, Record, RecordSet, RecordType, SerialNumber},
    serialize::binary::{BinEncodable, BinEncoder, EncodeMode},
};

use super::{
    SigSigner,
    rdata::{RRSIG, SIG, sig},
};

/// Data To Be Signed.
pub struct TBS(Vec<u8>);

impl TBS {
    /// Returns the to-be-signed serialization of the given record set using the information
    /// provided from the RRSIG record.
    ///
    /// # Arguments
    ///
    /// * `rrsig` - SIG or RRSIG record, which was produced from the RRSet
    /// * `records` - RRSet records to sign with the information in the `rrsig`
    ///
    /// # Return
    ///
    /// binary hash of the RRSet with the information from the RRSIG record
    pub fn from_rrsig<'a>(
        rrsig: &Record<RRSIG>,
        records: impl Iterator<Item = &'a Record>,
    ) -> ProtoResult<Self> {
        Self::from_sig(rrsig.name(), rrsig.dns_class(), rrsig.data(), records)
    }

    /// Returns the to-be-signed serialization of the given record set using the information
    /// provided from the SIG record.
    ///
    /// # Arguments
    ///
    /// * `name` - labels of the record to sign
    /// * `dns_class` - DNSClass of the RRSet, i.e. IN
    /// * `sig` - SIG or RRSIG record, which was produced from the RRSet
    /// * `records` - RRSet records to sign with the information in the `rrsig`
    ///
    /// # Return
    ///
    /// binary hash of the RRSet with the information from the RRSIG record
    pub fn from_sig<'a>(
        name: &Name,
        dns_class: DNSClass,
        sig: &SIG,
        records: impl Iterator<Item = &'a Record>,
    ) -> ProtoResult<Self> {
        Self::new(
            name,
            dns_class,
            sig.num_labels(),
            sig.type_covered(),
            sig.algorithm(),
            sig.original_ttl(),
            sig.sig_expiration(),
            sig.sig_inception(),
            sig.key_tag(),
            sig.signer_name(),
            records,
        )
    }

    /// Returns the to-be-signed serialization of the given record set.
    ///
    /// # Arguments
    ///
    /// * `rr_set` - RRSet to sign
    /// * `zone_class` - DNSClass, i.e. IN, of the records
    /// * `inception` - the date/time when this hashed signature will become valid
    /// * `expiration` - the date/time when this hashed signature will expire
    /// * `signer` - the signer to use for signing the RRSet
    ///
    /// # Returns
    ///
    /// the binary hash of the specified RRSet and associated information
    pub fn from_rrset(
        rr_set: &RecordSet,
        zone_class: DNSClass,
        inception: OffsetDateTime,
        expiration: OffsetDateTime,
        signer: &SigSigner,
    ) -> ProtoResult<Self> {
        Self::new(
            rr_set.name(),
            zone_class,
            rr_set.name().num_labels(),
            rr_set.record_type(),
            signer.key().algorithm(),
            rr_set.ttl(),
            SerialNumber(expiration.unix_timestamp() as u32),
            SerialNumber(inception.unix_timestamp() as u32),
            signer.calculate_key_tag()?,
            signer.signer_name(),
            rr_set.records_without_rrsigs(),
        )
    }

    /// Returns the to-be-signed serialization of the given record set.
    ///
    /// # Arguments
    ///
    /// * `name` - RRset record name
    /// * `dns_class` - DNSClass, i.e. IN, of the records
    /// * `num_labels` - number of labels in the name, needed to deal with `*.example.com`
    /// * `type_covered` - RecordType of the RRSet being hashed
    /// * `algorithm` - The Algorithm type used for the hashing
    /// * `original_ttl` - Original TTL is the TTL as specified in the SOA zones RRSet associated record
    /// * `sig_expiration` - the epoch seconds of when this hashed signature will expire
    /// * `key_inception` - the epoch seconds of when this hashed signature will be valid
    /// * `signer_name` - label of the entity responsible for signing this hash
    /// * `records` - RRSet to hash
    ///
    /// # Returns
    ///
    /// the binary hash of the specified RRSet and associated information
    // FIXME: OMG, there are a ton of asserts in here...
    #[allow(clippy::too_many_arguments)]
    fn new<'a>(
        name: &Name,
        dns_class: DNSClass,
        num_labels: u8,
        type_covered: RecordType,
        algorithm: Algorithm,
        original_ttl: u32,
        sig_expiration: SerialNumber,
        sig_inception: SerialNumber,
        key_tag: u16,
        signer_name: &Name,
        records: impl Iterator<Item = &'a Record>,
    ) -> ProtoResult<Self> {
        // TODO: change this to a BTreeSet so that it's preordered, no sort necessary
        let mut rrset: Vec<&Record> = Vec::new();

        // collect only the records for this rrset
        for record in records {
            if dns_class == record.dns_class()
                && type_covered == record.record_type()
                && name == record.name()
            {
                rrset.push(record);
            }
        }

        // put records in canonical order
        rrset.sort();

        let name = determine_name(name, num_labels)?;

        // TODO: rather than buffering here, use the Signer/Verifier? might mean fewer allocations...
        let mut buf: Vec<u8> = Vec::new();

        {
            let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut buf);
            encoder.set_canonical_names(true);

            //          signed_data = RRSIG_RDATA | RR(1) | RR(2)...  where
            //
            //             "|" denotes concatenation
            //
            //             RRSIG_RDATA is the wire format of the RRSIG RDATA fields
            //                with the Signature field excluded and the Signer's Name
            //                in canonical form.
            assert!(
                sig::emit_pre_sig(
                    &mut encoder,
                    type_covered,
                    algorithm,
                    name.num_labels(),
                    original_ttl,
                    sig_expiration,
                    sig_inception,
                    key_tag,
                    signer_name,
                )
                .is_ok()
            );

            // construct the rrset signing data
            for record in rrset {
                //             RR(i) = name | type | class | OrigTTL | RDATA length | RDATA
                //
                //                name is calculated according to the function in the RFC 4035
                assert!(
                    name.to_lowercase()
                        .emit_as_canonical(&mut encoder, true)
                        .is_ok()
                );
                //
                //                type is the RRset type and all RRs in the class
                assert!(type_covered.emit(&mut encoder).is_ok());
                //
                //                class is the RRset's class
                assert!(dns_class.emit(&mut encoder).is_ok());
                //
                //                OrigTTL is the value from the RRSIG Original TTL field
                assert!(encoder.emit_u32(original_ttl).is_ok());
                //
                //                RDATA length
                // TODO: add support to the encoder to set a marker to go back and write the length
                let mut rdata_buf = Vec::new();
                {
                    let mut rdata_encoder = BinEncoder::new(&mut rdata_buf);
                    rdata_encoder.set_canonical_names(true);
                    assert!(record.data().emit(&mut rdata_encoder).is_ok());
                }
                assert!(encoder.emit_u16(rdata_buf.len() as u16).is_ok());
                //
                //                All names in the RDATA field are in canonical form (set above)
                assert!(encoder.emit_vec(&rdata_buf).is_ok());
            }
        }

        Ok(Self(buf))
    }
}

impl<'a> From<&'a [u8]> for TBS {
    fn from(slice: &'a [u8]) -> Self {
        Self(slice.to_owned())
    }
}

impl AsRef<[u8]> for TBS {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Returns the to-be-signed serialization of the given message.
pub fn message_tbs<M: BinEncodable>(message: &M, pre_sig0: &SIG) -> ProtoResult<TBS> {
    // TODO: should perform the serialization and sign block by block to reduce the max memory
    //  usage, though at 4k max, this is probably unnecessary... For AXFR and large zones, it's
    //  more important
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut buf2: Vec<u8> = Vec::with_capacity(512);

    {
        let mut encoder: BinEncoder<'_> = BinEncoder::with_mode(&mut buf, EncodeMode::Normal);
        assert!(
            sig::emit_pre_sig(
                &mut encoder,
                pre_sig0.type_covered(),
                pre_sig0.algorithm(),
                pre_sig0.num_labels(),
                pre_sig0.original_ttl(),
                pre_sig0.sig_expiration(),
                pre_sig0.sig_inception(),
                pre_sig0.key_tag(),
                pre_sig0.signer_name(),
            )
            .is_ok()
        );
        // need a separate encoder here, as the encoding references absolute positions
        // inside the buffer. If the buffer already contains the sig0 RDATA, offsets
        // are wrong and the signature won't match.
        let mut encoder2: BinEncoder<'_> = BinEncoder::with_mode(&mut buf2, EncodeMode::Signing);
        message.emit(&mut encoder2).unwrap(); // coding error if this panics (i think?)
    }

    buf.append(&mut buf2);

    Ok(TBS(buf))
}

/// [RFC 4035](https://tools.ietf.org/html/rfc4035), DNSSEC Protocol Modifications, March 2005
///
/// ```text
///
/// 5.3.2.  Reconstructing the Signed Data
///             ...
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
/// ```
pub fn determine_name(name: &Name, num_labels: u8) -> Result<Name, ProtoError> {
    //             To calculate the name:
    //                let rrsig_labels = the value of the RRSIG Labels field
    //
    //                let fqdn = RRset's fully qualified domain name in
    //                                canonical form
    //
    //                let fqdn_labels = Label count of the fqdn above.
    let fqdn_labels = name.num_labels();
    //                if rrsig_labels = fqdn_labels,
    //                    name = fqdn

    if fqdn_labels == num_labels {
        return Ok(name.clone());
    }
    //                if rrsig_labels < fqdn_labels,
    //                   name = "*." | the rightmost rrsig_label labels of the
    //                                 fqdn
    if num_labels < fqdn_labels {
        let mut star_name: Name = Name::from_labels(vec![b"*" as &[u8]]).unwrap();
        let rightmost = name.trim_to(num_labels as usize);
        if !rightmost.is_root() {
            star_name = star_name.append_name(&rightmost)?;
            return Ok(star_name);
        }
        return Ok(star_name);
    }
    //
    //                if rrsig_labels > fqdn_labels
    //                   the RRSIG RR did not pass the necessary validation
    //                   checks and MUST NOT be used to authenticate this
    //                   RRset.

    Err(format!("could not determine name from {name}").into())
}
