// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! hash functions for DNSSEC operations

use alloc::{borrow::ToOwned, vec::Vec};

use super::rdata::sig::SigInput;
use crate::{
    error::{ProtoError, ProtoResult},
    rr::{DNSClass, Name, Record},
    serialize::binary::{BinEncodable, BinEncoder, EncodeMode, NameEncoding},
};

/// Data To Be Signed.
pub struct TBS(Vec<u8>);

impl TBS {
    /// Returns the to-be-signed serialization of the given message.
    pub fn from_message(message: &impl BinEncodable, input: &SigInput) -> ProtoResult<Self> {
        // TODO: should perform the serialization and sign block by block to reduce the max memory
        //  usage, though at 4k max, this is probably unnecessary... For AXFR and large zones, it's
        //  more important
        let mut buf = Vec::with_capacity(512);
        let mut buf2 = Vec::with_capacity(512);
        let mut encoder = BinEncoder::with_mode(&mut buf, EncodeMode::Normal);

        input.emit(&mut encoder)?;

        // need a separate encoder here, as the encoding references absolute positions
        // inside the buffer. If the buffer already contains the sig0 RDATA, offsets
        // are wrong and the signature won't match.
        let mut encoder2 = BinEncoder::with_mode(&mut buf2, EncodeMode::Signing);
        message.emit(&mut encoder2).unwrap(); // coding error if this panics (i think?)

        buf.append(&mut buf2);

        Ok(Self(buf))
    }

    /// Returns the to-be-signed serialization of the given record set using the information
    /// provided from the SIG record.
    ///
    /// # Arguments
    ///
    /// * `name` - labels of the record to sign
    /// * `dns_class` - DNSClass of the RRSet, i.e. IN
    /// * `input` - `SigInput` data used to create the signature
    /// * `records` - RRSet records to sign with the information in the `rrsig`
    ///
    /// # Return
    ///
    /// binary hash of the RRSet with the information from the RRSIG record
    pub fn from_input<'a>(
        name: &Name,
        dns_class: DNSClass,
        input: &SigInput,
        records: impl Iterator<Item = &'a Record>,
    ) -> ProtoResult<Self> {
        Self::new(name, dns_class, input, records)
    }

    /// Returns the to-be-signed serialization of the given record set.
    ///
    /// # Arguments
    ///
    /// * `name` - RRset record name
    /// * `dns_class` - DNSClass, i.e. IN, of the records
    /// * `input` - the input data used to create the signature
    /// * `records` - RRSet to hash
    ///
    /// # Returns
    ///
    /// the binary hash of the specified RRSet and associated information
    #[allow(clippy::too_many_arguments)]
    fn new<'a>(
        name: &Name,
        dns_class: DNSClass,
        input: &SigInput,
        records: impl Iterator<Item = &'a Record>,
    ) -> ProtoResult<Self> {
        // TODO: change this to a BTreeSet so that it's preordered, no sort necessary
        let mut rrset = Vec::new();

        // collect only the records for this rrset
        for record in records {
            if dns_class == record.dns_class()
                && input.type_covered == record.record_type()
                && name == record.name()
            {
                rrset.push(record);
            }
        }

        // put records in canonical order
        rrset.sort();

        let name = determine_name(name, input.num_labels)?;

        // TODO: rather than buffering here, use the Signer/Verifier? might mean fewer allocations...
        let mut buf = Vec::new();
        let mut encoder = BinEncoder::new(&mut buf);
        // Encode records using DNSSEC canonical form. This affects how names inside RDATA are
        // encoded.
        encoder.set_canonical_form(true);
        // Disable name compression. Encoding of other fields may switch to use lowercase names
        // as well.
        encoder.set_name_encoding(NameEncoding::Uncompressed);

        //          signed_data = RRSIG_RDATA | RR(1) | RR(2)...  where
        //
        //             "|" denotes concatenation
        //
        //             RRSIG_RDATA is the wire format of the RRSIG RDATA fields
        //                with the Signature field excluded and the Signer's Name
        //                in canonical form.
        input.emit(&mut encoder)?;

        // construct the rrset signing data
        for record in rrset {
            //             RR(i) = name | type | class | OrigTTL | RDATA length | RDATA
            //
            //                name is calculated according to the function in the RFC 4035
            {
                let mut encoder_name =
                    encoder.with_name_encoding(NameEncoding::UncompressedLowercase);
                name.emit(&mut encoder_name)?;
            }
            //
            //                type is the RRset type and all RRs in the class
            input.type_covered.emit(&mut encoder)?;
            //
            //                class is the RRset's class
            dns_class.emit(&mut encoder)?;
            //
            //                OrigTTL is the value from the RRSIG Original TTL field
            encoder.emit_u32(input.original_ttl)?;
            //
            //                RDATA length
            let rdata_length_place = encoder.place::<u16>()?;
            //
            //                All names in the RDATA field are in canonical form (set above)
            record.data().emit(&mut encoder)?;

            let length = u16::try_from(encoder.len_since_place(&rdata_length_place))
                .map_err(|_| ProtoError::from("RDATA length exceeds u16::MAX"))?;
            rdata_length_place.replace(&mut encoder, length)?;
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
