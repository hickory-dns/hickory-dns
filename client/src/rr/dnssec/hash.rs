//! hash functions for DNSSec operations

use op::Message;
use rr::{DNSClass, Name, Record, RecordType, RData};
use rr::dnssec::{Algorithm, DnsSecErrorKind, DnsSecResult};
use rr::rdata::{sig, SIG};
use serialize::binary::{BinEncoder, BinSerializable, EncodeMode};

/// Hashes a Message for signing
pub fn hash_message(message: &Message, pre_sig0: &SIG) -> DnsSecResult<Vec<u8>> {
    // TODO: should perform the serialization and sign block by block to reduce the max memory
    //  usage, though at 4k max, this is probably unnecessary... For AXFR and large zones, it's
    //  more important
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut buf2: Vec<u8> = Vec::with_capacity(512);

    {
        let mut encoder: BinEncoder = BinEncoder::with_mode(&mut buf, EncodeMode::Normal);
        assert!(sig::emit_pre_sig(&mut encoder,
                                  pre_sig0.type_covered(),
                                  pre_sig0.algorithm(),
                                  pre_sig0.num_labels(),
                                  pre_sig0.original_ttl(),
                                  pre_sig0.sig_expiration(),
                                  pre_sig0.sig_inception(),
                                  pre_sig0.key_tag(),
                                  pre_sig0.signer_name())
                        .is_ok());
        // need a separate encoder here, as the encoding references absolute positions
        // inside the buffer. If the buffer already contains the sig0 RDATA, offsets
        // are wrong and the signature won't match.
        let mut encoder2: BinEncoder = BinEncoder::with_mode(&mut buf2, EncodeMode::Signing);
        message.emit(&mut encoder2).unwrap(); // coding error if this panics (i think?)
    }

    buf.append(&mut buf2);

    Ok(buf)
}

/// Computes the hash of the given record set
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
/// * `signer_name` - label of the etity responsible for signing this hash
/// * `records` - RRSet to hash
///
/// # Returns
///
/// the binary hash of the specified RRSet and associated information
pub fn hash_rrset(name: &Name,
                  dns_class: DNSClass,
                  num_labels: u8,
                  type_covered: RecordType,
                  algorithm: Algorithm,
                  original_ttl: u32,
                  sig_expiration: u32,
                  sig_inception: u32,
                  key_tag: u16,
                  signer_name: &Name,
                  records: &[Record])
                  -> DnsSecResult<Vec<u8>> {
    // TODO: change this to a BTreeSet so that it's preordered, no sort necessary
    let mut rrset: Vec<&Record> = Vec::new();

    // collect only the records for this rrset
    for record in records {
        if dns_class == record.dns_class() && type_covered == record.rr_type() &&
           name == record.name() {
            rrset.push(record);
        }
    }

    // put records in canonical order
    rrset.sort();

    let name: Name = if let Some(name) = determine_name(name, num_labels) {
        name
    } else {
        return Err(DnsSecErrorKind::Msg(format!("could not determine name from {}", name)).into());
    };

    // TODO: rather than buffering here, use the Signer/Verifier? might mean fewer allocations...
    let mut buf: Vec<u8> = Vec::new();

    {
        let mut encoder: BinEncoder = BinEncoder::new(&mut buf);
        encoder.set_canonical_names(true);

        //          signed_data = RRSIG_RDATA | RR(1) | RR(2)...  where
        //
        //             "|" denotes concatenation
        //
        //             RRSIG_RDATA is the wire format of the RRSIG RDATA fields
        //                with the Signature field excluded and the Signer's Name
        //                in canonical form.
        assert!(sig::emit_pre_sig(&mut encoder,
                                  type_covered,
                                  algorithm,
                                  name.num_labels(),
                                  original_ttl,
                                  sig_expiration,
                                  sig_inception,
                                  key_tag,
                                  &signer_name)
                        .is_ok());

        // construct the rrset signing data
        for record in rrset {
            //             RR(i) = name | type | class | OrigTTL | RDATA length | RDATA
            //
            //                name is calculated according to the function in the RFC 4035
            assert!(name.to_lowercase()
                        .emit_as_canonical(&mut encoder, true)
                        .is_ok());
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
                assert!(record.rdata().emit(&mut rdata_encoder).is_ok());
            }
            assert!(encoder.emit_u16(rdata_buf.len() as u16).is_ok());
            //
            //                All names in the RDATA field are in canonical form (set above)
            assert!(encoder.emit_vec(&rdata_buf).is_ok());
        }
    }

    // TODO: This used to return the hash, now it's a hashable record type?
    // DigestType::from(self.algorithm).hash(&buf)
    Ok(buf)
}

/// hashes the RRSet with information provided from the RRSig record
///
/// # Arguments
///
/// * `rrsig` - SIG or RRSIG record, which was produced from the RRSet
/// * `records` - RRSet records to sign with the information in the `rrsig`
///
/// # Return
///
/// binary hash of the RRSet with the information from the RRSIG record
pub fn hash_rrset_with_rrsig(rrsig: &Record, records: &[Record]) -> DnsSecResult<Vec<u8>> {
    if let &RData::SIG(ref sig) = rrsig.rdata() {
        hash_rrset_with_sig(rrsig.name(), rrsig.dns_class(), sig, records)
    } else {
        return Err(DnsSecErrorKind::Msg(format!("could not determine name from {}", rrsig.name()))
                       .into());
    }
}

/// hashes the RRSet with information provided from the RRSig record
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
pub fn hash_rrset_with_sig(name: &Name,
                           dns_class: DNSClass,
                           sig: &SIG,
                           records: &[Record])
                           -> DnsSecResult<Vec<u8>> {
    hash_rrset(name,
               dns_class,
               sig.num_labels(),
               sig.type_covered(),
               sig.algorithm(),
               sig.original_ttl(),
               sig.sig_expiration(),
               sig.sig_inception(),
               sig.key_tag(),
               sig.signer_name(),
               records)
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
pub fn determine_name(name: &Name, num_labels: u8) -> Option<Name> {
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
        return Some(name.clone());
    }
    //                if rrsig_labels < fqdn_labels,
    //                   name = "*." | the rightmost rrsig_label labels of the
    //                                 fqdn
    if num_labels < fqdn_labels {
        let mut star_name: Name = Name::from_labels(vec!["*"]);
        let rightmost = name.trim_to(num_labels as usize);
        if !rightmost.is_root() {
            star_name = star_name.append_name(&rightmost);
            return Some(star_name);
        }
        return Some(star_name);
    }
    //
    //                if rrsig_labels > fqdn_labels
    //                   the RRSIG RR did not pass the necessary validation
    //                   checks and MUST NOT be used to authenticate this
    //                   RRset.
    // TODO: this should be an error
    None
}

#[cfg(feature = "openssl")]
#[cfg(test)]
mod tests {
    extern crate openssl;
    use self::openssl::rsa::Rsa;

    use rr::{Name, RecordType};
    use rr::rdata::SIG;
    use rr::dnssec::{KeyPair, Signer};

    pub use super::*;

    #[test]
    fn test_hash_rrset() {
        let rsa = Rsa::generate(512).unwrap();
        let key = KeyPair::from_rsa(rsa).unwrap();
        let sig0key = key.to_sig0key(Algorithm::RSASHA256).unwrap();
        let signer = Signer::sig0(sig0key, key, Name::root());

        let origin: Name = Name::parse("example.com.", None).unwrap();
        let rrsig = Record::new()
            .set_name(origin.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::NS)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::SIG(SIG::new(RecordType::NS,
                                           Algorithm::RSASHA256,
                                           origin.num_labels(),
                                           86400,
                                           5,
                                           0,
                                           signer.calculate_key_tag().unwrap(),
                                           origin.clone(),
                                           vec![])))
            .clone();
        let rrset =
            vec![Record::new()
                     .set_name(origin.clone())
                     .set_ttl(86400)
                     .set_rr_type(RecordType::NS)
                     .set_dns_class(DNSClass::IN)
                     .set_rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()))
                     .clone(),
                 Record::new()
                     .set_name(origin.clone())
                     .set_ttl(86400)
                     .set_rr_type(RecordType::NS)
                     .set_dns_class(DNSClass::IN)
                     .set_rdata(RData::NS(Name::parse("b.iana-servers.net.", None).unwrap()))
                     .clone()];

        let hash = hash_rrset_with_rrsig(&rrsig, &rrset).unwrap();
        assert!(!hash.is_empty());

        let rrset =
            vec![Record::new()
                     .set_name(origin.clone())
                     .set_ttl(86400)
                     .set_rr_type(RecordType::CNAME)
                     .set_dns_class(DNSClass::IN)
                     .set_rdata(RData::CNAME(Name::parse("a.iana-servers.net.", None)
                                                 .unwrap()))
                     .clone(), // different type
                 Record::new()
                     .set_name(Name::parse("www.example.com.", None).unwrap())
                     .set_ttl(86400)
                     .set_rr_type(RecordType::NS)
                     .set_dns_class(DNSClass::IN)
                     .set_rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()))
                     .clone(), // different name
                 Record::new()
                     .set_name(origin.clone())
                     .set_ttl(86400)
                     .set_rr_type(RecordType::NS)
                     .set_dns_class(DNSClass::CH)
                     .set_rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()))
                     .clone(), // different class
                 Record::new()
                     .set_name(origin.clone())
                     .set_ttl(86400)
                     .set_rr_type(RecordType::NS)
                     .set_dns_class(DNSClass::IN)
                     .set_rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()))
                     .clone(),
                 Record::new()
                     .set_name(origin.clone())
                     .set_ttl(86400)
                     .set_rr_type(RecordType::NS)
                     .set_dns_class(DNSClass::IN)
                     .set_rdata(RData::NS(Name::parse("b.iana-servers.net.", None).unwrap()))
                     .clone()];

        let filtered_hash = hash_rrset_with_rrsig(&rrsig, &rrset).unwrap();
        assert!(!filtered_hash.is_empty());
        assert_eq!(hash, filtered_hash);
    }
}