#![no_main]

//! This fuzzer checks that, if a DNS message can be decoded, it is re-encoded in a way that
//! preserves RDATA sections of records as appropriate. Names embedded in the RDATA section of some
//! well-known record types may be compressed or decompressed, but otherwise the RDATA should be
//! preserved byte-for-byte. See RFC 3597, section 3:
//!
//! "... servers MUST also exactly preserve the RDATA of RRs of known type, except for changes due
//! to compression or decompression where allowed by section 4 of this memo. In particular, the
//! character case of domain names that are not subject to compression MUST be preserved."

use std::fmt::Debug;

use libfuzzer_sys::fuzz_target;

use hickory_proto::{
    op::Message,
    serialize::binary::{BinDecodable, BinEncodable},
};

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = Message::from_bytes(data) {
        let reencoded = message.to_bytes().unwrap();
        compare(data, &message, &reencoded);
    }
});

fn compare(original: &[u8], message: &Message, reencoded: &[u8]) {
    let query_count = u16::from_be_bytes(reencoded[4..6].try_into().unwrap());
    let answer_count = u16::from_be_bytes(reencoded[6..8].try_into().unwrap());
    let authority_count = u16::from_be_bytes(reencoded[8..10].try_into().unwrap());
    let additional_records_count = u16::from_be_bytes(reencoded[10..12].try_into().unwrap());

    let rr_count = answer_count + authority_count + additional_records_count;
    let mut original_rrs = match split_rrs(original, query_count, rr_count) {
        Ok(original_rrs) => original_rrs,
        Err(error_message) => {
            println!("Parsed message: {message:?}");
            println!("Original: {original:02x?}");
            panic!("failed to split original message into resource records: {error_message}");
        }
    };
    let mut reencoded_rrs = match split_rrs(reencoded, query_count, rr_count) {
        Ok(reencoded_rrs) => reencoded_rrs,
        Err(error_message) => {
            println!("Parsed message: {message:?}");
            println!("Original:   {original:02x?}");
            println!("Re-encoded: {reencoded:02x?}");
            panic!("failed to split re-encoded message into resource records: {error_message}");
        }
    };

    sort_opt(&mut original_rrs);
    sort_opt(&mut reencoded_rrs);

    for (original_rr, reencoded_rr) in original_rrs.iter().zip(reencoded_rrs.iter()) {
        match original_rr.has_invalid_compressed_label() {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error_message) => {
                println!("Parsed message: {message:?}");
                println!("Record type: {}", original_rr.r#type);
                println!("Original: {:02x?}", original_rr.rdata);
                panic!("failed to check name labels of original RDATA: {error_message}");
            }
        }
        if original_rr.r#type != reencoded_rr.r#type {
            println!("Parsed message: {message:?}");
            println!("Original:   {original:02x?}");
            println!("Re-encoded: {reencoded:02x?}");
            println!(
                "Original record types:   {:?}",
                original_rrs
                    .iter()
                    .map(|record| record.r#type)
                    .collect::<Vec<_>>()
            );
            println!(
                "Re-encoded record types: {:?}",
                reencoded_rrs
                    .iter()
                    .map(|record| record.r#type)
                    .collect::<Vec<_>>()
            );
            panic!(
                "record type changed when decoding and re-encoding: {} vs. {}",
                original_rr.r#type, reencoded_rr.r#type
            );
        }
        let Err(error_message) = compare_rr(original, *original_rr, reencoded, *reencoded_rr)
        else {
            continue;
        };
        println!("Parsed message: {message:?}");
        println!("Record type: {}", original_rr.r#type);
        println!("Original:   {:02x?}", &original_rr.rdata);
        println!("Re-encoded: {:02x?}", &reencoded_rr.rdata);
        panic!("record RDATA was not preserved when decoding and re-encoding: {error_message}");
    }
}

fn compare_rr(
    original: &[u8],
    original_rr: Record<'_>,
    reencoded: &[u8],
    reencoded_rr: Record<'_>,
) -> Result<(), &'static str> {
    if original_rr.rdata == reencoded_rr.rdata {
        return Ok(());
    }
    match original_rr.r#type {
        record_types::NS
        | record_types::MD
        | record_types::MF
        | record_types::CNAME
        | record_types::MB
        | record_types::MG
        | record_types::MR
        | record_types::PTR => {
            // RDATA consists of a single `<domain-name>`.
            let original_decompressed = Name::decompress(original_rr.rdata, original)?;
            let reencoded_decompressed = Name::decompress(reencoded_rr.rdata, reencoded)?;
            if original_decompressed == reencoded_decompressed {
                Ok(())
            } else {
                Err("PTR RDATA was not preserved")
            }
        }
        record_types::SOA => {
            // RDATA consists of seven different fields.
            let original_decompressed = Soa::decompress(original_rr.rdata, original)?;
            let reencoded_decompressed = Soa::decompress(reencoded_rr.rdata, reencoded)?;
            if original_decompressed == reencoded_decompressed {
                Ok(())
            } else {
                Err("SOA RDATA was not preserved")
            }
        }
        record_types::MINFO => {
            // RDATA consists of two `<domain-name>`s.
            let original_decompressed = Minfo::decompress(original_rr.rdata, original)?;
            let reencoded_decompressed = Minfo::decompress(reencoded_rr.rdata, reencoded)?;
            if original_decompressed == reencoded_decompressed {
                Ok(())
            } else {
                Err("MINFO RDATA was not preserved")
            }
        }
        record_types::MX => {
            // RDATA consists of a 16-bit integer and a `<domain-name>`.
            let original_decompressed = Mx::decompress(original_rr.rdata, original)?;
            let reencoded_decompressed = Mx::decompress(reencoded_rr.rdata, reencoded)?;
            if original_decompressed == reencoded_decompressed {
                Ok(())
            } else {
                Err("MX RDATA was not preserved")
            }
        }
        record_types::OPT => {
            // Ignore OPT records because they are reconstructed hop-by-hop, not passed through
            // transparently.
            Ok(())
        }
        _ => Err("RDATA was not preserved"),
    }
}

#[derive(Debug, Clone, Copy)]
struct Record<'a> {
    r#type: u16,
    rdata: &'a [u8],
}

impl Record<'_> {
    /// Check if this record is of a non-well-known type, and if it contains a compressed label in
    /// some name in the RDATA.
    ///
    /// If the fuzzer input contains such a label, it is improperly encoded, because only well-known
    /// record types are allowed to use compression in their RDATA. We don't want to enforce that
    /// the re-encoded message preserves the malformed, non-interoperable RDATA, thus, we can skip
    /// further comparisons.
    fn has_invalid_compressed_label(&self) -> Result<bool, &'static str> {
        let Self { r#type, rdata } = self;
        if rdata.is_empty() {
            return Ok(false);
        }
        match *r#type {
            // RFC 1035 types
            record_types::CNAME
            | record_types::MB
            | record_types::MD
            | record_types::MF
            | record_types::MG
            | record_types::MINFO
            | record_types::MR
            | record_types::MX
            | record_types::NS
            | record_types::PTR
            | record_types::SOA => Ok(false),
            record_types::SIG | record_types::RRSIG => {
                // Signer's name appears at an offset of 18 bytes.
                if rdata.len() <= 18 {
                    return Ok(false);
                }
                name_uses_compression(&rdata[18..])
            }
            record_types::SRV => {
                // Target name appears at an offset of 6 bytes.
                if rdata.len() <= 6 {
                    return Ok(false);
                }
                name_uses_compression(&rdata[6..])
            }
            record_types::NAPTR => {
                // The replacement name appears after two fixed length fields and three
                // variable-length `character-string` fields.
                let mut offset = 4;
                for _ in 0..3 {
                    if rdata.len() <= offset {
                        return Ok(false);
                    }
                    let character_string_length = rdata[offset];
                    offset += 1 + character_string_length as usize;
                }
                if rdata.len() <= offset {
                    return Ok(false);
                }
                name_uses_compression(&rdata[offset..])
            }
            record_types::NSEC => name_uses_compression(rdata),
            record_types::SVCB | record_types::HTTPS => {
                // Target name appears at an offset of 2 bytes.
                if rdata.len() <= 2 {
                    return Ok(false);
                }
                name_uses_compression(&rdata[2..])
            }
            record_types::TSIG => name_uses_compression(rdata),
            record_types::ANAME => name_uses_compression(rdata),
            _ => Ok(false),
        }
    }
}

/// Walks through a DNS message and returns slices spanning each resource record in the main three
/// sections.
fn split_rrs(
    buffer: &[u8],
    query_count: u16,
    rr_count: u16,
) -> Result<Vec<Record<'_>>, &'static str> {
    let mut offset = 12;

    // Skip over the question section.
    for _ in 0..query_count {
        if offset >= buffer.len() {
            return Err("question section queries extend past end of message");
        }
        offset += name_length(&buffer[offset..])?; // QNAME
        offset += 2; // QTYPE
        offset += 2; // QCLASS
    }

    let mut output = Vec::new();
    for _ in 0..rr_count {
        offset += name_length(&buffer[offset..])?; // NAME

        // TYPE
        let r#type = u16::from_be_bytes(buffer[offset..offset + 2].try_into().unwrap());
        offset += 2;

        offset += 2; // CLASS

        offset += 4; // TTL

        // RDLENGTH
        let rdlength = u16::from_be_bytes(buffer[offset..offset + 2].try_into().unwrap());
        offset += 2;

        // RDATA
        let rdata = &buffer[offset..offset + rdlength as usize];
        offset += rdlength as usize;

        output.push(Record { r#type, rdata });
    }

    Ok(output)
}

const LABEL_TYPE_MASK: u8 = 0b1100_0000;
const COMPRESSED_LABEL_TYPE: u8 = 0b1100_0000;

/// Determines the encoded length of a name inside a DNS message.
fn name_length(input: &[u8]) -> Result<usize, &'static str> {
    let mut offset = 0;

    loop {
        let byte = input[offset];
        if byte == 0 {
            return Ok(offset + 1);
        }
        match byte & LABEL_TYPE_MASK {
            0 => offset += 1 + byte as usize,
            COMPRESSED_LABEL_TYPE => return Ok(offset + 2),
            _ => return Err("unsupported label type in name"),
        }
        if offset >= input.len() {
            return Err("name label length is longer than the remainder of the message");
        }
    }
}

/// Checks whether an encoded name ends with a compressed label pointer.
fn name_uses_compression(input: &[u8]) -> Result<bool, &'static str> {
    let mut offset = 0;
    loop {
        let byte = input[offset];
        if byte == 0 {
            return Ok(false);
        }
        match byte & LABEL_TYPE_MASK {
            0 => offset += 1 + byte as usize,
            COMPRESSED_LABEL_TYPE => return Ok(true),
            _ => return Err("unsupported label type in name"),
        }
        if offset >= input.len() {
            return Err("name label length is longer than the remainder of the message");
        }
    }
}

/// Re-sort the list of records such that OPT records are at the end.
///
/// Hickory DNS extracts any OPT record from the rest of the additional section record, and stores
/// it separately, then re-encodes it at the end. To adapt to this, we do a stable sort of records
/// before and after re-encoding. Then, records should line up with each other one-to-one in the two
/// vectors again.
fn sort_opt(rrs: &mut Vec<Record<'_>>) {
    rrs.sort_by_key(|record| record.r#type == record_types::OPT);
}

/// A decompressed domain name.
#[derive(Debug, PartialEq, Eq)]
struct Name(Vec<u8>);

impl Decompressible for Name {
    /// Decompress a name in a DNS message.
    fn decompress(compressed_name: &[u8], message: &[u8]) -> Result<Self, &'static str> {
        let mut output = Vec::with_capacity(compressed_name.len());
        let mut buffer = compressed_name;
        loop {
            if buffer[0] & LABEL_TYPE_MASK == COMPRESSED_LABEL_TYPE {
                let offset = u16::from_be_bytes([buffer[0] & !LABEL_TYPE_MASK, buffer[1]]) as usize;
                buffer = &message[offset..];
            } else {
                let length = (buffer[0] & !LABEL_TYPE_MASK) as usize;
                output.extend_from_slice(&buffer[0..length + 1]);
                if length == 0 {
                    return Ok(Self(output));
                }
                buffer = &buffer[length + 1..];
            }
        }
    }
}

/// `RDATA` for a `MINFO` record, with decompressed names.
#[derive(Debug, PartialEq, Eq)]
struct Minfo {
    rmailbx: Name,
    emailbx: Name,
}

impl Decompressible for Minfo {
    /// Decompress a MINFO RDATA.
    fn decompress(compressed_rdata: &[u8], message: &[u8]) -> Result<Self, &'static str> {
        let emailbx_offset = name_length(compressed_rdata)?;
        let rmailbx = Name::decompress(compressed_rdata, message)?;
        let emailbx = Name::decompress(&compressed_rdata[emailbx_offset..], message)?;

        Ok(Minfo { rmailbx, emailbx })
    }
}

/// `RDATA` for a `MX` record, with a decompressed name.
#[derive(Debug, PartialEq, Eq)]
struct Mx {
    preference: [u8; 2],
    exchange: Name,
}

impl Decompressible for Mx {
    fn decompress(input: &[u8], message: &[u8]) -> Result<Self, &'static str> {
        let preference = input[0..2].try_into().unwrap();
        let exchange = Name::decompress(&input[2..], message)?;
        Ok(Self {
            preference,
            exchange,
        })
    }
}

/// `RDATA` for a `SOA` record, with decompressed names.
#[derive(Debug, PartialEq, Eq)]
struct Soa {
    mname: Name,
    rname: Name,
    rest: Vec<u8>,
}

impl Decompressible for Soa {
    /// Decompress a SOA RDATA.
    fn decompress(compressed_rdata: &[u8], message: &[u8]) -> Result<Self, &'static str> {
        let rname_offset = name_length(compressed_rdata)?;
        let serial_offset = rname_offset + name_length(&compressed_rdata[rname_offset..])?;

        let mname = Name::decompress(compressed_rdata, message)?;
        let rname = Name::decompress(&compressed_rdata[rname_offset..], message)?;

        let rest = compressed_rdata[serial_offset..].to_vec();

        Ok(Soa { mname, rname, rest })
    }
}

/// Any part of a message containing names that can be decompressed, and then compared.
trait Decompressible: Debug + PartialEq + Eq + Sized {
    /// Decompress one portion of a message, and return some representation of it.
    ///
    /// The second argument is the entire DNS message. Compressed names will refer to byte offsets
    /// within this message.
    fn decompress(input: &[u8], message: &[u8]) -> Result<Self, &'static str>;
}

mod record_types {
    pub(super) const NS: u16 = 2;
    pub(super) const MD: u16 = 3;
    pub(super) const MF: u16 = 4;
    pub(super) const CNAME: u16 = 5;
    pub(super) const SOA: u16 = 6;
    pub(super) const MB: u16 = 7;
    pub(super) const MG: u16 = 8;
    pub(super) const MR: u16 = 9;
    pub(super) const PTR: u16 = 12;
    pub(super) const MINFO: u16 = 14;
    pub(super) const MX: u16 = 15;
    pub(super) const SIG: u16 = 24;
    pub(super) const SRV: u16 = 33;
    pub(super) const NAPTR: u16 = 35;
    pub(super) const OPT: u16 = 41;
    pub(super) const RRSIG: u16 = 46;
    pub(super) const NSEC: u16 = 47;
    pub(super) const SVCB: u16 = 64;
    pub(super) const HTTPS: u16 = 65;
    pub(super) const TSIG: u16 = 250;
    pub(super) const ANAME: u16 = 65305;
}
