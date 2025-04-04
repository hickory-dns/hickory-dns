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
    assert_eq!(original[4..6], reencoded[4..6]);
    let query_count = u16::from_be_bytes(reencoded[4..6].try_into().unwrap());
    assert_eq!(original[6..8], reencoded[6..8]);
    let answer_count = u16::from_be_bytes(reencoded[6..8].try_into().unwrap());
    assert_eq!(original[8..10], reencoded[8..10]);
    let name_server_count = u16::from_be_bytes(reencoded[8..10].try_into().unwrap());
    assert_eq!(original[10..12], reencoded[10..12]);
    let additional_records_count = u16::from_be_bytes(reencoded[10..12].try_into().unwrap());

    let rr_count = answer_count + name_server_count + additional_records_count;
    let original_rrs = split_rrs(original, query_count, rr_count);
    let reencoded_rrs = split_rrs(reencoded, query_count, rr_count);

    for (original_rr, reencoded_rr) in original_rrs.into_iter().zip(reencoded_rrs.into_iter()) {
        assert_eq!(original_rr.r#type, reencoded_rr.r#type);
        if let Err(()) = compare_rr(original, original_rr, reencoded, reencoded_rr) {
            println!("Parsed message: {message:?}");
            println!("Record type: {}", original_rr.r#type);
            println!("Original: {:02x?}", &original_rr.rdata);
            println!("Re-encoded: {:02x?}", &reencoded_rr.rdata);
            panic!("record RDATA was not preserved when decoding and re-encoding");
        }
    }
}

fn compare_rr(
    original: &[u8],
    original_rr: Record<'_>,
    reencoded: &[u8],
    reencoded_rr: Record<'_>,
) -> Result<(), ()> {
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
            let original_decompressed = Name::decompress(original_rr.rdata, original);
            let reencoded_decompressed = Name::decompress(reencoded_rr.rdata, reencoded);
            if original_decompressed == reencoded_decompressed {
                Ok(())
            } else {
                Err(())
            }
        }
        record_types::SOA => {
            // RDATA consists of seven different fields.
            let original_decompressed = Soa::decompress(original_rr.rdata, original);
            let reencoded_decompressed = Soa::decompress(reencoded_rr.rdata, reencoded);
            if original_decompressed == reencoded_decompressed {
                Ok(())
            } else {
                Err(())
            }
        }
        record_types::MINFO => {
            // RDATA consists of two `<domain-name>`s.
            let original_decompressed = Minfo::decompress(original_rr.rdata, original);
            let reencoded_decompressed = Minfo::decompress(reencoded_rr.rdata, reencoded);
            if original_decompressed == reencoded_decompressed {
                Ok(())
            } else {
                Err(())
            }
        }
        record_types::MX => {
            // RDATA consists of a 16-bit integer and a `<domain-name>`.
            let original_decompressed = Mx::decompress(original_rr.rdata, original);
            let reencoded_decompressed = Mx::decompress(reencoded_rr.rdata, reencoded);
            if original_decompressed == reencoded_decompressed {
                Ok(())
            } else {
                Err(())
            }
        }
        record_types::OPT => {
            // Ignore OPT records because they are reconstructed hop-by-hop, not passed through
            // transparently.
            Ok(())
        }
        _ => Err(()),
    }
}

#[derive(Debug, Clone, Copy)]
struct Record<'a> {
    r#type: u16,
    rdata: &'a [u8],
}

/// Walks through a DNS message and returns slices spanning each resource record in the main three
/// sections.
fn split_rrs(buffer: &[u8], query_count: u16, rr_count: u16) -> Vec<Record<'_>> {
    let mut offset = 12;

    // Skip over the question section.
    for _ in 0..query_count {
        offset += name_length(&buffer[offset..]); // QNAME
        offset += 2; // QTYPE
        offset += 2; // QCLASS
    }

    let mut output = Vec::new();
    for _ in 0..rr_count {
        offset += name_length(&buffer[offset..]); // NAME

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

    output
}

const LABEL_TYPE_MASK: u8 = 0b1100_0000;
const COMPRESSED_LABEL_TYPE: u8 = 0b1100_0000;

/// Determines the encoded length of a name inside a DNS message.
fn name_length(input: &[u8]) -> usize {
    let mut offset = 0;

    while input[offset] != 0 && input[offset] & LABEL_TYPE_MASK != COMPRESSED_LABEL_TYPE {
        let length = input[offset];
        offset += 1 + length as usize;
    }

    offset + 1
}

/// A decompressed domain name.
#[derive(Debug, PartialEq, Eq)]
struct Name(Vec<u8>);

impl Decompressible for Name {
    /// Decompress a name in a DNS message.
    fn decompress(compressed_name: &[u8], message: &[u8]) -> Self {
        let mut output = Vec::with_capacity(compressed_name.len());
        let mut buffer = compressed_name;
        loop {
            if buffer[0] & LABEL_TYPE_MASK == COMPRESSED_LABEL_TYPE {
                let offset = (buffer[0] & !LABEL_TYPE_MASK) as usize;
                buffer = &message[offset..];
            } else {
                let length = (buffer[0] & !LABEL_TYPE_MASK) as usize;
                output.extend_from_slice(&buffer[0..length + 1]);
                if length == 0 {
                    return Self(output);
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
    fn decompress(compressed_rdata: &[u8], message: &[u8]) -> Self {
        let emailbx_offset = name_length(compressed_rdata);
        let rmailbx = Name::decompress(compressed_rdata, message);
        let emailbx = Name::decompress(&compressed_rdata[emailbx_offset..], message);

        Minfo { rmailbx, emailbx }
    }
}

/// `RDATA` for a `MX` record, with a decompressed name.
#[derive(Debug, PartialEq, Eq)]
struct Mx {
    preference: [u8; 2],
    exchange: Name,
}

impl Decompressible for Mx {
    fn decompress(input: &[u8], message: &[u8]) -> Self {
        let preference = input[0..2].try_into().unwrap();
        let exchange = Name::decompress(&input[2..], message);
        Self {
            preference,
            exchange,
        }
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
    fn decompress(compressed_rdata: &[u8], message: &[u8]) -> Self {
        let rname_offset = name_length(compressed_rdata);
        let serial_offset = rname_offset + name_length(&compressed_rdata[rname_offset..]);

        let mname = Name::decompress(compressed_rdata, message);
        let rname = Name::decompress(&compressed_rdata[rname_offset..], message);

        let rest = compressed_rdata[serial_offset..].to_vec();

        Soa { mname, rname, rest }
    }
}

/// Any part of a message containing names that can be decompressed, and then compared.
trait Decompressible: Debug + PartialEq + Eq {
    /// Decompress one portion of a message, and return some representation of it.
    ///
    /// The second argument is the entire DNS message. Compressed names will refer to byte offsets
    /// within this message.
    fn decompress(input: &[u8], message: &[u8]) -> Self;
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
    pub(super) const OPT: u16 = 41;
}
