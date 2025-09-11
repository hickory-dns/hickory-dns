use std::{fs, path::Path};

use base64::prelude::*;
use data_encoding::{BASE32_DNSSEC, HEXUPPER};
use hickory_proto::{
    dnssec::{
        Algorithm, Nsec3HashAlgorithm, PublicKeyBuf,
        rdata::{DNSKEY, DNSSECRData, NSEC3, NSEC3PARAM, RRSIG, SigInput},
    },
    rr::{RData, Record, RecordType, domain::Name, rdata},
};
use time::{PrimitiveDateTime, macros::format_description};

// Minimal zone file parser for NSEC3 not covered test.  This will go away once there are record
// decoders for the DNSSEC record types in the RDataParser interface.
pub(crate) fn parse_zone_file(path: &Path) -> Result<Vec<Record>, String> {
    let buf = fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e:?}", path.display()))?;

    let mut records = vec![];

    for (i, rec) in buf.lines().enumerate() {
        let tokens = rec.split_whitespace().collect::<Vec<&str>>();
        if tokens.len() < 4 {
            return Err(format!("Error on line {i}: only {} tokens", tokens.len()));
        }
        match tokens[3] {
            "A" => {
                records.push(Record::from_rdata(
                    Name::from_ascii(tokens[0])
                        .map_err(|e| format!("A record name error: {e:?}"))?,
                    tokens[1]
                        .parse()
                        .map_err(|e| format!("A record TTL error: {e:?}"))?,
                    RData::A(rdata::A(
                        tokens[4]
                            .parse()
                            .map_err(|e| format!("A record IP error: {e:?}"))?,
                    )),
                ));
            }
            "NS" => {
                records.push(Record::from_rdata(
                    Name::from_ascii(tokens[0])
                        .map_err(|e| format!("NS record name error: {e:?}"))?,
                    tokens[1]
                        .parse()
                        .map_err(|e| format!("NS record TTL error: {e:?}"))?,
                    RData::NS(rdata::NS(
                        Name::from_ascii(tokens[4])
                            .map_err(|e| format!("NS record name error: {e:?}"))?,
                    )),
                ));
            }
            "SOA" => {
                records.push(Record::from_rdata(
                    Name::from_ascii(tokens[0])
                        .map_err(|e| format!("SOA record name error: {e:?}"))?,
                    tokens[1]
                        .parse()
                        .map_err(|e| format!("SOA record TTL error: {e:?}"))?,
                    RData::SOA(rdata::SOA::new(
                        Name::from_ascii(tokens[4])
                            .map_err(|e| format!("SOA record mname error: {e:?}"))?,
                        Name::from_ascii(tokens[5])
                            .map_err(|e| format!("SOA record rname error: {e:?}"))?,
                        tokens[6]
                            .parse()
                            .map_err(|e| format!("SOA record serial error: {e:?}"))?,
                        tokens[7]
                            .parse()
                            .map_err(|e| format!("SOA record refresh error: {e:?}"))?,
                        tokens[8]
                            .parse()
                            .map_err(|e| format!("SOA record retry error: {e:?}"))?,
                        tokens[9]
                            .parse()
                            .map_err(|e| format!("SOA record expire error: {e:?}"))?,
                        tokens[10]
                            .parse()
                            .map_err(|e| format!("SOA record minimum error: {e:?}"))?,
                    )),
                ));
            }
            "RRSIG" => {
                let date_format = format_description!("[year][month][day][hour][minute][second]");
                let sig_base64 = tokens[12..].join("");
                let sig_bytes = &BASE64_STANDARD
                    .decode(sig_base64.as_bytes())
                    .map_err(|e| format!("RRSIG signature decode error: {e:?}"))?;

                let type_covered = match tokens[4] {
                    "DNSKEY" => RecordType::DNSKEY,
                    "NSEC3" => RecordType::NSEC3,
                    "SOA" => RecordType::SOA,
                    "A" => RecordType::A,
                    "NS" => RecordType::NS,
                    "NSEC3PARAM" => RecordType::NSEC3PARAM,
                    _ => {
                        return Err(format!(
                            "RRSIG covered type error: unexpected type {}",
                            tokens[4]
                        ));
                    }
                };

                let rrsig = RRSIG::from_sig(
                    SigInput {
                        type_covered,
                        algorithm: Algorithm::from_u8(
                            tokens[5]
                                .parse()
                                .map_err(|e| format!("RRSIG algorithm error: {e:?}"))?,
                        ),
                        num_labels: tokens[6]
                            .parse()
                            .map_err(|e| format!("RRSIG num labels errors: {e:?}"))?,
                        original_ttl: tokens[7]
                            .parse()
                            .map_err(|e| format!("RRSIG original ttl error: {e:?}"))?,
                        sig_expiration: (PrimitiveDateTime::parse(tokens[8], &date_format)
                            .map_err(|e| format!("RRSIG sig expiration error: {e:?}"))?
                            .as_utc()
                            .unix_timestamp() as u32)
                            .into(),
                        sig_inception: (PrimitiveDateTime::parse(tokens[9], &date_format)
                            .map_err(|e| format!("RRSIG sig inception error: {e:?}"))?
                            .as_utc()
                            .unix_timestamp() as u32)
                            .into(),
                        key_tag: tokens[10]
                            .parse()
                            .map_err(|e| format!("RRSIG key tag error: {e:?}"))?,
                        signer_name: Name::from_ascii(tokens[11])
                            .map_err(|e| format!("RRSIG signer name error: {e:?}"))?,
                    },
                    sig_bytes.to_vec(),
                );

                records.push(Record::from_rdata(
                    Name::from_ascii(tokens[0]).map_err(|e| format!("RRSIG name error: {e:?}"))?,
                    tokens[1]
                        .parse()
                        .map_err(|e| format!("RRSIG ttl error: {e:?}"))?,
                    RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
                ));
            }
            "NSEC3" => {
                let mut types = vec![];

                for rtype in &tokens[9..] {
                    match *rtype {
                        "DNSKEY" => types.push(RecordType::DNSKEY),
                        "RRSIG" => types.push(RecordType::RRSIG),
                        "SOA" => types.push(RecordType::SOA),
                        "A" => types.push(RecordType::A),
                        "NS" => types.push(RecordType::NS),
                        "NSEC3PARAM" => types.push(RecordType::NSEC3PARAM),
                        _ => return Err(format!("NSEC3 unexpected covered type: {rtype}")),
                    }
                }

                let salt = if tokens[7] == "-" {
                    vec![]
                } else {
                    HEXUPPER
                        .decode(tokens[7].as_bytes())
                        .map_err(|e| format!("NSEC3 unable to decode salt: {e:?}"))?
                };

                records.push(Record::from_rdata(
                    Name::from_ascii(tokens[0]).map_err(|e| format!("NSEC3 name error: {e:?}"))?,
                    tokens[1]
                        .parse()
                        .map_err(|e| format!("NSEC3 ttl error: {e:?}"))?,
                    RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                        Nsec3HashAlgorithm::try_from(
                            tokens[4]
                                .parse::<u8>()
                                .map_err(|e| format!("NSEC3PARAM algorithm error: {e:?}"))?,
                        )
                        .map_err(|e| format!("NSEC3PARAM algorithm error: {e:?}"))?,
                        tokens[5] == "1",
                        tokens[6]
                            .parse()
                            .map_err(|e| format!("NSEC3 iterations error: {e:?}"))?,
                        salt,
                        BASE32_DNSSEC
                            .decode(tokens[8].as_bytes())
                            .map_err(|e| format!("NSEC3 base32 decode error: {e:?}"))?,
                        types,
                    ))),
                ));
            }
            "DNSKEY" => {
                let key_base64 = tokens[7..].join("");
                let key_bytes = &BASE64_STANDARD.decode(key_base64.as_bytes()).map_err(|e| {
                    format!("DNSKEY base64 key decode error: {e:?} for {key_base64}")
                })?;

                records.push(Record::from_rdata(
                    Name::from_ascii(tokens[0]).map_err(|e| format!("DNSKEY name error: {e:?}"))?,
                    tokens[1]
                        .parse()
                        .map_err(|e| format!("DNSKEY ttl error: {e:?}"))?,
                    RData::DNSSEC(DNSSECRData::DNSKEY(DNSKEY::new(
                        true,
                        tokens[4] == "257",
                        false,
                        PublicKeyBuf::new(
                            key_bytes.to_vec(),
                            Algorithm::from_u8(
                                tokens[6]
                                    .parse()
                                    .map_err(|e| format!("DNSKEY algorithm error: {e:?}"))?,
                            ),
                        ),
                    ))),
                ));
            }
            "NSEC3PARAM" => {
                records.push(Record::from_rdata(
                    Name::from_ascii(tokens[0])
                        .map_err(|e| format!("NSEC3PARAM name error: {e:?}"))?,
                    tokens[1]
                        .parse()
                        .map_err(|e| format!("NSEC3PARAM ttl error: {e:?}"))?,
                    RData::DNSSEC(DNSSECRData::NSEC3PARAM(NSEC3PARAM::new(
                        Nsec3HashAlgorithm::try_from(
                            tokens[4]
                                .parse::<u8>()
                                .map_err(|e| format!("NSEC3PARAM algorithm error: {e:?}"))?,
                        )
                        .map_err(|e| format!("NSEC3PARAM algorithm error: {e:?}"))?,
                        tokens[5] == "1",
                        tokens[6]
                            .parse()
                            .map_err(|e| format!("NSEC3PARAM iterations error: {e:?}"))?,
                        if tokens[7] == "-" {
                            vec![]
                        } else {
                            tokens[8].as_bytes().to_vec()
                        },
                    ))),
                ));
            }
            _ => return Err(format!("unexpected record type: {}", tokens[3])),
        }
    }

    Ok(records)
}
