use crate::{Handler, Transport, zone_file};
use anyhow::{Context, Error, Result, anyhow};
use async_trait::async_trait;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use data_encoding::BASE32_DNSSEC;
use hickory_net::{
    client::Client,
    runtime::TokioRuntimeProvider,
    tcp::TcpClientStream,
    xfer::{DnsHandle, FirstAnswer},
};
use hickory_proto::{
    dnssec::{
        Algorithm, DnssecSigner, Nsec3HashAlgorithm, PublicKeyBuf,
        crypto::EcdsaSigningKey,
        rdata::{DNSKEY, DNSSECRData, NSEC, NSEC3, NSEC3PARAM, RRSIG},
    },
    op::{
        DnsRequest, DnsRequestOptions, DnsResponse, Edns, Message, MessageType, Query, ResponseCode,
    },
    rr::{
        DNSClass, RData, Record, RecordSet, RecordType,
        domain::Name,
        rdata::{self, NS},
    },
};
use std::{
    env,
    net::IpAddr,
    ops::DerefMut,
    path::Path,
    sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering},
    time::Duration,
};
use time::OffsetDateTime;

/// This handler generates a valid A-record response to any query
pub(crate) fn base_handler(bytes: &[u8], _transport: Transport) -> Result<Option<Vec<u8>>> {
    let mut msg = Message::from_vec(bytes)?.into_response();
    let name = msg.queries[0].name().clone();

    msg.metadata.recursion_desired = false;
    msg.add_answer(Record::from_rdata(
        name,
        1,
        RData::A(rdata::A([192, 0, 2, 1].into())),
    ))
    .to_vec()
    .map(Some)
    .with_context(|| "base handler: could not serialize Message")
}

/// This handler responds to any messages with an incorrect transaction (query) id.
pub(crate) fn bad_txid_handler(bytes: &[u8], _transport: Transport) -> Result<Option<Vec<u8>>> {
    let mut msg = Message::from_vec(bytes)?.into_response();
    let name = msg.queries[0].name().clone();

    msg.metadata.id = if msg.metadata.id == 65535 {
        0
    } else {
        msg.metadata.id + 1
    };
    msg.metadata.recursion_desired = false;
    msg.metadata.authoritative = true;
    msg.add_answer(Record::from_rdata(
        name,
        1,
        RData::A(rdata::A([192, 0, 2, 1].into())),
    ))
    .to_vec()
    .map(Some)
    .with_context(|| "bad txid handler: could not serialize Message")
}

/// This handler responds to any messages with an empty message (no response records)
pub(crate) fn empty_response_handler(
    bytes: &[u8],
    _transport: Transport,
) -> Result<Option<Vec<u8>>> {
    Message::from_vec(bytes)?
        .into_response()
        .to_vec()
        .map(Some)
        .with_context(|| "empty response handler: could not serialize Message")
}

/// This handler responds to UDP requests with the truncation bit set.  If the test server is
/// configured to listen via TCP and a request is received over a TCP channel, the truncation bit
/// is not set.
pub(crate) fn truncated_response_handler(
    bytes: &[u8],
    transport: Transport,
) -> Result<Option<Vec<u8>>> {
    let mut msg = Message::from_vec(bytes)?.into_response();
    let name = msg.queries[0].name().clone();

    if name != Name::from_ascii("example.testing.").unwrap()
        && msg.queries[0].query_type() != RecordType::TXT
    {
        msg.metadata.response_code = ResponseCode::NXDomain;
        return msg
            .to_vec()
            .map(Some)
            .with_context(|| "truncated response handler: could not serialize Message");
    }

    let (protocol_str, counter_str) = match transport {
        Transport::Tcp => (
            String::from("protocol=TCP"),
            format!(
                "counter={}",
                TRUNCATED_TCP_COUNTER.fetch_add(1, Ordering::Relaxed)
            ),
        ),
        Transport::Udp => (
            String::from("protocol=UDP"),
            format!(
                "counter={}",
                TRUNCATED_UDP_COUNTER.fetch_add(1, Ordering::Relaxed)
            ),
        ),
    };

    msg.metadata.authoritative = true;
    msg.metadata.recursion_desired = false;
    msg.metadata.truncation = match transport {
        Transport::Udp => true,
        Transport::Tcp => false,
    };
    msg.add_answer(Record::from_rdata(
        name,
        86400,
        RData::TXT(rdata::TXT::new(vec![protocol_str, counter_str])),
    ))
    .to_vec()
    .map(Some)
    .with_context(|| "truncated response handler: could not serialize Message")
}

/// This handler simulates packet loss by not responding to the first query it receives
pub(crate) fn packet_loss_handler(bytes: &[u8], _transport: Transport) -> Result<Option<Vec<u8>>> {
    let mut msg = Message::from_vec(bytes)?.into_response();
    let query = msg.queries[0].clone();
    let name = query.name().clone();
    let q_type = query.query_type();

    if name == Name::from_ascii("example.testing.").unwrap() {
        if !PACKET_LOSS_MARKER.load(Ordering::Relaxed) && q_type == RecordType::A {
            PACKET_LOSS_MARKER.store(true, Ordering::Relaxed);
            return Ok(None);
        }
        msg.metadata.recursion_desired = false;
        msg.metadata.authoritative = true;
        msg.add_answer(Record::from_rdata(
            name,
            86400,
            RData::A(rdata::A([192, 0, 2, 1].into())),
        ));
    } else {
        msg.metadata.response_code = ResponseCode::NXDomain;
    }

    msg.to_vec()
        .map(Some)
        .with_context(|| "packet loss handler: could not serialize Message")
}

/// This handler does not preserve the case of query names in responses.
pub(crate) fn bad_case_handler(bytes: &[u8], transport: Transport) -> Result<Option<Vec<u8>>> {
    let mut msg = Message::from_vec(bytes)?.into_response();
    let mut queries = msg.queries;

    // This doesn't use Name::randomize_case_labels since that doesn't guarantee
    // input != output.
    let mut mod_name = Name::new();
    for label in queries[0].name.iter() {
        let mut new_label = label.to_vec();
        for ch in &mut new_label {
            if ch.is_ascii_alphabetic() {
                *ch ^= 0x20; // flip case
            }
        }
        mod_name = mod_name.append_label(new_label).unwrap();
    }
    queries[0].name = mod_name;
    let name = queries[0].name().clone();
    msg.queries = queries;

    msg.metadata.authoritative = true;
    msg.metadata.recursion_desired = false;
    msg.add_answer(Record::from_rdata(
        name,
        0,
        RData::A(rdata::A(match transport {
            Transport::Tcp => [192, 0, 2, 2].into(),
            Transport::Udp => [192, 0, 2, 1].into(),
        })),
    ))
    .to_vec()
    .map(Some)
    .with_context(|| "bad case handler: could not serialize Message")
}

/// This handler generates a large number of lengthy CNAME records to resolve
pub(crate) fn cname_loop_handler(bytes: &[u8], _transport: Transport) -> Result<Option<Vec<u8>>> {
    let mut msg = Message::from_vec(bytes)?.into_response();
    let name = msg.queries[0].name().clone();

    let Some(host) = name.iter().next() else {
        return Ok(None);
    };

    let Ok(host_str) = std::str::from_utf8(host) else {
        return Ok(None);
    };

    let round = host_str
        .split('-')
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .map(|n| n + 1)
        .unwrap_or(0);

    if round > 9 {
        msg.add_answer(Record::from_rdata(
            name,
            1,
            RData::A(rdata::A([192, 0, 2, 1].into())),
        ));
    } else {
        for i in 0..40 {
            msg.add_answer(Record::from_rdata(
                name.clone(),
                1,
                RData::CNAME(rdata::CNAME(
                    Name::from_ascii(format!("c-{round}-{i}.testing.")).unwrap(),
                )),
            ));
        }
    }

    msg.metadata.authoritative = true;
    msg.metadata.recursion_desired = false;
    msg.to_vec()
        .map(Some)
        .with_context(|| "cname loop handler: could not serialize Message")
}

/// This handler is for testing that NSEC3 coverage validation. It should respond to queries in the
/// following way:
///  * DNSKEY queries - return the correct records
///  * SOA queries - return the correct records
///  * A query for subdomain-0.hickory-dns.testing. - Return correct A + RRSIG RRset.
///  * A query for validnx.hickory-dns.testing. - Return NXDOMAIN + valid NSEC3/RRSIG RRSet.
///  * A query for any other name - Return NXDOMAIN + invalid (non-covering) NSEC3/RRSIG RRset.
pub(crate) fn nsec3_nocover_handler(
    bytes: &[u8],
    _transport: Transport,
) -> Result<Option<Vec<u8>>> {
    let mut msg = Message::from_vec(bytes)?.into_response();
    let query_name = msg.queries[0].name().clone();
    let query_type = msg.queries[0].query_type();

    let origin_name = Name::from_ascii("hickory-dns.testing.").unwrap();
    let correct_name = origin_name.prepend_label("subdomain-0")?;
    let valid_nx_name = origin_name.prepend_label("validnx")?;

    let records = read_zone_file()?;

    match query_type {
        RecordType::DNSKEY | RecordType::SOA => {
            msg.add_answers(records.into_iter().filter(|x| match x.record_type() {
                RecordType::DNSKEY | RecordType::SOA => x.record_type() == query_type,
                RecordType::RRSIG => {
                    let Some(rrsig) = x.try_borrow::<RRSIG>() else {
                        return false;
                    };
                    rrsig.data().input().type_covered == query_type
                }
                _ => false,
            }));
        }
        RecordType::A if query_name == correct_name => {
            for record in records {
                if record.name != correct_name {
                    continue;
                }

                if record.record_type() == RecordType::A {
                    msg.add_answer(record.clone());
                } else if record.record_type() == RecordType::RRSIG {
                    let Some(rrsig) = record.try_borrow::<RRSIG>() else {
                        continue;
                    };

                    if rrsig.data().input().type_covered == RecordType::A {
                        msg.add_answer(record.clone());
                    }
                }
            }
        }
        RecordType::A if query_name == valid_nx_name => {
            msg.metadata.response_code = ResponseCode::NXDomain;

            let Some(params_rec) = records
                .clone()
                .into_iter()
                .filter(|x| x.record_type() == RecordType::NSEC3PARAM)
                .to_owned()
                .next()
            else {
                return Err(Error::msg("Could not get nsec3param record"));
            };

            let Some(params_inner) = params_rec.try_borrow::<NSEC3PARAM>() else {
                return Err(Error::msg("Could not get nsec3param record data"));
            };

            let b32_hasher = |name: &Name| {
                BASE32_DNSSEC.encode(
                    Nsec3HashAlgorithm::SHA1
                        .hash(
                            params_inner.data().salt(),
                            name,
                            params_inner.data().iterations(),
                        )
                        .unwrap()
                        .as_ref(),
                )
            };

            let mut names = vec![];
            for rec in records.iter().filter(|x| {
                x.record_type() != RecordType::NSEC3 && x.record_type() != RecordType::RRSIG
            }) {
                let hash = b32_hasher(&rec.name);
                if !names.contains(&hash) {
                    names.push(hash);
                }
            }

            names.sort();

            println!("Names: {names:?}");
            let b32_hashed_valid_name = b32_hasher(&valid_nx_name);
            let b32_hashed_closest_name = b32_hasher(&origin_name);
            let b32_hashed_wildcard_name = b32_hasher(&origin_name.prepend_label("*")?);

            let mut closest_encloser = None;
            let mut covering_name = None;
            let mut wildcard_name = None;

            // Get NSEC3 covering, closest encloser, and next closer proofs
            for (i, name) in names.iter().enumerate() {
                if **name > *b32_hashed_valid_name && covering_name.is_none() {
                    covering_name =
                        Some(names[if i == 0 { names.len() - 1 } else { i - 1 }].clone());
                    println!(
                        "Covering record for {b32_hashed_valid_name}: {}",
                        names[if i == 0 { names.len() - 1 } else { i - 1 }]
                    );
                }

                if **name > *b32_hashed_wildcard_name && wildcard_name.is_none() {
                    wildcard_name =
                        Some(names[if i == 0 { names.len() - 1 } else { i - 1 }].clone());
                    println!(
                        "Wildcard record for {b32_hashed_valid_name}: {}",
                        names[if i == 0 { names.len() - 1 } else { i - 1 }]
                    );
                }

                if **name == b32_hashed_closest_name {
                    closest_encloser = Some(name.clone());
                    println!("Closest encloser record for {b32_hashed_valid_name}: {name}",);
                }
            }

            let nsec3_name = origin_name.prepend_label(covering_name.unwrap())?;
            let nsec3_closest_name = origin_name.prepend_label(closest_encloser.unwrap())?;
            let nsec3_wildcard_name = origin_name.prepend_label(wildcard_name.unwrap())?;

            for record in records {
                match record.record_type() {
                    RecordType::NSEC3
                        if (record.name == nsec3_name
                            || record.name == nsec3_closest_name
                            || record.name == nsec3_wildcard_name) =>
                    {
                        msg.add_authority(record);
                    }
                    RecordType::SOA => {
                        msg.add_authority(record);
                    }
                    RecordType::RRSIG => {
                        let Some(rrsig) = record.try_borrow::<RRSIG>() else {
                            continue;
                        };

                        match rrsig.data().input().type_covered {
                            RecordType::SOA => {
                                msg.add_authority(record);
                            }
                            RecordType::NSEC3
                                if (record.name == nsec3_name
                                    || record.name == nsec3_closest_name
                                    || record.name == nsec3_wildcard_name) =>
                            {
                                msg.add_authority(record);
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
        RecordType::A => {
            msg.metadata.response_code = ResponseCode::NXDomain;

            let mut nsec3_name = None;
            for record in records {
                if record.record_type() == RecordType::SOA {
                    msg.add_additional(record);
                } else if record.record_type() == RecordType::NSEC3 {
                    if nsec3_name.is_none() {
                        let rec = record.clone();
                        let Some(nsec3) = rec.try_borrow::<NSEC3>() else {
                            continue;
                        };
                        for rtype in nsec3.data().type_bit_maps() {
                            // Find the first NSEC3 record that covers an A record and save
                            // the record name so we can find a matching RRSIG.
                            if rtype == RecordType::A {
                                nsec3_name = Some(nsec3.name().clone());
                                msg.add_additional(record);
                                break;
                            }
                        }
                    }
                } else if record.record_type() == RecordType::RRSIG {
                    let Some(rrsig) = record.try_borrow::<RRSIG>() else {
                        continue;
                    };

                    match rrsig.data().input().type_covered {
                        RecordType::SOA => {
                            msg.add_additional(record);
                        }
                        RecordType::NSEC3 => {
                            let Some(name) = nsec3_name.clone() else {
                                continue;
                            };
                            if name == record.name {
                                msg.add_additional(record);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        _ => {}
    }

    msg.metadata.recursion_desired = true;
    msg.metadata.recursion_available = true;
    msg.metadata.authoritative = true;
    msg.metadata.authentic_data = true;
    msg.to_vec()
        .map(Some)
        .with_context(|| "nsec3 no cover handler: could not serialize Message")
}

/// This handler simulates a misbehaving authoritative for an apex NODATA response.
///  * DNSKEY queries - return the correct records
///  * SOA queries - return the correct records
///  * A query for subdomain-0.hickory-dns.testing. - Return correct A + RRSIG RRset.
///  * MX query for hickory-dns.testing. - Return NOERROR with SOA + a non-apex NSEC3
///    (and their RRSIGs) in the authority section. RFC 5155 §8.5 requires the NSEC3
///    matching H(QNAME); the substituted record does not match the apex hash, so a
///    conformant validating resolver must SERVFAIL.
pub(crate) fn nsec3_apex_nodata_handler(
    bytes: &[u8],
    _transport: Transport,
) -> Result<Option<Vec<u8>>> {
    let mut msg = Message::from_vec(bytes)?.into_response();
    let query_name = msg.queries[0].name.clone();
    let query_type = msg.queries[0].query_type;

    let origin_name = Name::from_ascii("hickory-dns.testing.")?;
    let correct_name = origin_name.prepend_label("subdomain-0")?;

    let records = zone_file::parse_zone_file(Path::new(
        &env::var("ZONE_FILE").unwrap_or("/etc/zones/main.zone".to_string()),
    ))
    .map_err(|e| {
        Error::msg(format!(
            "nsec3_apex_nodata handler: unable to load zone file: {e:?}"
        ))
    })?;

    match query_type {
        RecordType::DNSKEY | RecordType::SOA => {
            msg.add_answers(records.into_iter().filter(|x| match x.record_type() {
                RecordType::DNSKEY | RecordType::SOA => x.record_type() == query_type,
                RecordType::RRSIG => {
                    let Some(rrsig) = x.try_borrow::<RRSIG>() else {
                        return false;
                    };
                    rrsig.data().input().type_covered == query_type
                }
                _ => false,
            }));
        }
        RecordType::A if query_name == correct_name => {
            for record in records {
                if record.name != correct_name {
                    continue;
                }

                if record.record_type() == RecordType::A {
                    msg.add_answer(record.clone());
                } else if record.record_type() == RecordType::RRSIG {
                    let Some(rrsig) = record.try_borrow::<RRSIG>() else {
                        continue;
                    };

                    if rrsig.data().input().type_covered == RecordType::A {
                        msg.add_answer(record.clone());
                    }
                }
            }
        }
        RecordType::MX if query_name == origin_name => {
            let Some(params_rec) = records
                .iter()
                .find(|x| x.record_type() == RecordType::NSEC3PARAM)
                .cloned()
            else {
                return Err(Error::msg("Could not get nsec3param record"));
            };

            let Some(params_inner) = params_rec.try_borrow::<NSEC3PARAM>() else {
                return Err(Error::msg("Could not get nsec3param record data"));
            };

            let apex_hash = BASE32_DNSSEC.encode(
                Nsec3HashAlgorithm::SHA1
                    .hash(
                        params_inner.data().salt(),
                        &origin_name,
                        params_inner.data().iterations(),
                    )?
                    .as_ref(),
            );

            // Pick the first NSEC3 whose hashed-owner label is NOT H(apex). This is
            // the malformed apex NODATA: no NSEC3 in the response matches H(QNAME).
            let Some(decoy_nsec3) = records.iter().find(|x| {
                if x.record_type() != RecordType::NSEC3 {
                    return false;
                }
                let Some(label) = x.name.iter().next() else {
                    return false;
                };
                label != apex_hash.as_bytes()
            }) else {
                return Err(Error::msg(
                    "no non-apex NSEC3 available in zone for apex NODATA test",
                ));
            };
            let decoy_name = decoy_nsec3.name.clone();

            for record in records {
                match record.record_type() {
                    RecordType::SOA => msg.add_authority(record),
                    RecordType::NSEC3 if record.name == decoy_name => msg.add_authority(record),
                    RecordType::RRSIG => {
                        let Some(rrsig) = record.try_borrow::<RRSIG>() else {
                            continue;
                        };
                        match rrsig.data().input().type_covered {
                            RecordType::SOA => msg.add_authority(record),
                            RecordType::NSEC3 if record.name == decoy_name => {
                                msg.add_authority(record)
                            }
                            _ => continue,
                        }
                    }
                    _ => continue,
                };
            }
        }
        _ => {}
    }

    msg.metadata.recursion_desired = true;
    msg.metadata.recursion_available = true;
    msg.metadata.authoritative = true;
    msg.metadata.authentic_data = true;
    msg.to_vec()
        .map(Some)
        .with_context(|| "nsec3 apex nodata handler: could not serialize Message")
}

/// This handler generates a response with an out-of-bailiwick record included.
///
/// There are four variations: a baseline case that returns a superfluous out of bailiwick record
/// along with a responsive A record, a CNAME test that returns an out of bailiwick response that is
/// part of a CNAME chain, and two negative response cases that include an out of bailiwick record
/// in the authority section.
pub(crate) fn bailiwick_handler(bytes: &[u8], _transport: Transport) -> Result<Option<Vec<u8>>> {
    let mut msg = Message::from_vec(bytes)?.into_response();
    let name = msg.queries[0].name().clone();

    if name == Name::from_ascii("cname.example.testing.")? {
        msg.add_answer(Record::from_rdata(
            name,
            1,
            RData::CNAME(rdata::CNAME(Name::from_ascii("host.otherdomain.testing.")?)),
        ))
        .add_answer(Record::from_rdata(
            Name::from_ascii("host.otherdomain.testing.")?,
            86400,
            RData::A(rdata::A([192, 0, 2, 1].into())),
        ));
    } else if name == Name::from_ascii("example-123.valid.testing.")? {
        msg.add_answer(Record::from_rdata(
            name,
            1,
            RData::A(rdata::A([192, 0, 2, 1].into())),
        ))
        .add_answer(Record::from_rdata(
            Name::from_ascii("host.invalid.testing.")?,
            86400,
            RData::A(rdata::A([192, 0, 2, 2].into())),
        ));
    } else if name == Name::from_ascii("nxdomain-1.example.testing.")? {
        msg.metadata.response_code = ResponseCode::NXDomain;
        msg.add_authority(Record::from_rdata(
            Name::from_ascii("example.testing.")?,
            86400,
            RData::SOA(rdata::SOA::new(
                Name::from_ascii("primary.tld-server.testing.")?,
                Name::from_ascii("root.example.testing.")?,
                1,
                7200,
                3600,
                1209600,
                86400,
            )),
        ));
        msg.add_authority(Record::from_rdata(
            Name::from_ascii("host.invalid.testing.")?,
            86400,
            RData::A(rdata::A([192, 0, 5, 7].into())),
        ));
    } else if name == Name::from_ascii("nxdomain-2.example.testing.")? {
        msg.metadata.response_code = ResponseCode::NXDomain;
        msg.add_authority(Record::from_rdata(
            Name::from_ascii("host.invalid.testing.")?,
            86400,
            RData::SOA(rdata::SOA::new(
                Name::from_ascii("primary.tld-server.testing.")?,
                Name::from_ascii("root.host.invalid.testing.")?,
                1,
                7200,
                3600,
                1209600,
                86400,
            )),
        ));
    } else {
        return Err(anyhow!("unexpected QNAME: {name}"));
    }

    msg.metadata.recursion_desired = false;
    msg.to_vec()
        .map(Some)
        .with_context(|| "base handler: could not serialize Message")
}

/// This handler simulates an authoritative server that includes parent NS records
/// Simulates authoritative servers (e.g. twtrdns.net for twitter.com/x.com) that
/// include parent NS records in responses to subdomain NS queries.
///
/// The handler uses a CNAME chain to make the bug observable in testing:
/// `deep.sub.example.testing. IN CNAME target.example.testing.` with an inline
/// A record for `target.example.testing.`. When the recursor incorrectly creates
/// a false zone cut at `sub.example.testing.`, the bailiwick filter (zone =
/// `sub.example.testing.`) drops the `target.example.testing. IN A` record
/// because `target.example.testing.` is not a subzone of `sub.example.testing.`.
/// CNAME following then fails because `target.example.testing. IN A` is not
/// served as a standalone query. Without the false zone cut (zone =
/// `example.testing.`), both records pass the bailiwick filter and resolution
/// succeeds.
pub(crate) fn parent_ns_in_authority_handler(
    bytes: &[u8],
    _transport: Transport,
) -> Result<Option<Vec<u8>>> {
    let mut msg = Message::from_vec(bytes)?.into_response();
    let name = msg.queries[0].name().clone();
    let q_type = msg.queries[0].query_type();

    let zone = Name::from_ascii("example.testing.")?;
    let ns_name = Name::from_ascii("ns.external.testing.")?;
    let deep_sub = Name::from_ascii("deep.sub.example.testing.")?;
    let cname_target = Name::from_ascii("target.example.testing.")?;

    msg.metadata.authoritative = true;
    msg.metadata.recursion_desired = false;

    if q_type == RecordType::NS && name == zone {
        // Direct NS query for the zone itself — return the real NS record.
        msg.add_answer(Record::from_rdata(
            zone,
            86400,
            RData::NS(rdata::NS(ns_name)),
        ));
    } else if q_type == RecordType::A && name == deep_sub {
        // A query for deep.sub — return a CNAME chain to target.example.testing.
        // The CNAME owner (deep.sub) is a subzone of both example.testing. and
        // sub.example.testing., but the A record owner (target.example.testing.)
        // is only a subzone of example.testing. — not sub.example.testing.
        // This makes the bailiwick filter the distinguishing factor.
        msg.add_answer(Record::from_rdata(
            deep_sub,
            300,
            RData::CNAME(rdata::CNAME(cname_target.clone())),
        ));
        msg.add_answer(Record::from_rdata(
            cname_target,
            300,
            RData::A(rdata::A([192, 0, 2, 1].into())),
        ));
    } else if q_type == RecordType::NS && name != zone && name.base_name() == zone {
        // NS query for a direct subdomain (e.g. sub.example.testing.) — return
        // the parent NS in the answer section. This is the response that triggers
        // the zone cut misidentification bug: the recursor sees an NS record and
        // (without the fix) treats it as evidence of a zone cut, even though the
        // NS record's owner name (example.testing.) doesn't match the queried
        // name (sub.example.testing.).
        msg.add_answer(Record::from_rdata(
            zone,
            86400,
            RData::NS(rdata::NS(ns_name)),
        ));
    } else if q_type == RecordType::NS && zone.zone_of(&name) {
        // NS query for a deeper subdomain (e.g. deep.sub.example.testing.) —
        // return NODATA (empty NOERROR). This allows the recursor's
        // ns_pool_for_name loop to continue past this name without error.
    } else {
        msg.metadata.response_code = ResponseCode::NXDomain;
    }

    msg.to_vec()
        .map(Some)
        .with_context(|| "parent_ns_in_authority handler: could not serialize Message")
}

/// This handler generates a response with QR=0 (Query type instead of Response type).
/// Such responses should be rejected by resolvers as invalid.
pub(crate) fn qr_not_response_handler(
    bytes: &[u8],
    _transport: Transport,
) -> Result<Option<Vec<u8>>> {
    let mut msg = Message::from_vec(bytes)?.into_response();
    let name = msg.queries[0].name().clone();

    msg.metadata.message_type = MessageType::Query;
    msg.metadata.recursion_desired = false;
    msg.add_answer(Record::from_rdata(
        name,
        1,
        RData::A(rdata::A([192, 0, 2, 1].into())),
    ))
    .to_vec()
    .map(Some)
    .with_context(|| "qr_not_response handler: could not serialize Message")
}

/// This handler forces TCP by returning truncated on UDP, then returns QR=0 on TCP.
/// Used to test QR validation over TCP connections.
pub(crate) fn qr_not_response_force_tcp_handler(
    bytes: &[u8],
    transport: Transport,
) -> Result<Option<Vec<u8>>> {
    let mut msg = Message::from_vec(bytes)?.into_response();
    let name = msg.queries[0].name().clone();

    match transport {
        Transport::Udp => {
            msg.metadata.truncation = true;
            msg.metadata.authoritative = true;
            msg.to_vec()
                .map(Some)
                .with_context(|| "qr_not_response_force_tcp handler: could not serialize Message")
        }
        Transport::Tcp => {
            msg.metadata.message_type = MessageType::Query;
            msg.metadata.recursion_desired = false;
            msg.add_answer(Record::from_rdata(
                name,
                1,
                RData::A(rdata::A([192, 0, 2, 1].into())),
            ))
            .to_vec()
            .map(Some)
            .with_context(|| "qr_not_response_force_tcp handler: could not serialize Message")
        }
    }
}

/// This handler proxies requests to another server, and drops a specific record set from responses.
pub(crate) struct DropRrsetHandler {
    ip_address: IpAddr,
    name: Name,
    record_type: RecordType,
}

impl DropRrsetHandler {
    pub(crate) fn new(ip_address: IpAddr, name: Name, record_type: RecordType) -> Self {
        Self {
            ip_address,
            name,
            record_type,
        }
    }
}

#[async_trait]
impl Handler for DropRrsetHandler {
    async fn handle(&self, bytes: &[u8], _transport: Transport) -> Result<Option<Vec<u8>>> {
        let query_message = Message::from_vec(bytes).context("error parsing query into message")?;
        let mut response = proxy_query(self.ip_address, query_message).await?;

        let Message {
            answers,
            authorities,
            additionals,
            ..
        } = response.deref_mut();
        for section in [answers, authorities, additionals] {
            section.retain(|record| {
                if record.name != self.name {
                    return true;
                }
                if record.record_type() == self.record_type {
                    return false;
                }
                if let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &record.data {
                    if rrsig.input().type_covered == self.record_type {
                        return false;
                    }
                }
                true
            });
        }

        Ok(Some(
            response.to_vec().context("error serializing response")?,
        ))
    }
}

/// This handler returns a legitimate IN A response with a single foreign-class
/// (CH) record appended in the answer section, simulating an on-path attacker
/// smuggling attacker-chosen rdata under the same (qname, qtype).
pub(crate) fn foreign_class_handler(
    bytes: &[u8],
    _transport: Transport,
) -> Result<Option<Vec<u8>>> {
    let mut msg = Message::from_vec(bytes)?.into_response();
    let name = msg.queries[0].name.clone();

    msg.metadata.authoritative = true;
    msg.metadata.recursion_desired = false;
    msg.add_answer(Record::from_rdata(
        name.clone(),
        300,
        RData::A(rdata::A([192, 0, 2, 1].into())),
    ));

    let mut foreign = Record::from_rdata(name, 300, RData::A(rdata::A([6, 6, 6, 6].into())));
    foreign.dns_class = DNSClass::CH;
    msg.add_answer(foreign);

    msg.to_vec()
        .map(Some)
        .with_context(|| "foreign class handler: could not serialize Message")
}

/// A handler returns SERVFAIL for some queries, and proxies the rest.
///
/// It returns SERVFAIL for the first `count` queries matching a specific (name, record type) pair.
/// Subsequent matching queries are forwarded unchanged. This simulates a transient parent-side
/// failure on a specific RRset.
pub(crate) struct ServfailRrsetHandler {
    ip_address: IpAddr,
    name: Name,
    record_type: RecordType,
    remaining: AtomicU32,
}

impl ServfailRrsetHandler {
    pub(crate) fn new(ip_address: IpAddr, name: Name, record_type: RecordType, count: u32) -> Self {
        Self {
            ip_address,
            name,
            record_type,
            remaining: AtomicU32::new(count),
        }
    }
}

#[async_trait]
impl Handler for ServfailRrsetHandler {
    async fn handle(&self, bytes: &[u8], _transport: Transport) -> Result<Option<Vec<u8>>> {
        let query_message = Message::from_vec(bytes).context("error parsing query into message")?;

        let matches_target = query_message
            .queries
            .iter()
            .any(|q| q.name == self.name && q.query_type == self.record_type);

        if matches_target
            && self
                .remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |c| c.checked_sub(1))
                .is_ok()
        {
            let mut response = query_message.into_response();
            response.metadata.response_code = ResponseCode::ServFail;
            response.metadata.authoritative = false;
            response.metadata.recursion_available = false;
            return response
                .to_vec()
                .map(Some)
                .with_context(|| "servfail_rrset handler: could not serialize Message");
        }

        let response = proxy_query(self.ip_address, query_message).await?;
        Ok(Some(
            response.to_vec().context("error serializing response")?,
        ))
    }
}

/// Forwards a query over TCP and returns the response with the original id restored.
async fn proxy_query(ip_address: IpAddr, query_message: Message) -> Result<DnsResponse> {
    let (future, sender) = TcpClientStream::new(
        (ip_address, 53).into(),
        None,
        None,
        TokioRuntimeProvider::new(),
    );
    let (client, bg) = Client::<TokioRuntimeProvider>::new(future.await?, sender);
    tokio::spawn(bg);

    let id = query_message.id;
    let query_request = DnsRequest::new(query_message, DnsRequestOptions::default());

    let mut response = client
        .send(query_request)
        .first_answer()
        .await
        .context("error sending proxied query")?;

    response.metadata.id = id;
    Ok(response)
}

/// This handler responds to specific queries with the wrong RRset.
pub(crate) fn wrong_rrset_handler(bytes: &[u8], _transport: Transport) -> Result<Option<Vec<u8>>> {
    let mut msg = Message::from_vec(bytes)?.into_response();
    let query_name = msg.queries[0].name.clone();
    let query_type = msg.queries[0].query_type;

    let origin_name = Name::from_ascii("leaf.testing.").unwrap();
    let hashed_origin_name =
        Name::from_ascii("58TK0VPG9OTNFP15LMGE6CVEVA91FJD1.leaf.testing.").unwrap();
    let record_name = Name::from_ascii("www.leaf.testing.").unwrap();
    let alternate_name = Name::from_ascii("www2.leaf.testing.").unwrap();
    let substitute_name = Name::from_ascii("other.leaf.testing.").unwrap();
    let nameserver_name = Name::from_ascii("primary1.leaf.testing.").unwrap();

    let records = zone_file::parse_zone_file(Path::new(
        &env::var("ZONE_FILE").unwrap_or("/etc/zones/main.zone".to_string()),
    ))
    .map_err(|e| {
        Error::msg(format!(
            "wrong rrset handler: unable to load zone file: {e:?}"
        ))
    })?;

    match query_type {
        // Basic infrastructure: return correct responses, including signatures.
        RecordType::DNSKEY | RecordType::SOA | RecordType::NS if query_name == origin_name => {
            msg.add_answers(records.into_iter().filter(
                |record| match record.try_borrow::<RRSIG>() {
                    Some(rrsig) => rrsig.data().input().type_covered == query_type,
                    None => record.record_type() == query_type,
                },
            ));
        }

        // Send an RRset with the wrong name.
        RecordType::A if query_name == record_name => {
            msg.add_answers(records.into_iter().filter(|record| {
                if record.name != substitute_name {
                    return false;
                }
                match record.try_borrow::<RRSIG>() {
                    Some(rrsig) => rrsig.data().input().type_covered == RecordType::A,
                    None => record.record_type() == RecordType::A,
                }
            }));
        }
        // Send an RRset with the wrong type.
        RecordType::AAAA if query_name == record_name => {
            msg.add_answers(records.into_iter().filter(|record| {
                if record.name != record_name {
                    return false;
                }
                match record.try_borrow::<RRSIG>() {
                    Some(rrsig) => rrsig.data().input().type_covered == RecordType::A,
                    None => record.record_type() == RecordType::A,
                }
            }));
        }
        // Send an RRset with the wrong name, and include an NSEC or NSEC3 record in the authority
        // section.
        RecordType::A if query_name == alternate_name => {
            msg.add_answers(
                records
                    .iter()
                    .filter(|record| {
                        if record.name != substitute_name {
                            return false;
                        }
                        match record.try_borrow::<RRSIG>() {
                            Some(rrsig) => rrsig.data().input().type_covered == RecordType::A,
                            None => record.record_type() == RecordType::A,
                        }
                    })
                    .cloned(),
            );
            msg.add_authorities(records.into_iter().filter(|record| {
                if record.name != origin_name && record.name != hashed_origin_name {
                    return false;
                }
                match record.try_borrow::<RRSIG>() {
                    Some(rrsig) => {
                        rrsig.data().input().type_covered == RecordType::NSEC
                            || rrsig.data().input().type_covered == RecordType::NSEC3
                    }
                    None => {
                        record.record_type() == RecordType::NSEC
                            || record.record_type() == RecordType::NSEC3
                    }
                }
            }));
        }

        // Handle possible glue hardening requests.
        RecordType::A if query_name == nameserver_name => {
            msg.add_answers(records.into_iter().filter(|record| {
                if record.name != nameserver_name {
                    return false;
                }
                match record.try_borrow::<RRSIG>() {
                    Some(rrsig) => rrsig.data().input().type_covered == RecordType::A,
                    None => record.record_type() == RecordType::A,
                }
            }));
        }
        RecordType::AAAA if query_name == nameserver_name => {
            msg.add_authorities(records.into_iter().filter(|record| {
                if record.name == origin_name {
                    match record.try_borrow::<RRSIG>() {
                        Some(rrsig) => rrsig.data().input().type_covered == RecordType::SOA,
                        None => record.record_type() == RecordType::SOA,
                    }
                } else if record.name == nameserver_name {
                    match record.try_borrow::<RRSIG>() {
                        Some(rrsig) => rrsig.data().input().type_covered == RecordType::NSEC,
                        None => record.record_type() == RecordType::NSEC,
                    }
                } else {
                    false
                }
            }));
        }

        // DS RRset nonexistence, or Hickory QNAME minimization queries, at child names.
        RecordType::DS | RecordType::NS
            if query_name == record_name || query_name == alternate_name =>
        {
            // Add all NSEC3 records, if any are present. This way we don't have to think about name hashes.
            msg.add_authorities(
                records
                    .iter()
                    .filter(|record| match record.try_borrow::<RRSIG>() {
                        Some(rrsig) => rrsig.data().input().type_covered == RecordType::NSEC3,
                        None => record.record_type() == RecordType::NSEC3,
                    })
                    .cloned(),
            );
            msg.add_authorities(records.into_iter().filter(|record| {
                if record.name == origin_name {
                    match record.try_borrow::<RRSIG>() {
                        Some(rrsig) => rrsig.data().input().type_covered == RecordType::SOA,
                        None => record.record_type() == RecordType::SOA,
                    }
                } else if record.name == query_name {
                    match record.try_borrow::<RRSIG>() {
                        Some(rrsig) => rrsig.data().input().type_covered == RecordType::NSEC,
                        None => record.record_type() == RecordType::NSEC,
                    }
                } else {
                    false
                }
            }));
        }

        _ => {
            return Err(anyhow!(
                "wrong rrset handler: unexpected query: {}",
                msg.queries[0]
            ));
        }
    }

    msg.metadata.authoritative = true;
    msg.metadata.authentic_data = true;
    Ok(Some(msg.to_vec().with_context(
        || "wrong rrset handler: could not serialize Message",
    )?))
}

/// A proxying handler that turns queries for a selected name into possibly-bogus referrals.
///
/// This will reset the AA flag and RCODE, while adding a forged NS record to the authority section.
/// It is intended to be used on queries that would otherwise return a signed NODATA or NXDOMAIN
/// response, so that we can test what happens when those DNSSEC records are repurposed in a spoofed
/// response. It is intended to target the checks described in RFC 6840 section 4.4.
pub(crate) struct ForgedDelegationHandler {
    ip_address: IpAddr,
    zone: Name,
    nameserver: Name,
}

impl ForgedDelegationHandler {
    pub(crate) fn new(ip_address: IpAddr, zone: Name, nameserver: Name) -> Self {
        Self {
            ip_address,
            zone,
            nameserver,
        }
    }
}

#[async_trait]
impl Handler for ForgedDelegationHandler {
    async fn handle(&self, bytes: &[u8], _transport: Transport) -> Result<Option<Vec<u8>>> {
        let query_message = Message::from_vec(bytes).context("error parsing query into message")?;

        let query = query_message.queries.first();
        let is_ds_query =
            query.is_some_and(|q| q.query_type == RecordType::DS && self.zone == q.name);
        let is_descendant = query.is_some_and(|q| self.zone.zone_of(&q.name));

        let mut response = proxy_query(self.ip_address, query_message).await?;

        if is_ds_query {
            if response.metadata.response_code == ResponseCode::NXDomain {
                response.metadata.response_code = ResponseCode::NoError;
            }
        } else if is_descendant {
            response.metadata.authoritative = false;
            if response.metadata.response_code == ResponseCode::NXDomain {
                response.metadata.response_code = ResponseCode::NoError;
            }
            response.authorities.insert(
                0,
                Record::from_rdata(
                    self.zone.clone(),
                    3600,
                    RData::NS(NS(self.nameserver.clone())),
                ),
            );
            // BIND expects that if NS and SOA records are both present, they should have the same
            // name. Remove the SOA record when we transform a response into a referral.
            response
                .authorities
                .retain(|record| record.record_type() != RecordType::SOA);
        }

        Ok(Some(
            response.to_vec().context("error serializing response")?,
        ))
    }
}

pub(super) fn bogus_wildcard_expansion_nsec_same_name_condition_handler(
    bytes: &[u8],
    _transport: Transport,
) -> Result<Option<Vec<u8>>> {
    let mut msg = Message::from_vec(bytes)?.into_response();
    let query = &msg.queries[0];
    let query_name = query.name.clone();
    let query_type = query.query_type;

    let origin_name = Name::from_ascii("hickory-dns.testing.")?;
    let www_name = Name::from_ascii("www.hickory-dns.testing.")?;
    let wildcard_name = Name::from_ascii("*.hickory-dns.testing.")?;
    let expected_query_name = Name::from_ascii("subdomain.www.hickory-dns.testing.")?;

    let records = read_zone_file()?;
    // Gather RRsets and signatures over RRsets from the zone file.
    let soa = records
        .iter()
        .filter(|r| r.record_type() == RecordType::SOA)
        .collect::<Vec<_>>();
    let soa_rrsig = records
        .iter()
        .filter(filter_rrsig_rrset(&origin_name, RecordType::SOA))
        .collect::<Vec<_>>();
    let ns = records
        .iter()
        .filter(|r| r.record_type() == RecordType::NS)
        .collect::<Vec<_>>();
    let ns_rrsig = records
        .iter()
        .filter(filter_rrsig_rrset(&origin_name, RecordType::NS))
        .collect::<Vec<_>>();
    let dnskey = records
        .iter()
        .filter(|r| r.record_type() == RecordType::DNSKEY)
        .collect::<Vec<_>>();
    let dnskey_rrsig = records
        .iter()
        .filter(filter_rrsig_rrset(&origin_name, RecordType::DNSKEY))
        .collect::<Vec<_>>();
    let apex_nsec = records
        .iter()
        .filter(|r| r.record_type() == RecordType::NSEC && r.name == origin_name)
        .collect::<Vec<_>>();
    let apex_nsec_rrsig = records
        .iter()
        .filter(filter_rrsig_rrset(&origin_name, RecordType::NSEC))
        .collect::<Vec<_>>();
    let wildcard_a = records
        .iter()
        .filter(|r| r.record_type() == RecordType::A && r.name == wildcard_name)
        .collect::<Vec<_>>();
    let wildcard_a_rrsig = records
        .iter()
        .filter(filter_rrsig_rrset(&wildcard_name, RecordType::A))
        .collect::<Vec<_>>();
    let wildcard_nsec = records
        .iter()
        .filter(|r| r.record_type() == RecordType::NSEC && r.name == wildcard_name)
        .collect::<Vec<_>>();
    let wildcard_nsec_rrsig = records
        .iter()
        .filter(filter_rrsig_rrset(&wildcard_name, RecordType::NSEC))
        .collect::<Vec<_>>();
    let www_nsec = records
        .iter()
        .filter(|r| r.record_type() == RecordType::NSEC && r.name == www_name)
        .collect::<Vec<_>>();
    let www_nsec_rrsig = records
        .iter()
        .filter(filter_rrsig_rrset(&www_name, RecordType::NSEC))
        .collect::<Vec<_>>();

    match query_type {
        RecordType::SOA => {
            msg.add_answers(soa.iter().copied().cloned());
            msg.add_answers(soa_rrsig.iter().copied().cloned());
        }
        RecordType::DNSKEY => {
            msg.add_answers(dnskey.iter().copied().cloned());
            msg.add_answers(dnskey_rrsig.iter().copied().cloned());
        }
        RecordType::A if query_name == expected_query_name => {
            // This is the query for which we return a tampered response.

            let mut modified_a_record =
                (*wildcard_a.first().context("no wildcard A record")?).clone();
            let mut modified_a_rrsig = (*wildcard_a_rrsig
                .first()
                .context("no wildcard A signature")?)
            .clone();
            // Wildcard expansion: overwrite name.
            modified_a_record.name = expected_query_name.clone();
            modified_a_rrsig.name = expected_query_name.clone();
            msg.add_answer(modified_a_record);
            msg.add_answer(modified_a_rrsig);

            let mut modified_nsec_record =
                (*wildcard_nsec.first().context("no wildcard NSEC record")?).clone();
            let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = &mut modified_nsec_record.data else {
                return Err(anyhow!("wrong RDATA type in wildcard NSEC record"));
            };
            // Overwrite next domain name to prove the query name, subdomain.www.hickory-dns.testing.,
            // does not exist.
            *nsec = NSEC::new(
                Name::from_ascii("z.hickory-dns.testing.").unwrap(),
                nsec.type_bit_maps(),
            );
            msg.add_authority(modified_nsec_record);
            msg.add_authorities(wildcard_nsec_rrsig.iter().copied().cloned());

            // Add an extra RRset with the same name to trigger the bug.
            msg.add_authorities(wildcard_a.iter().copied().cloned());
            msg.add_authorities(wildcard_a_rrsig.iter().copied().cloned());
        }
        RecordType::NS if query_name == origin_name => {
            msg.add_answers(ns.iter().copied().cloned());
            msg.add_answers(ns_rrsig.iter().copied().cloned());
        }
        RecordType::NS if query_name == www_name || query_name == expected_query_name => {
            msg.add_authorities(soa.iter().copied().cloned());
            msg.add_authorities(soa_rrsig.iter().copied().cloned());
            msg.add_authorities(www_nsec.iter().copied().cloned());
            msg.add_authorities(www_nsec_rrsig.iter().copied().cloned());
        }
        RecordType::A if query_name.to_string().contains("primary") => {
            // BIND requests A records for the name server names.
            msg.add_answers(
                records
                    .iter()
                    .filter(|r| {
                        r.name == query_name
                            && (r.record_type() == RecordType::A
                                || r.record_type() == RecordType::RRSIG)
                    })
                    .cloned(),
            );
        }
        RecordType::AAAA if query_name.to_string().contains("primary") => {
            // BIND requests AAAA records for the name server names.
            msg.add_authorities(soa.iter().copied().cloned());
            msg.add_authorities(soa_rrsig.iter().copied().cloned());
            msg.add_authorities(apex_nsec.iter().copied().cloned());
            msg.add_authorities(apex_nsec_rrsig.iter().copied().cloned());
            msg.add_authorities(wildcard_nsec.iter().copied().cloned());
            msg.add_authorities(wildcard_nsec_rrsig.iter().copied().cloned());
            msg.add_authorities(www_nsec.iter().copied().cloned());
            msg.add_authorities(www_nsec_rrsig.iter().copied().cloned());
        }
        RecordType::A if query_name.to_string() == "www.hickory-dns.testing." => {
            // Unbound sends this query as part of QNAME minimization.
            msg.add_authorities(soa.iter().copied().cloned());
            msg.add_authorities(soa_rrsig.iter().copied().cloned());
            msg.add_authorities(www_nsec.iter().copied().cloned());
            msg.add_authorities(www_nsec_rrsig.iter().copied().cloned());
        }
        _ => {
            return Err(anyhow!("unexpected query: {query_name} {query_type}"));
        }
    }

    msg.metadata.recursion_available = false;
    msg.metadata.authoritative = true;
    msg.metadata.authentic_data = true;
    Ok(Some(
        msg.to_vec()
            .with_context(|| "could not serialize Message")?,
    ))
}

/// Reads a zone file and returns the records it contains.
///
/// If the environment variable `ZONE_FILE` is set, the filename of the zone file will be taken from
/// there. Otherwise, `/etc/zones/main.zone` will be read by default.
fn read_zone_file() -> Result<Vec<Record>> {
    zone_file::parse_zone_file(Path::new(
        &env::var("ZONE_FILE").unwrap_or("/etc/zones/main.zone".to_string()),
    ))
    .map_err(|message| anyhow!("unable to load zone file: {message}"))
}

/// Returns a filter function that selects RRSIGs over a specific RRset.
fn filter_rrsig_rrset(name: &Name, record_type: RecordType) -> impl Fn(&&Record) -> bool + use<'_> {
    move |record| {
        let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &record.data else {
            return false;
        };
        rrsig.input().type_covered == record_type && &record.name == name
    }
}

pub(super) struct Nsec3WrongZoneHandler {
    /// IP address of the upstream resolver.
    ip_address: IpAddr,
    /// Private key for the attacker zone's ZSK.
    private_key: String,
    /// Public key for the attacker zone's ZSK.
    public_key: String,
}

impl Nsec3WrongZoneHandler {
    pub(super) fn new(ip_address: IpAddr, private_key: String, public_key: String) -> Self {
        Self {
            ip_address,
            private_key,
            public_key,
        }
    }
}

#[async_trait]
impl Handler for Nsec3WrongZoneHandler {
    async fn handle(&self, bytes: &[u8], _transport: Transport) -> Result<Option<Vec<u8>>> {
        let query_message = Message::from_vec(bytes).context("error parsing query into message")?;
        let query = &query_message.queries[0];
        let query_name = query.name.clone();
        let query_type = query.query_type;

        let origin_name = Name::from_ascii("victim.testing.")?;

        if !(query_type == RecordType::A && query_name == origin_name) {
            let msg = proxy_query(self.ip_address, query_message).await?;
            return Ok(Some(msg.to_vec().context("error serializing response")?));
        }

        // Construct NSEC3 record.
        //
        // $ nsec3hash -r 1 0 1 - victim.testing.
        // victim.testing. NSEC3 1 0 1 - GTR6F74IERHONNKRCH3QDNUNNDVR2OF1
        let hash_base32 = "GTR6F74IERHONNKRCH3QDNUNNDVR2OF1";
        let hash = data_encoding::BASE32_DNSSEC
            .decode(hash_base32.as_bytes())
            .unwrap();
        let crafted_nsec3_rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            1,
            Vec::new(),
            hash,
            [
                RecordType::NS,
                RecordType::SOA,
                RecordType::RRSIG,
                RecordType::DNSKEY,
                RecordType::NSEC3PARAM,
            ],
        );
        let crafted_nsec3_name =
            Name::from_ascii("GTR6F74IERHONNKRCH3QDNUNNDVR2OF1.attacker.testing.")?;
        let crafted_nsec3_record = Record::from_rdata(
            crafted_nsec3_name.clone(),
            86400,
            RData::DNSSEC(DNSSECRData::NSEC3(crafted_nsec3_rdata)),
        );

        // Convert keypair.
        let private_key_raw = data_encoding::BASE64
            .decode(self.private_key.as_bytes())
            .context("could not decode private key")?;
        let public_key_raw = data_encoding::BASE64
            .decode(self.public_key.as_bytes())
            .context("could not decode public key")?;
        let mut uncompressed_public_key = public_key_raw.clone();
        uncompressed_public_key.insert(0, 0x04);
        let keypair = EcdsaKeyPair::from_private_key_and_public_key(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &private_key_raw,
            &uncompressed_public_key,
        )
        .context("could not construct key pair from raw bytes")?;
        let pkcs8 = keypair
            .to_pkcs8v1()
            .context("could not convert private key to PKCS-8")?;
        let signing_key =
            EcdsaSigningKey::from_pkcs8(&pkcs8.as_ref().into(), Algorithm::ECDSAP256SHA256)
                .context("could not load PKCS-8 private key")?;

        // Sign NSEC3 record with the attacker's zone signing key.
        let signer = DnssecSigner::new(
            DNSKEY::new(
                true,
                false,
                false,
                PublicKeyBuf::new(public_key_raw.clone(), Algorithm::ECDSAP256SHA256),
            ),
            Box::new(signing_key),
            Name::from_ascii("attacker.testing.")?,
            Duration::from_secs(60 * 60 * 24 * 7),
        );
        let mut rrset = RecordSet::new(crafted_nsec3_name.clone(), RecordType::NSEC3, 0);
        rrset.insert(crafted_nsec3_record.clone(), 0);
        let inception = OffsetDateTime::now_utc();
        let rrsig = RRSIG::from_rrset(&rrset, DNSClass::IN, inception, &signer)?;
        let rrsig_record = Record::from_rdata(
            crafted_nsec3_name,
            86400,
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
        );

        // Construct response.
        let mut msg = query_message.into_response();
        msg.add_authority(crafted_nsec3_record);
        msg.add_authority(rrsig_record);

        Ok(Some(msg.to_vec().context("error serializing response")?))
    }
}

/// Proxies queries to another server, and forges a positive wildcard-expanded response in place of
/// a NODATA response.
pub(super) struct BogusWildcardExpansionQnameExistsHandler {
    ip_address: IpAddr,
    wildcard_name: Name,
    query_name: Name,
}

impl BogusWildcardExpansionQnameExistsHandler {
    pub(super) fn new(ip_address: IpAddr, wildcard_name: Name, query_name: Name) -> Self {
        Self {
            ip_address,
            wildcard_name,
            query_name,
        }
    }
}

#[async_trait]
impl Handler for BogusWildcardExpansionQnameExistsHandler {
    async fn handle(&self, bytes: &[u8], _transport: Transport) -> Result<Option<Vec<u8>>> {
        let query_message = Message::from_vec(bytes).context("error parsing query into message")?;
        let query = &query_message.queries[0];

        let response = if query.name == self.query_name && query.query_type == RecordType::A {
            let mut edns = Edns::new();
            edns.set_max_payload(1232);
            edns.set_dnssec_ok(true);

            let mut wildcard_query = Message::query();
            wildcard_query.set_edns(edns.clone());
            wildcard_query.add_query(Query::query(
                self.wildcard_name.base_name().prepend_label("other")?,
                RecordType::A,
            ));
            let wildcard_response = proxy_query(self.ip_address, wildcard_query).await?;
            let mut wildcard_records = Message::from(wildcard_response).answers;
            for record in wildcard_records.iter_mut() {
                // Replace the name in the wildcard-expanded record.
                record.name = query.name.clone();
            }

            let mut nodata_query = Message::query();
            nodata_query.set_edns(edns);
            nodata_query.add_query(Query::query(self.query_name.clone(), RecordType::A));
            let nodata_response = proxy_query(self.ip_address, nodata_query).await?;

            let mut response: Message = nodata_response.into();
            response.metadata.id = query_message.id;
            response.add_answers(wildcard_records);
            response
        } else {
            proxy_query(self.ip_address, query_message).await?.into()
        };

        Ok(Some(
            response.to_vec().context("error serializing response")?,
        ))
    }
}

static TRUNCATED_TCP_COUNTER: AtomicU8 = AtomicU8::new(0);
static TRUNCATED_UDP_COUNTER: AtomicU8 = AtomicU8::new(0);
static PACKET_LOSS_MARKER: AtomicBool = AtomicBool::new(false);
