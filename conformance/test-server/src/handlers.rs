use crate::{Transport, zone_file};
use anyhow::{Context, Result};
use hickory_proto::{
    dnssec::rdata::{NSEC3, RRSIG},
    op::{Message, ResponseCode},
    rr::{RData, Record, RecordType, domain::Name, rdata},
};
use std::{
    env,
    path::Path,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
};

/// This handler generates a valid A-record response to any query
pub(crate) fn base_handler(bytes: &[u8], _transport: Transport) -> Result<Option<Vec<u8>>> {
    let mut msg = Message::from_vec(bytes)?.to_response();
    let name = msg.queries()[0].name().clone();

    msg.set_recursion_desired(false)
        .add_answer(Record::from_rdata(
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
    let mut msg = Message::from_vec(bytes)?.to_response();
    let name = msg.queries()[0].name().clone();

    msg.set_id(if msg.id() == 65535 { 0 } else { msg.id() + 1 })
        .set_recursion_desired(false)
        .set_authoritative(true)
        .add_answer(Record::from_rdata(
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
        .to_response()
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
    let mut msg = Message::from_vec(bytes)?.to_response();
    let name = msg.queries()[0].name().clone();

    if name != Name::from_ascii("example.testing.").unwrap()
        && msg.queries()[0].query_type() != RecordType::TXT
    {
        msg.set_response_code(ResponseCode::NXDomain);
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

    msg.set_authoritative(true)
        .set_recursion_desired(false)
        .set_truncated(match transport {
            Transport::Udp => true,
            Transport::Tcp => false,
        })
        .add_answer(Record::from_rdata(
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
    let mut msg = Message::from_vec(bytes)?.to_response();
    let name = msg.queries()[0].name().clone();

    if name == Name::from_ascii("example.testing.").unwrap() {
        if !PACKET_LOSS_MARKER.load(Ordering::Relaxed) {
            PACKET_LOSS_MARKER.store(true, Ordering::Relaxed);
            return Ok(None);
        }
        msg.set_recursion_desired(false)
            .set_authoritative(true)
            .add_answer(Record::from_rdata(
                name,
                86400,
                RData::A(rdata::A([192, 0, 2, 1].into())),
            ));
    } else {
        msg.set_response_code(ResponseCode::NXDomain);
    }

    msg.to_vec()
        .map(Some)
        .with_context(|| "packet loss handler: could not serialize Message")
}

/// This handler does not preserve the case of query names in responses.
pub(crate) fn bad_case_handler(bytes: &[u8], transport: Transport) -> Result<Option<Vec<u8>>> {
    let mut msg = Message::from_vec(bytes)?.to_response();
    let mut queries = msg.take_queries();

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
    msg.add_queries(queries);

    msg.set_authoritative(true)
        .set_recursion_desired(false)
        .add_answer(Record::from_rdata(
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
    let mut msg = Message::from_vec(bytes)?.to_response();
    let name = msg.queries()[0].name().clone();

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

    msg.set_authoritative(true)
        .set_recursion_desired(false)
        .to_vec()
        .map(Some)
        .with_context(|| "cname loop handler: could not serialize Message")
}

/// This handler responds to A record requests with invalid (non-covering) NSEC3 records
pub(crate) fn nsec3_nocover_handler(
    bytes: &[u8],
    _transport: Transport,
) -> Result<Option<Vec<u8>>> {
    let mut msg = Message::from_vec(bytes)?.to_response();

    let records = zone_file::parse_zone_file(Path::new(
        &env::var("ZONE_FILE").unwrap_or("/etc/zones/main.zone".to_string()),
    ))
    .map_err(|e| {
        Error::msg(format!(
            "nsec3_nocover handler: unable to load zone file: {e:?}"
        ))
    })?;

    match msg.queries()[0].query_type() {
        RecordType::DNSKEY => {
            let dnskey_records = records
                .into_iter()
                .filter(|x| match x.record_type() {
                    RecordType::DNSKEY => true,
                    RecordType::RRSIG => {
                        let Some(rrsig) = x.try_borrow::<RRSIG>() else {
                            return false;
                        };
                        rrsig.data().input().type_covered == RecordType::DNSKEY
                    }
                    _ => false,
                })
                .to_owned()
                .collect::<Vec<Record>>();
            msg.add_answers(dnskey_records);
        }
        RecordType::A => {
            msg.set_response_code(ResponseCode::NXDomain);

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
                            // Find the first NSEC3 record that covers an A record
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
                            if name == *record.name() {
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

    msg.set_recursion_desired(true)
        .set_recursion_available(true)
        .set_authoritative(true)
        .set_authentic_data(true)
        .to_vec()
        .map(Some)
        .with_context(|| "nsec3 no cover handler: could not serialize Message")
}

static TRUNCATED_TCP_COUNTER: AtomicU8 = AtomicU8::new(0);
static TRUNCATED_UDP_COUNTER: AtomicU8 = AtomicU8::new(0);
static PACKET_LOSS_MARKER: AtomicBool = AtomicBool::new(false);
