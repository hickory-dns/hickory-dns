#![no_main]
use libfuzzer_sys::fuzz_target;

use trust_dns_proto::{
    op::Message,
    rr::{Record, RecordType},
    serialize::binary::{BinDecodable, BinEncodable},
};

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = Message::from_bytes(data) {
        let new_data = msg.to_bytes().unwrap();
        match Message::from_bytes(&new_data) {
            Ok(reparsed) => {
                if !messages_equal(&msg, &reparsed) {
                    for (m, r) in format!("{:#?}", msg)
                        .lines()
                        .zip(format!("{:#?}", reparsed).lines())
                    {
                        if m != r {
                            println!("{} -> {}", m, r);
                        }
                    }
                    assert_eq!(msg, reparsed);
                }
            }
            Err(e) => {
                eprintln!("{:?}", msg);
                panic!("Message failed to deserialize: {:?}", e);
            }
        }
    }
});

fn messages_equal(msg1: &Message, msg2: &Message) -> bool {
    if msg1 == msg2 {
        return true;
    }

    // see if there are some of the records that don't round trip properly...
    // compare headers
    if msg1.header() != msg2.header() {
        return false;
    }

    // compare queries
    if msg1.queries() != msg2.queries() {
        return false;
    }

    // now compare answers
    if !records_equal(msg1.answers(), msg2.answers()) {
        return false;
    }
    if !records_equal(msg1.name_servers(), msg2.name_servers()) {
        return false;
    }
    if !records_equal(msg1.additionals(), msg2.additionals()) {
        return false;
    }

    // everything is effectively equal
    true
}

fn records_equal(records1: &[Record], records2: &[Record]) -> bool {
    for (record1, record2) in records1.iter().zip(records2.iter()) {
        if !record_equal(record1, record2) {
            return false;
        }
    }

    true
}

/// Some RDATAs don't roundtrip elegantly, so we have custom matching rules here.
#[allow(clippy::single_match)]
fn record_equal(record1: &Record, record2: &Record) -> bool {
    use trust_dns_proto::rr::RData;

    if record1.record_type() != record2.record_type() {
        return false;
    }

    // FIXME: evaluate why these don't work
    // record types we're skipping for now
    match record1.record_type() {
        RecordType::CSYNC => return true,
        _ => (),
    }

    // if the record data matches, we're fine
    if record1.data() == record2.data() {
        return true;
    }

    // custom rules to match..
    match (record1.data(), record2.data()) {
        (None, Some(RData::OPT(opt))) | (Some(RData::OPT(opt)), None) => {
            if opt.as_ref().is_empty() {
                return true;
            }
        }
        _ => return false,
    }

    false
}
