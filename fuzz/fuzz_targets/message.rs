#![no_main]
use libfuzzer_sys::fuzz_target;

use hickory_proto::{
    op::Message,
    rr::{Record, RecordType},
    serialize::binary::{BinDecodable, BinEncodable},
};

fuzz_target!(|data: &[u8]| {
    if let Ok(original) = Message::from_bytes(data) {
        let reencoded = original.to_bytes().unwrap();
        match Message::from_bytes(&reencoded) {
            Ok(reparsed) => {
                if !messages_equal(&original, &reparsed) {
                    for (m, r) in format!("{:#?}", original)
                        .lines()
                        .zip(format!("{:#?}", reparsed).lines())
                    {
                        if m != r {
                            println!("{} -> {}", m, r);
                        }
                    }
                    assert_eq!(original, reparsed);
                }
            }
            Err(e) => {
                eprintln!("{:?}", original);
                panic!("Message failed to deserialize: {:?}", e);
            }
        }
    }
});

fn messages_equal(original: &Message, reparsed: &Message) -> bool {
    if original == reparsed {
        return true;
    }

    // see if there are some of the records that don't round trip properly...
    if reparsed.truncated() {
        // TODO: there might be a better comparison to make here.
        return true;
    }

    // compare headers
    if original.header() != reparsed.header() {
        return false;
    }

    // compare queries
    if original.queries() != reparsed.queries() {
        return false;
    }

    // now compare answers
    if !records_equal(original.answers(), reparsed.answers()) {
        return false;
    }
    if !records_equal(original.name_servers(), reparsed.name_servers()) {
        return false;
    }
    if !records_equal(original.additionals(), reparsed.additionals()) {
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
    use hickory_proto::rr::RData;

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
        (RData::Update0(_), RData::OPT(opt)) | (RData::OPT(opt), RData::Update0(_)) => {
            if opt.as_ref().is_empty() {
                return true;
            }
        }
        _ => return false,
    }

    false
}
