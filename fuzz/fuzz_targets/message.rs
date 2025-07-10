#![no_main]
use libfuzzer_sys::fuzz_target;
use pretty_assertions::assert_eq;

use hickory_proto::{
    ProtoErrorKind,
    op::Message,
    rr::Record,
    serialize::binary::{BinDecodable, BinEncodable},
};

fuzz_target!(|data: &[u8]| {
    let Ok(original) = Message::from_bytes(data) else {
        // If we can't parse the original message, we can't re-encode it.
        return;
    };

    let reencoded = match original.to_bytes() {
        Ok(reencoded) => reencoded,
        // If we can't re-encode the original message, we can't re-parse it.
        Err(err) if matches!(err.kind(), ProtoErrorKind::NotAllRecordsWritten { .. }) => return,
        Err(err) => {
            eprintln!("{original:?}");
            panic!("Message failed to serialize: {err:?}");
        }
    };

    let reparsed = match Message::from_bytes(&reencoded) {
        Ok(reparsed) => reparsed,
        Err(e) => {
            eprintln!("{original:?}");
            panic!("Message failed to deserialize: {e:?}");
        }
    };

    if !messages_equal(&original, &reparsed) {
        assert_eq!(original, reparsed);
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
    if !records_equal(original.authorities(), reparsed.authorities()) {
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
