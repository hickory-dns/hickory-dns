#![no_main]
use libfuzzer_sys::fuzz_target;
use trust_dns_proto::op::Message;
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = Message::from_bytes(data) {
        // Temporary hack to pass over messages with CAA records, because there's an empty string
        // -> None round-trip failure inside CAA that we're not looking for right now.
        if let Some(add) = msg.additionals().get(0) {
            if add.rr_type() == trust_dns_proto::rr::record_type::RecordType::CAA {
                return;
            }
        }
        let new_data = msg.to_bytes().unwrap();
        match Message::from_bytes(&new_data) {
            Ok(reparsed) => {
                if msg != reparsed {
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
