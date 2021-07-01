#![feature(test)]

extern crate test;

use trust_dns_proto::op::{Header, Message, MessageType, OpCode, ResponseCode};
use trust_dns_proto::rr::Record;
use trust_dns_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};

use test::Bencher;

#[bench]
fn bench_emit_header(b: &mut Bencher) {
    let header = Header::new();
    b.iter(|| {
        // we need to create the vector here, otherwise its length is already big enough and the
        // encoder does not need to resize it
        let mut bytes = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut bytes);
        header.emit(&mut encoder)
    })
}

// TODO:
// This is a bit silly, because everywhere in the codebase, we reserve 512 bytes for the buffer.
// But what we want to measure here is the cost of reserving more space, which can happen for big
// messages exceeding 512 bytes. A better benchmark would be to emit such a big message.
#[bench]
fn bench_parse_header_no_reservation(b: &mut Bencher) {
    let header = Header::new();
    b.iter(|| {
        let mut bytes = Vec::with_capacity(0);
        let mut encoder = BinEncoder::new(&mut bytes);
        header.emit(&mut encoder)
    })
}

#[bench]
fn bench_parse_header(b: &mut Bencher) {
    let byte_vec = vec![
        0x01, 0x10, 0xAA, 0x83, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    ];
    b.iter(|| {
        let mut decoder = BinDecoder::new(&byte_vec);
        Header::read(&mut decoder)
    })
}

#[bench]
fn bench_emit_message(b: &mut Bencher) {
    let mut message = Message::new();
    message
        .set_id(10)
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Update)
        .set_authoritative(true)
        .set_truncated(true)
        .set_recursion_desired(true)
        .set_recursion_available(true)
        .set_authentic_data(true)
        .set_checking_disabled(true)
        .set_response_code(ResponseCode::ServFail);
    message.add_answer(Record::new());
    message.add_name_server(Record::new());
    message.add_additional(Record::new());
    b.iter(|| {
        let mut byte_vec: Vec<u8> = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut byte_vec);
        message.emit(&mut encoder)
    })
}

#[bench]
fn bench_emit_message_no_reservation(b: &mut Bencher) {
    let mut message = Message::new();
    message
        .set_id(10)
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Update)
        .set_authoritative(true)
        .set_truncated(true)
        .set_recursion_desired(true)
        .set_recursion_available(true)
        .set_authentic_data(true)
        .set_checking_disabled(true)
        .set_response_code(ResponseCode::ServFail);
    message.add_answer(Record::new());
    message.add_name_server(Record::new());
    message.add_additional(Record::new());
    b.iter(|| {
        let mut byte_vec: Vec<u8> = Vec::with_capacity(0);
        let mut encoder = BinEncoder::new(&mut byte_vec);
        message.emit(&mut encoder)
    })
}

#[bench]
fn bench_parse_message(b: &mut Bencher) {
    let mut message = Message::new();
    message
        .set_id(10)
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Update)
        .set_authoritative(true)
        .set_truncated(true)
        .set_recursion_desired(true)
        .set_recursion_available(true)
        .set_authentic_data(true)
        .set_checking_disabled(true)
        .set_response_code(ResponseCode::ServFail);

    message.add_answer(Record::new());
    message.add_name_server(Record::new());
    message.add_additional(Record::new());
    let mut byte_vec: Vec<u8> = Vec::with_capacity(512);
    {
        let mut encoder = BinEncoder::new(&mut byte_vec);
        message.emit(&mut encoder).unwrap();
    }
    b.iter(|| {
        let mut decoder = BinDecoder::new(&byte_vec);
        Message::read(&mut decoder)
    })
}

#[bench]
fn bench_parse_real_message(b: &mut Bencher) {
    let bytes = [
        145, 188, 129, 128, 0, 1, 0, 6, 0, 0, 0, 0, 5, 118, 105, 100, 101, 111, 5, 116, 119, 105,
        109, 103, 3, 99, 111, 109, 0, 0, 1, 0, 1, 192, 12, 0, 5, 0, 1, 0, 0, 0, 245, 0, 11, 8, 118,
        105, 100, 101, 111, 45, 97, 107, 192, 18, 192, 45, 0, 5, 0, 1, 0, 0, 12, 213, 0, 24, 5,
        118, 105, 100, 101, 111, 5, 116, 119, 105, 109, 103, 6, 97, 107, 97, 100, 110, 115, 3, 110,
        101, 116, 0, 192, 68, 0, 5, 0, 1, 0, 0, 0, 57, 0, 28, 5, 118, 105, 100, 101, 111, 5, 116,
        119, 105, 109, 103, 3, 99, 111, 109, 9, 97, 107, 97, 109, 97, 105, 122, 101, 100, 192, 87,
        192, 104, 0, 5, 0, 1, 0, 0, 2, 194, 0, 22, 5, 118, 105, 100, 101, 111, 5, 116, 119, 105,
        109, 103, 3, 99, 111, 109, 3, 101, 105, 112, 192, 80, 192, 144, 0, 5, 0, 1, 0, 0, 0, 43, 0,
        35, 8, 101, 105, 112, 45, 116, 97, 116, 97, 5, 118, 105, 100, 101, 111, 5, 116, 119, 105,
        109, 103, 3, 99, 111, 109, 7, 97, 107, 97, 104, 111, 115, 116, 192, 87, 192, 178, 0, 1, 0,
        1, 0, 0, 0, 23, 0, 4, 184, 31, 3, 236,
    ];
    b.iter(|| {
        let mut decoder = BinDecoder::new(&bytes[..]);
        assert!(Message::read(&mut decoder).is_ok());
    })
}
