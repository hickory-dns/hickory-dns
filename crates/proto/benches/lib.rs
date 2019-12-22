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
