// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use alloc::vec::Vec;
use core::net::SocketAddr;

use futures_util::stream::iter;
use test_support::subscribe;

use super::ClientStreamXfrState::*;
use super::*;
use crate::{
    rr::{
        RData,
        rdata::{A, SOA},
    },
    runtime::TokioRuntimeProvider,
};

// Keep this in sync with the example in the README.
#[tokio::test]
async fn readme_example() {
    subscribe();

    use core::net::SocketAddr;
    use core::str::FromStr;

    use crate::client::{Client, ClientHandle};
    use crate::op::DnsResponse;
    use crate::rr::{DNSClass, Name, Record, RecordType};
    use crate::runtime::TokioRuntimeProvider;
    use crate::udp::UdpClientStream;

    let address = SocketAddr::from(([8, 8, 8, 8], 53));
    let conn = UdpClientStream::builder(address, TokioRuntimeProvider::default()).build();
    let (mut client, bg) = Client::<TokioRuntimeProvider>::connect(conn).await.unwrap();
    tokio::spawn(bg);

    // Specify the name, note the final '.' which specifies it's an FQDN
    let name = Name::from_str("www.example.com.").unwrap();

    // NOTE: see 'Setup a connection' example above
    // Send the query and get a message response, see RecordType for all supported options
    let response: DnsResponse = client
        .query(name, DNSClass::IN, RecordType::A)
        .await
        .unwrap();

    // Messages are the packets sent between client and server in DNS, DnsResponse's can be
    //  dereferenced to a Message. There are many fields to a Message, It's beyond the scope
    //  of these examples to explain them. See hickory_dns::op::message::Message for more details.
    //  generally we will be interested in the Message::answers
    let answers: &[Record] = response.answers();

    // Records are generic objects which can contain any data.
    //  In order to access it we need to first check what type of record it is
    //  In this case we are interested in A, IPv4 address
    let a_data = answers
        .iter()
        .flat_map(|record| match record.data() {
            RData::A(addr) => Some(addr),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(!a_data.is_empty());
}

fn soa_record(serial: u32) -> Record {
    let soa = RData::SOA(SOA::new(
        Name::from_ascii("example.com.").unwrap(),
        Name::from_ascii("admin.example.com.").unwrap(),
        serial,
        60,
        60,
        60,
        60,
    ));
    Record::from_rdata(Name::from_ascii("example.com.").unwrap(), 600, soa)
}

fn a_record(ip: u8) -> Record {
    let a = RData::A(A::new(0, 0, 0, ip));
    Record::from_rdata(Name::from_ascii("www.example.com.").unwrap(), 600, a)
}

fn get_stream_testcase(
    records: Vec<Vec<Record>>,
) -> impl Stream<Item = Result<DnsResponse, NetError>> + Send + Unpin + 'static {
    let stream = records.into_iter().map(|r| {
        Ok({
            let mut m = Message::query();
            m.insert_answers(r);
            DnsResponse::from_message(m).unwrap()
        })
    });
    iter(stream)
}

#[tokio::test]
async fn test_stream_xfr_valid_axfr() {
    subscribe();
    let stream = get_stream_testcase(vec![vec![
        soa_record(3),
        a_record(1),
        a_record(2),
        soa_record(3),
    ]]);
    let mut stream = ClientStreamXfr::new(stream, false);
    assert!(matches!(stream.state, Start { .. }));

    let response = stream.next().await.unwrap().unwrap();
    assert!(matches!(stream.state, Ended));
    assert_eq!(response.answers().len(), 4);

    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn test_stream_xfr_valid_axfr_multipart() {
    subscribe();
    let stream = get_stream_testcase(vec![
        vec![soa_record(3)],
        vec![a_record(1)],
        vec![soa_record(3)],
        vec![a_record(2)], // will be ignored as connection is dropped before reading this message
    ]);
    let mut stream = ClientStreamXfr::new(stream, false);
    assert!(matches!(stream.state, Start { .. }));

    let response = stream.next().await.unwrap().unwrap();
    assert!(matches!(stream.state, Second { .. }));
    assert_eq!(response.answers().len(), 1);

    let response = stream.next().await.unwrap().unwrap();
    assert!(matches!(stream.state, Axfr { .. }));
    assert_eq!(response.answers().len(), 1);

    let response = stream.next().await.unwrap().unwrap();
    assert!(matches!(stream.state, Ended));
    assert_eq!(response.answers().len(), 1);

    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn test_stream_xfr_empty_axfr() {
    subscribe();
    let stream = get_stream_testcase(vec![vec![soa_record(3)], vec![soa_record(3)]]);
    let mut stream = ClientStreamXfr::new(stream, false);
    assert!(matches!(stream.state, Start { .. }));

    let response = stream.next().await.unwrap().unwrap();
    assert!(matches!(stream.state, Second { .. }));
    assert_eq!(response.answers().len(), 1);

    let response = stream.next().await.unwrap().unwrap();
    assert!(matches!(stream.state, Ended));
    assert_eq!(response.answers().len(), 1);

    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn test_stream_xfr_axfr_with_ixfr_reply() {
    subscribe();
    let stream = get_stream_testcase(vec![vec![
        soa_record(3),
        soa_record(2),
        a_record(1),
        soa_record(3),
        a_record(2),
        soa_record(3),
    ]]);
    let mut stream = ClientStreamXfr::new(stream, false);
    assert!(matches!(stream.state, Start { .. }));

    stream.next().await.unwrap().unwrap_err();
    assert!(matches!(stream.state, Ended));

    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn test_stream_xfr_axfr_with_non_xfr_reply() {
    subscribe();
    let stream = get_stream_testcase(vec![
        vec![a_record(1)], // assume this is an error response, not a zone transfer
        vec![a_record(2)],
    ]);
    let mut stream = ClientStreamXfr::new(stream, false);
    assert!(matches!(stream.state, Start { .. }));

    let response = stream.next().await.unwrap().unwrap();
    assert!(matches!(stream.state, Ended));
    assert_eq!(response.answers().len(), 1);

    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn test_stream_xfr_invalid_axfr_multipart() {
    subscribe();
    let stream = get_stream_testcase(vec![
        vec![soa_record(3)],
        vec![a_record(1)],
        vec![soa_record(3), a_record(2)],
        vec![soa_record(3)],
    ]);
    let mut stream = ClientStreamXfr::new(stream, false);
    assert!(matches!(stream.state, Start { .. }));

    let response = stream.next().await.unwrap().unwrap();
    assert!(matches!(stream.state, Second { .. }));
    assert_eq!(response.answers().len(), 1);

    let response = stream.next().await.unwrap().unwrap();
    assert!(matches!(stream.state, Axfr { .. }));
    assert_eq!(response.answers().len(), 1);

    stream.next().await.unwrap().unwrap_err();
    assert!(matches!(stream.state, Ended));

    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn test_stream_xfr_valid_ixfr() {
    subscribe();
    let stream = get_stream_testcase(vec![vec![
        soa_record(3),
        soa_record(2),
        a_record(1),
        soa_record(3),
        a_record(2),
        soa_record(3),
    ]]);
    let mut stream = ClientStreamXfr::new(stream, true);
    assert!(matches!(stream.state, Start { .. }));

    let response = stream.next().await.unwrap().unwrap();
    assert!(matches!(stream.state, Ended));
    assert_eq!(response.answers().len(), 6);

    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn test_stream_xfr_valid_ixfr_multipart() {
    subscribe();
    let stream = get_stream_testcase(vec![
        vec![soa_record(3)],
        vec![soa_record(2)],
        vec![a_record(1)],
        vec![soa_record(3)],
        vec![a_record(2)],
        vec![soa_record(3)],
        vec![a_record(3)], //
    ]);
    let mut stream = ClientStreamXfr::new(stream, true);
    assert!(matches!(stream.state, Start { .. }));

    let response = stream.next().await.unwrap().unwrap();
    assert!(matches!(stream.state, Second { .. }));
    assert_eq!(response.answers().len(), 1);

    let response = stream.next().await.unwrap().unwrap();
    assert!(matches!(stream.state, Ixfr { even: true, .. }));
    assert_eq!(response.answers().len(), 1);

    let response = stream.next().await.unwrap().unwrap();
    assert!(matches!(stream.state, Ixfr { even: true, .. }));
    assert_eq!(response.answers().len(), 1);

    let response = stream.next().await.unwrap().unwrap();
    assert!(matches!(stream.state, Ixfr { even: false, .. }));
    assert_eq!(response.answers().len(), 1);

    let response = stream.next().await.unwrap().unwrap();
    assert!(matches!(stream.state, Ixfr { even: false, .. }));
    assert_eq!(response.answers().len(), 1);

    let response = stream.next().await.unwrap().unwrap();
    assert!(matches!(stream.state, Ended));
    assert_eq!(response.answers().len(), 1);

    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn async_client() {
    subscribe();
    use crate::client::{Client, ClientHandle};
    use crate::{
        rr::{DNSClass, Name, RData, RecordType},
        tcp::TcpClientStream,
    };
    use core::str::FromStr;

    // Since we used UDP in the previous examples, let's change things up a bit and use TCP here
    let addr = SocketAddr::from(([8, 8, 8, 8], 53));
    let (stream, sender) = TcpClientStream::new(addr, None, None, TokioRuntimeProvider::new());

    // Create a new client, the bg is a background future which handles
    //   the multiplexing of the DNS requests to the server.
    //   the client is a handle to an unbounded queue for sending requests via the
    //   background. The background must be scheduled to run before the client can
    //   send any dns requests
    let client = Client::<TokioRuntimeProvider>::new(stream, sender, None);

    // await the connection to be established
    let (mut client, bg) = client.await.expect("connection failed");

    // make sure to run the background task
    tokio::spawn(bg);

    // Create a query future
    let query = client.query(
        Name::from_str("www.example.com.").unwrap(),
        DNSClass::IN,
        RecordType::A,
    );

    // wait for its response
    let (message_returned, buffer) = query.await.unwrap().into_parts();

    // validate it's what we expected
    if let RData::A(addr) = message_returned.answers()[0].data() {
        assert_eq!(*addr, A::new(93, 184, 215, 14));
    }

    let message_parsed = Message::from_vec(&buffer)
        .expect("buffer was parsed already by Client so we should be able to do it again");

    // validate it's what we expected
    if let RData::A(addr) = message_parsed.answers()[0].data() {
        assert_eq!(*addr, A::new(93, 184, 215, 14));
    }
}
