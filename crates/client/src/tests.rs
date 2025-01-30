// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use test_support::subscribe;

// Keep this in sync with the example in the README.
#[tokio::test]
async fn readme_example() {
    subscribe();

    use std::net::SocketAddr;
    use std::str::FromStr;

    use crate::client::{Client, ClientHandle};
    use crate::proto::rr::{DNSClass, Name, Record, RecordType};
    use crate::proto::runtime::TokioRuntimeProvider;
    use crate::proto::udp::UdpClientStream;
    use crate::proto::xfer::DnsResponse;

    let address = SocketAddr::from(([8, 8, 8, 8], 53));
    let conn = UdpClientStream::builder(address, TokioRuntimeProvider::default()).build();
    let (mut client, bg) = Client::connect(conn).await.unwrap();
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
        .flat_map(|record| record.data().as_a())
        .collect::<Vec<_>>();
    assert!(!a_data.is_empty());
}
