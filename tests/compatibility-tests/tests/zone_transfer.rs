// Copyright 2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[cfg(not(feature = "none"))]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(not(feature = "none"))]
use std::str::FromStr;

#[cfg(not(feature = "none"))]
use time::Duration;

#[cfg(not(feature = "none"))]
use hickory_client::client::{Client, SyncClient};
#[cfg(not(feature = "none"))]
use hickory_client::rr::{Name, RData, Record, RecordType};
#[cfg(not(feature = "none"))]
use hickory_client::tcp::TcpClientConnection;
#[cfg(not(feature = "none"))]
use hickory_compatibility::named_process;

#[allow(unused)]
macro_rules! assert_serial {
    ( $record:expr, $serial:expr  ) => {{
        let rdata = $record.data();
        if let RData::SOA(soa) = rdata {
            assert_eq!(soa.serial(), $serial);
        } else {
            assert!(false, "record was not a SOA");
        }
    }};
}

#[cfg(not(feature = "none"))]
#[test]
#[allow(unused)]
fn test_zone_transfer() {
    use hickory_client::rr::rdata::A;

    let (process, port) = named_process();
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
    let conn = TcpClientConnection::new(socket).unwrap();
    let client = SyncClient::new(conn);

    let name = Name::from_str("example.net.").unwrap();
    let result = client.zone_transfer(&name, None).expect("query failed");
    let result = result.collect::<Result<Vec<_>, _>>().unwrap();
    assert_ne!(result.len(), 1);
    assert_eq!(
        result.iter().map(|r| r.answers().len()).sum::<usize>(),
        2000 + 3
    );

    let soa = if let RData::SOA(soa) = result[0].answers()[0].data() {
        soa
    } else {
        panic!("First answer was not an SOA record")
    };

    assert_eq!(result[0].answers()[0].record_type(), RecordType::SOA);
    assert_eq!(
        result
            .last()
            .unwrap()
            .answers()
            .last()
            .unwrap()
            .record_type(),
        RecordType::SOA
    );

    let mut record = Record::from_rdata(
        Name::from_str("new.example.net.").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    client.create(record, name.clone()).expect("create failed");

    let result = client
        .zone_transfer(&name, Some(soa.clone()))
        .expect("query failed");
    let result = result.collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(result.len(), 1);
    let result = &result[0];
    assert_eq!(result.answers().len(), 3 + 2);

    assert_serial!(result.answers()[0], 20210102);
    assert_serial!(result.answers()[1], 20210101);
    assert_serial!(result.answers()[2], 20210102);
    assert_eq!(result.answers()[3].record_type(), RecordType::A);
    assert_serial!(result.answers()[4], 20210102);
}
