// Copyright 2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[cfg(not(feature = "none"))]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(not(feature = "none"))]
use std::str::FromStr;

#[cfg(not(feature = "none"))]
use trust_dns_client::client::{Client, SyncClient};
#[cfg(not(feature = "none"))]
use trust_dns_client::rr::{Name, RecordType};
#[cfg(not(feature = "none"))]
use trust_dns_client::tcp::TcpClientConnection;
#[cfg(not(feature = "none"))]
use trust_dns_compatibility::named_process;

#[cfg(not(feature = "none"))]
#[test]
#[allow(unused)]
fn test_zone_transfer() {
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
    assert_eq!(result[0].answers()[0].rr_type(), RecordType::SOA);
    assert_eq!(
        result.last().unwrap().answers().last().unwrap().rr_type(),
        RecordType::SOA
    );
}
