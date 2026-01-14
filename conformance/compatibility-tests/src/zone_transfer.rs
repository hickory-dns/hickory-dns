// Copyright 2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use futures::TryStreamExt;
use time::Duration;

use hickory_net::client::{Client, ClientHandle};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::xfer::DnsMultiplexer;
use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::A};
use test_support::subscribe;

use dns_test::{
    FQDN, Implementation, Network,
    name_server::{AdditionalZoneConfig, NameServer, ZoneAcl},
    record::{A as TestA, Record as DnsTestRecord, SOA, SoaSettings},
    zone_file::ZoneFile,
};

macro_rules! assert_serial {
    ( $record:expr, $serial:expr  ) => {{
        let rdata = $record.data();
        if let RData::SOA(soa) = rdata {
            assert_eq!(soa.serial(), $serial);
        } else {
            panic!("record was not a SOA");
        }
    }};
}

#[tokio::test]
async fn test_zone_transfer() {
    subscribe();

    let mut ns = NameServer::new(
        &Implementation::Bind,
        FQDN::from_str("example.com.").unwrap(),
        &Network::new().unwrap(),
    )
    .unwrap();

    // Create an extra zone file that has too many records to be
    // returned in a single TCP message.
    let mut zone_file = ZoneFile::new(SOA {
        zone: FQDN::from_str("example.net.").unwrap(),
        ttl: 86400,
        nameserver: FQDN::from_str("example.net.").unwrap(),
        admin: FQDN::from_str("root.example.net.").unwrap(),
        settings: SoaSettings {
            serial: 20210101,
            ..SoaSettings::default()
        },
    });

    // Add NS record for the zone
    zone_file.add(DnsTestRecord::ns(
        FQDN::from_str("example.net.").unwrap(),
        FQDN::from_str("hickory-dns.org.").unwrap(),
    ));

    // Add a bunch of mock records to bloat the zone.
    let bogus_record_count = 2000;
    for i in 0..bogus_record_count {
        zone_file.add(TestA {
            fqdn: FQDN::from_str(&format!("www{i}.example.net.")).unwrap(),
            ttl: 86400,
            ipv4_addr: Ipv4Addr::new(127, 0, 0, 1),
        });
    }

    // Add the extra zone along with configuration to allow unsigned transfers and updates.
    ns.add_zone_with_config(
        FQDN::from_str("example.net.").unwrap(),
        zone_file,
        AdditionalZoneConfig::default()
            .allow_transfer(ZoneAcl::Any)
            .allow_update(ZoneAcl::Any),
    );

    let ns = ns.start().unwrap();
    let socket = SocketAddr::new(IpAddr::V4(ns.ipv4_addr()), 53);
    let (future, sender) =
        TcpClientStream::new(socket, None, None, TokioRuntimeProvider::default());
    let stream = future.await.expect("failed to connect");
    let multiplexer = DnsMultiplexer::new(stream, sender, None);

    let (mut client, driver) = Client::<TokioRuntimeProvider>::from_sender(multiplexer);
    tokio::spawn(driver);

    let name = Name::from_str("example.net.").unwrap();
    let result = client
        .zone_transfer(name.clone(), None)
        .try_collect::<Vec<_>>()
        .await
        .expect("query failed");

    assert_ne!(result.len(), 1);
    assert_eq!(
        result.iter().map(|r| r.answers().len()).sum::<usize>(),
        bogus_record_count + 3
    );

    let RData::SOA(soa) = result[0].answers()[0].data() else {
        panic!("First answer was not an SOA record");
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

    let record = Record::from_rdata(
        Name::from_str("new.example.net.").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    client
        .create(record, name.clone())
        .await
        .expect("create failed");

    let result = client
        .zone_transfer(name, Some(soa.clone()))
        .try_collect::<Vec<_>>()
        .await
        .expect("query failed");
    assert_eq!(result.len(), 1);
    let result = &result[0];
    assert_eq!(result.answers().len(), 3 + 2);

    assert_serial!(result.answers()[0], 20210102);
    assert_serial!(result.answers()[1], 20210101);
    assert_serial!(result.answers()[2], 20210102);
    assert_eq!(result.answers()[3].record_type(), RecordType::A);
    assert_serial!(result.answers()[4], 20210102);
}
