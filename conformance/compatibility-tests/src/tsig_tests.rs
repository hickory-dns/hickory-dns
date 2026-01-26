// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(test)]

use std::net::Ipv4Addr;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use futures::TryStreamExt;
use time::Duration;

use hickory_net::client::{Client, ClientHandle};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::udp::UdpClientStream;
use hickory_net::xfer::DnsMultiplexer;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{TSigner, Name, RData, Record, rdata::{A, tsig::TsigAlgorithm}};
use test_support::subscribe;

use dns_test::{
    FQDN, Implementation, Network,
    name_server::{AdditionalZoneConfig, NameServer, ZoneAcl},
    record::{A as TestA, Record as DnsTestRecord, SOA, SoaSettings},
    tsig::{TsigAlgorithm as TestTsigAlgorithm, TsigKey, TsigSecretKey},
    zone_file::ZoneFile,
};

#[tokio::test]
async fn test_create() {
    subscribe();

    let (tsig_key, signer) = tsig_key_and_signer();

    // Create a BIND nameserver that's configured to use TSIG authentication.
    let mut ns = NameServer::new(
        &Implementation::Bind,
        FQDN::from_str("example.com.").unwrap(),
        &Network::new().unwrap(),
    )
    .unwrap();
    ns.tsig_key(tsig_key.clone());

    // Create an extra zone file that allows TSIG signed updates
    ns.add_zone_with_config(
        FQDN::from_str("example.net.").unwrap(),
        extra_zone(),
        AdditionalZoneConfig::default().allow_update(ZoneAcl::TsigKey(tsig_key.name.clone())),
    );

    let ns = ns.start().unwrap();

    // Create a Hickory sender/client also configured for TSIG with the same key
    // material.
    let socket = SocketAddr::new(IpAddr::V4(ns.ipv4_addr()), 53);
    let sender = UdpClientStream::builder(socket, TokioRuntimeProvider::default())
        .with_signer(Some(signer))
        .build();
    let (mut client, driver) = Client::<TokioRuntimeProvider>::from_sender(sender);
    tokio::spawn(driver);

    // Create a record.
    let mut record = Record::from_rdata(
        Name::from_str("new.example.net.").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    let origin = Name::from_str("example.net.").unwrap();
    let result = client
        .create(record.clone(), origin.clone())
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    let result = client
        .query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        )
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0], record);

    // Trying to create the record again should error.
    let result = client
        .create(record.clone(), origin.clone())
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);

    // Similarly, trying to create the record again should fail if already set and
    // the update is not the same value.
    record.set_data(RData::A(A::new(101, 11, 101, 11)));

    let result = client.create(record, origin).await.expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);
}

#[tokio::test]
async fn test_tsig_zone_transfer() {
    subscribe();

    let (tsig_key, signer) = tsig_key_and_signer();

    // Create a BIND nameserver.
    let mut ns = NameServer::new(
        &Implementation::Bind,
        FQDN::from_str("example.com.").unwrap(),
        &Network::new().unwrap(),
    )
    .unwrap();
    // Configure the nameserver with the TSIG key.
    ns.tsig_key(tsig_key.clone());

    // Create an extra zone file that has too many records to be
    // returned in a single TCP message.
    let bogus_record_count = 2000;
    let mut zone_file = extra_zone();
    for i in 0..bogus_record_count {
        zone_file.add(TestA {
            fqdn: FQDN::from_str(&format!("www{i}.example.net.")).unwrap(),
            ttl: 86400,
            ipv4_addr: Ipv4Addr::new(127, 0, 0, 1),
        });
    }

    // Add the extra zone, configured to allow zone transfers signed by the TSIG key.
    ns.add_zone_with_config(
        FQDN::from_str("example.net.").unwrap(),
        zone_file,
        AdditionalZoneConfig::default().allow_transfer(ZoneAcl::TsigKey(tsig_key.name.clone())),
    );

    let ns = ns.start().unwrap();
    let socket = SocketAddr::new(IpAddr::V4(ns.ipv4_addr()), 53);
    let (future, sender) =
        TcpClientStream::new(socket, None, None, TokioRuntimeProvider::default());
    let multiplexer = DnsMultiplexer::new(future.await.unwrap(), sender).with_signer(signer);

    let (mut client, driver) = Client::<TokioRuntimeProvider>::from_sender(multiplexer);
    tokio::spawn(driver);

    let name = Name::from_str("example.net.").unwrap();
    let result = client
        .zone_transfer(name.clone(), None)
        .try_collect::<Vec<_>>()
        .await
        .expect("query failed");

    // The results should be spread across more than one `DnsResponse` due to the zone size
    assert_ne!(result.len(), 1);

    // We should have received the expected number of records; the count of bogus
    // records, plus the additional metadata records (SOA, NS, etc).
    assert_eq!(
        result.iter().map(|r| r.answers().len()).sum::<usize>(),
        bogus_record_count + 3
    );
}

fn tsig_key_and_signer() -> (TsigKey, Arc<TSigner>) {
    let tsig_key = TsigKey {
        name: "TsigTestCreateKey.".to_owned(),
        algorithm: TestTsigAlgorithm::HmacSha256,
        secret_key: TsigSecretKey(b"!! t0p $3cr3t !!".to_vec()),
    };
    let signer = Arc::new(
        TSigner::new(
            tsig_key.secret_key.0.clone(),
            match tsig_key.algorithm {
                TestTsigAlgorithm::HmacSha256 => TsigAlgorithm::HmacSha256,
                TestTsigAlgorithm::HmacSha384 => TsigAlgorithm::HmacSha384,
                TestTsigAlgorithm::HmacSha512 => TsigAlgorithm::HmacSha512,
            },
            Name::from_str(&tsig_key.name).unwrap(),
            60,
        )
        .unwrap(),
    );
    (tsig_key, signer)
}

fn extra_zone() -> ZoneFile {
    let mut zone_file = ZoneFile::new(SOA {
        zone: FQDN::from_str("example.net.").unwrap(),
        ttl: 86400,
        nameserver: FQDN::from_str("example.net.").unwrap(),
        admin: FQDN::from_str("root.example.net.").unwrap(),
        settings: SoaSettings::default(),
    });

    // Add NS record for the zone
    zone_file.add(DnsTestRecord::ns(
        FQDN::from_str("example.net.").unwrap(),
        FQDN::from_str("hickory-dns.org.").unwrap(),
    ));

    zone_file
}
