use dns_test::{
    FQDN, Network, PEER, Resolver, Result,
    client::{Client, DigSettings},
    name_server::{Graph, NameServer, Sign},
    record::{Record, RecordType, UnknownRdata},
};

/// See RFC 3597, section 3, "Transparency":
///
/// "To enable new RR types to be deployed without server changes, name servers and resolvers MUST
/// handle RRs of unknown type transparently. That is, they must treat the RDATA section of such RRs
/// as unstructured binary data, storing and transmitting it without change."
#[test]
fn unknown_type_transparency() -> Result<()> {
    let network = Network::new()?;

    let mut leaf_ns = NameServer::new(&PEER, FQDN::TEST_DOMAIN, &network)?;
    leaf_ns.add(Record::Unknown(UnknownRdata {
        zone: FQDN::TEST_DOMAIN,
        ttl: 86400,
        r#type: 1234,
        rdata: [0xde, 0xad, 0xbe, 0xef].to_vec(),
    }));
    println!("{}", leaf_ns.zone_file());

    let Graph {
        nameservers: _nameservers,
        root,
        ..
    } = Graph::build(leaf_ns, Sign::No)?;

    let resolver = Resolver::new(&network, root).start()?;
    let client = Client::new(&network)?;

    let settings = *DigSettings::default().recurse();
    let output = client.dig(
        settings,
        resolver.ipv4_addr(),
        RecordType::Unknown(1234),
        &FQDN::TEST_DOMAIN,
    )?;
    dbg!(&output);

    assert!(output.status.is_noerror(), "{:?}", output.status);

    let [answer] = output.answer.try_into().unwrap();
    let Record::Unknown(record) = answer else {
        panic!("unexpected record type: {answer:?}");
    };
    assert_eq!(record.zone, FQDN::TEST_DOMAIN);
    assert_eq!(record.r#type, 1234);
    assert_eq!(record.rdata, [0xde, 0xad, 0xbe, 0xef]);

    Ok(())
}
