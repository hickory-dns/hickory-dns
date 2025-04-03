use dns_test::{
    FQDN, Network, PEER, Resolver, Result,
    client::{Client, DigSettings},
    name_server::{Graph, NameServer, Sign},
    record::{CAA, Record, RecordType, UnknownRdata},
    zone_file::SignSettings,
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

/// See RFC 3597, section 3, "Transparency":
///
/// "To ensure the correct operation of ... the DNSSEC canonical form (section 7) when an RR type is
/// known to some but not all of the servers involved, servers MUST also exactly preserve the RDATA
/// of RRs of known type, except for changes due to compression or decompression where allowed by
/// section 4 of this memo."
#[test]
fn caa_issue_empty_value_dnssec() -> Result<()> {
    let network = Network::new()?;

    let mut leaf_ns = NameServer::new(&PEER, FQDN::TEST_DOMAIN, &network)?;
    leaf_ns.add(Record::CAA(CAA {
        zone: FQDN::TEST_DOMAIN,
        ttl: 86400,
        flags: 0,
        tag: "issue".to_string(),
        value: "".to_string(),
    }));

    let settings = SignSettings::default();
    let Graph {
        nameservers: _nameservers,
        root,
        trust_anchor,
    } = Graph::build(leaf_ns, Sign::Yes { settings })?;
    let trust_anchor = trust_anchor.unwrap();

    let resolver = Resolver::new(&network, root)
        .trust_anchor(&trust_anchor)
        .start()?;
    let client = Client::new(&network)?;

    let settings = *DigSettings::default().dnssec().recurse();
    let output = client.dig(
        settings,
        resolver.ipv4_addr(),
        RecordType::CAA,
        &FQDN::TEST_DOMAIN,
    )?;
    dbg!(&output);

    assert!(output.status.is_noerror(), "{:?}", output.status);
    assert!(output.flags.authenticated_data);

    let caa = output
        .answer
        .into_iter()
        .filter_map(|record| record.try_into_caa().ok())
        .next()
        .expect("did not find CAA record in response");
    assert_eq!(caa.zone, FQDN::TEST_DOMAIN);
    assert_eq!(caa.flags, 0);
    assert_eq!(caa.tag, "issue");
    assert_eq!(caa.value, "");

    Ok(())
}
