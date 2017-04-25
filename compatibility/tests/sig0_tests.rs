extern crate trust_dns_compatibility;

use trust_dns_compatibility::named_process;

#[test]
fn test_create() {
    named_process();

    let catalog = Catalog::new();
    let (client, origin) = create_sig0_ready_client(catalog);

    // create a record
    let mut record = Record::with(domain::Name::with_labels(vec!["new".to_string(),
                                                                 "example".to_string(),
                                                                 "com".to_string()]),
                                  RecordType::A,
                                  Duration::minutes(5).num_seconds() as u32);
    record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));


    let result = client
        .create(record.clone(), origin.clone())
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    let result = client
        .query(record.name(), record.dns_class(), record.rr_type())
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0], record);

    // trying to create again should error
    // TODO: it would be cool to make this
    let result = client
        .create(record.clone(), origin.clone())
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);

    // will fail if already set and not the same value.
    let mut record = record.clone();
    record.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));

    let result = client
        .create(record.clone(), origin.clone())
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);

}

#[test]
fn test_update() {
    // named_process();
}

#[test]
fn test_delete() {
    // named_process();
}