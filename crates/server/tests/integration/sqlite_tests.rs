#![cfg(feature = "sqlite")]

use std::str::FromStr;

use rusqlite::*;

use hickory_proto::rr::{rdata::A, *};
use hickory_server::store::sqlite::persistence::CURRENT_VERSION;
use hickory_server::store::sqlite::Journal;

#[test]
fn test_new_journal() {
    let conn = Connection::open_in_memory().expect("could not create in memory DB");
    assert_eq!(
        Journal::new(conn).expect("new Journal").schema_version(),
        -1
    );
}

#[test]
fn test_init_journal() {
    let conn = Connection::open_in_memory().expect("could not create in memory DB");
    let mut journal = Journal::new(conn).unwrap();
    let version = journal.schema_up().unwrap();
    assert_eq!(version, CURRENT_VERSION);
    assert_eq!(
        Journal::select_schema_version(&journal.conn()).unwrap(),
        CURRENT_VERSION
    );
}

fn create_test_journal() -> (Record, Journal) {
    let www = Name::from_str("www.example.com").unwrap();

    let mut record = Record::from_rdata(www, 0, RData::A(A::from_str("127.0.0.1").unwrap()));

    // test that this message can be inserted
    let conn = Connection::open_in_memory().expect("could not create in memory DB");
    let mut journal = Journal::new(conn).unwrap();
    journal.schema_up().unwrap();

    // insert the message
    journal.insert_record(0, &record).unwrap();

    // insert another...
    record.set_data(RData::A(A::from_str("127.0.1.1").unwrap()));
    journal.insert_record(0, &record).unwrap();

    (record, journal)
}

#[test]
fn test_insert_and_select_record() {
    let (mut record, journal) = create_test_journal();

    // select the record
    let (row_id, journal_record) = journal
        .select_record(0)
        .expect("persistence error")
        .expect("none");
    record.set_data(RData::A(A::from_str("127.0.0.1").unwrap()));
    assert_eq!(journal_record, record);

    // test another
    let (row_id, journal_record) = journal
        .select_record(row_id + 1)
        .expect("persistence error")
        .expect("none");
    record.set_data(RData::A(A::from_str("127.0.1.1").unwrap()));
    assert_eq!(journal_record, record);

    // check that we get nothing for id over row_id
    let option_none = journal
        .select_record(row_id + 1)
        .expect("persistence error");
    assert!(option_none.is_none());
}

#[test]
fn test_iterator() {
    let (mut record, journal) = create_test_journal();

    let mut iter = journal.iter();

    assert_eq!(
        record.set_data(RData::A(A::from_str("127.0.0.1").unwrap())),
        &iter.next().unwrap()
    );
    assert_eq!(
        record.set_data(RData::A(A::from_str("127.0.1.1").unwrap())),
        &iter.next().unwrap()
    );
    assert_eq!(None, iter.next());
}
