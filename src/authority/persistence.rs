// Copyright 2015-2016 Benjamin Fry <benjaminfry -@- me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std::iter::Iterator;
use std::path::Path;

use time;
use rusqlite;
use rusqlite::Connection;
use rusqlite::SqliteError;

use ::error::PersistenceErrorKind;
use ::error::PersistenceResult;
use ::rr::Record;
use ::serialize::binary::{BinDecoder, BinEncoder, BinSerializable};

const CURRENT_VERSION: i64 = 1;

/// The Journal is the audit log of all changes to a zone after initial creation.
pub struct Journal {
  conn: Connection,
  version: i64,
}

impl Journal {
  pub fn new(conn: Connection) -> PersistenceResult<Journal> {
    let version = Self::select_schema_version(&conn);
    Ok(Journal { conn: conn, version: try!(version) })
  }

  pub fn from_file(journal_file: &Path) -> PersistenceResult<Journal> {
    Self::new(try!(Connection::open(journal_file)))
  }

  /// gets the current schema version of the journal
  pub fn get_schema_version(&self) -> i64 {
    self.version
  }

  /// this returns an iterator from the beginning of time, to be used to recreate an authority
  pub fn iter<'j>(&'j self) -> JournalIter<'j> {
    JournalIter::new(self)
  }

  /// Inserts a record, this is an append only operation.
  ///
  /// Records should never be posthumously modified. The message will be serialized into the.
  ///  the first message serialized to the journal, should be a single AXFR of the entire zone,
  ///  this will be used as a starting point to reconstruct the zone.
  ///
  /// # Argument
  ///
  /// * `record` - will be serialized into the journal
  pub fn insert_record(&self, soa_serial: u32, record: &Record) -> PersistenceResult<()> {
    assert!(self.version == CURRENT_VERSION, "schema version mismatch, schema_up() resolves this");

    let mut serial_record: Vec<u8> = Vec::with_capacity(512);
    {
      let mut encoder = BinEncoder::new(&mut serial_record);
      try!(record.emit(&mut encoder));
    }

    let timestamp = time::get_time();
    let client_id: i64 = 0; // TODO: we need better id information about the client, like pub_key
    let soa_serial: i64 = soa_serial as i64;

    let count = try!(self.conn.execute("INSERT
                                          INTO records (client_id, soa_serial, timestamp, record)
                                          VALUES ($1, $2, $3, $4)",
                                          &[&client_id, &soa_serial, &timestamp, &serial_record]));
    //
    if count != 1 {
      return Err(PersistenceErrorKind::WrongInsertCount(count, 1).into());
    };

    Ok(())
  }

  /// Inserts a set of records into the Journal, a convenience method for insert_record
  pub fn insert_records(&self, soa_serial: u32, records: &[Record]) -> PersistenceResult<()> {
    // TODO: NEED TRANSACTION HERE
    for record in records {
      try!(self.insert_record(soa_serial, record));
    }

    Ok(())
  }

  /// Selects a record from the given row_id.
  ///
  /// This allows for the entire set of records to be iterated through, by starting at 0, and
  ///  incrementing each subsequent row.
  ///
  /// # Arguments
  ///
  /// * `row_id` - the row_id can either be exact, or start at 0 to get the earliest row in the
  ///              list.
  pub fn select_record(&self, row_id: i64) -> PersistenceResult<Option<(i64, Record)>> {
    assert!(self.version == CURRENT_VERSION, "schema version mismatch, schema_up() resolves this");

    let mut stmt = try!(self.conn.prepare("SELECT _rowid_, record
                                            FROM records
                                            WHERE _rowid_ >= $1
                                            LIMIT 1"));

    let record_opt: Option<Result<(i64, Record), SqliteError>> = try!(stmt.query_and_then(&[&row_id],
                                                                      |row| -> Result<(i64, Record), SqliteError> {
      let row_id: i64 = try!(row.get_checked(0));
      let record_bytes: Vec<u8> = try!(row.get_checked(1));
      let mut decoder = BinDecoder::new(&record_bytes);

      // todo add location to this...
      match Record::read(&mut decoder) {
        Ok(record) => Ok((row_id, record)),
        Err(decode_error) => Err(rusqlite::Error::InvalidParameterName(format!("could not decode: {}", decode_error))),
      }
    })).next();

    //
    match record_opt {
      Some(Ok((row_id, record))) => Ok(Some((row_id, record))),
      Some(Err(err)) => return Err(try!(Err(err))),
      None => Ok(None),
    }
  }

  /// selects the current schema version of the journal DB, returns -1 if there is no schema
  ///
  ///
  /// # Arguments
  ///
  /// * `conn` - db connection to use
  fn select_schema_version(conn: &Connection) -> PersistenceResult<i64> {
    // first see if our schema is there
    let mut stmt = try!(conn.prepare("SELECT name
                                        FROM sqlite_master
                                        WHERE type='table'
                                        AND name='tdns_schema'"));

    let tdns_schema_opt: Option<Result<String, _>> = try!(stmt.query_map(&[],
                                                            |row| row.get(0)))
                                                    .next();

    let tdns_schema = match tdns_schema_opt {
      Some(Ok(string)) => string,
      Some(Err(err)) => return try!(Err(err)),
      None => return Ok(-1),
    };

    assert_eq!(&tdns_schema, "tdns_schema");

    let version: i64 = try!(conn.query_row_safe("SELECT version
                                                  FROM tdns_schema",
                                                  &[],
                                                  |row| row.get(0)));

    Ok(version)
  }

  /// update the schema version
  fn update_schema_version(&self, new_version: i64) -> PersistenceResult<()> {
    // validate the versions of all the schemas...
    assert!(new_version <= CURRENT_VERSION);

    let count = try!(self.conn.execute("UPDATE tdns_schema SET version = $1", &[&new_version]));

    //
    assert_eq!(count, 1);
    Ok(())
  }

  /// initilizes the schema for the Journal
  pub fn schema_up(&mut self) -> PersistenceResult<i64> {
    while self.version < CURRENT_VERSION {
      match self.version + 1 {
        0 => self.version = try!(self.init_up()),
        1 => self.version = try!(self.records_up()),
        _ => panic!("incorrect version somewhere"),
      }

      try!(self.update_schema_version(self.version));
    }

    Ok(self.version)
  }

  /// initial schema, include the tdns_schema table for tracking the Journal version
  fn init_up(&self) -> PersistenceResult<i64> {
    let count = try!(self.conn.execute("CREATE TABLE tdns_schema (
                                          version INTEGER NOT NULL
                                        )", &[]));
    //
    assert_eq!(count, 0);

    let count = try!(self.conn.execute("INSERT INTO tdns_schema (version) VALUES (0)", &[]));
    //
    assert_eq!(count, 1);

    Ok(0)
  }

  /// adds the records table, this is the main and single table for the history of changes to an
  ///  authority. Each record is expected to be in the format of an update record
  fn records_up(&self) -> PersistenceResult<i64> {
    // we'll be using rowid for our primary key, basically: `rowid INTEGER PRIMARY KEY ASC`
    let count = try!(self.conn.execute("CREATE TABLE records (
                                          client_id      INTEGER NOT NULL,
                                          soa_serial     INTEGER NOT NULL,
                                          timestamp      TEXT NOT NULL,
                                          record         BLOB NOT NULL
                                        )", &[]));
    //
    assert_eq!(count, 1);

    Ok(1)
  }
}

pub struct JournalIter<'j> {
  current_row_id: i64,
  journal: &'j Journal,
}

impl<'j> JournalIter<'j> {
  fn new(journal: &'j Journal) -> Self {
    JournalIter { current_row_id: 0, journal: journal }
  }
}

impl<'j> Iterator for JournalIter<'j> {
  type Item = Record;

  fn next(&mut self) -> Option<Self::Item> {
    let next: PersistenceResult<Option<(i64, Record)>> = self.journal.select_record(self.current_row_id + 1);

    match next {
      Ok(Some((row_id, record))) => {
        self.current_row_id = row_id;
        Some(record)
      },
      Ok(None) => {
        None
      },
      Err(err) => {
        error!("persistence error while iterating over journal: {}", err);
        None
      }
    }
  }
}

#[test]
fn test_new_journal() {
  let conn = Connection::open_in_memory().expect("could not create in memory DB");
  assert_eq!(Journal::new(conn).expect("new Journal").get_schema_version(), -1);
}

#[test]
fn test_init_journal() {
  let conn = Connection::open_in_memory().expect("could not create in memory DB");
  let mut journal = Journal::new(conn).unwrap();
  let version = journal.schema_up().unwrap();
  assert_eq!(version, CURRENT_VERSION);
  assert_eq!(Journal::select_schema_version(&journal.conn).unwrap(), CURRENT_VERSION);
}

#[cfg(test)]
fn create_test_journal() -> (Record, Journal) {
  use std::net::Ipv4Addr;
  use std::str::FromStr;

  use ::rr::{Name, RData, Record, RecordType};

  let www = Name::with_labels(vec!["www".to_string(),"example".to_string(), "com".to_string()]);

  let mut record = Record::new();
  record.name(www);
  record.rr_type(RecordType::A);
  record.rdata(RData::A(Ipv4Addr::from_str("127.0.0.1").unwrap()));

  // test that this message can be inserted
  let conn = Connection::open_in_memory().expect("could not create in memory DB");
  let mut journal = Journal::new(conn).unwrap();
  journal.schema_up().unwrap();

  // insert the message
  journal.insert_record(0, &record).unwrap();

  // insert another...
  record.rdata(RData::A(Ipv4Addr::from_str("127.0.1.1").unwrap()));
  journal.insert_record(0, &record).unwrap();

  (record, journal)
}

#[test]
fn test_insert_and_select_record() {
  use std::net::Ipv4Addr;
  use std::str::FromStr;

  use rr::RData;

  let (mut record, journal) = create_test_journal();

  // select the record
  let (row_id, journal_record) = journal.select_record(0).expect("persistence error").expect("none");
  record.rdata(RData::A(Ipv4Addr::from_str("127.0.0.1").unwrap()));
  assert_eq!(journal_record, record);

  // test another
  let (row_id, journal_record) = journal.select_record(row_id + 1).expect("persistence error").expect("none");
  record.rdata(RData::A(Ipv4Addr::from_str("127.0.1.1").unwrap()));
  assert_eq!(journal_record, record);

  // check that we get nothing for id over row_id
  let option_none = journal.select_record(row_id + 1).expect("persistence error");
  assert!(option_none.is_none());
}

#[test]
fn test_iterator() {
  use std::net::Ipv4Addr;
  use std::str::FromStr;

  use rr::RData;

  let (mut record, journal) = create_test_journal();

  let mut iter = journal.iter();

  assert_eq!(record.rdata(RData::A(Ipv4Addr::from_str("127.0.0.1").unwrap())), &iter.next().unwrap());
  assert_eq!(record.rdata(RData::A(Ipv4Addr::from_str("127.0.1.1").unwrap())), &iter.next().unwrap());
  assert_eq!(None, iter.next());
}
