// Copyright 2015-2016 Benjamin Fry <benjaminfry -@- me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std::iter::Iterator;

use time;
use time::Timespec;
use rusqlite;
use rusqlite::Connection;
use rusqlite::SqliteError;

use ::error::PersistenceError;
use ::error::PersistenceResult;
use ::op::Message;
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

  /// gets the current schema version of the journal
  pub fn get_schema_version(&self) -> i64 {
    self.version
  }

  pub fn iter<'j>(&'j self) -> JournalIter<'j> {
    JournalIter::new(self)
  }

  /// inserts a message, this is an append only operation.
  ///
  /// Messages should never be posthumously modified. The message will be serialized into the.
  ///  the first message serialized to the journal, should be a single AXFR of the entire zone,
  ///  this will be used as a starting point to reconstruct the zone.
  ///
  /// # Argument
  ///
  /// * `message` - will be serialized into the journal
  pub fn insert_message(&self, soa_serial: u32, message: &Message) -> PersistenceResult<()> {
    assert!(self.version == CURRENT_VERSION, "schema version mismatch, schema_up() resolves this");

    let mut serial_message: Vec<u8> = Vec::with_capacity(512);
    {
      let mut encoder = BinEncoder::new(&mut serial_message);
      try_rethrow!(PersistenceError::EncodeError, message.emit(&mut encoder));
    }

    let timestamp = time::get_time();
    let client_id: i64 = message.get_id() as i64;
    let soa_serial: i64 = soa_serial as i64;

    let count = try_rethrow!(PersistenceError::SqliteError,
                              self.conn.execute("INSERT
                                                 INTO messages (client_id, soa_serial, timestamp, message)
                                                 VALUES ($1, $2, $3, $4)",
                                                 &[&client_id, &soa_serial, &timestamp, &serial_message]));
    //
    if count != 1 {
      return Err(PersistenceError::WrongInsertCount{loc: error_loc!(), got: count, expect: 1});
    };

    Ok(())
  }

  /// Selects a message from the given row_id.
  ///
  /// This allows for the entire set of records to be iterated through, by starting at 0, and
  ///  incrementing each subsequent row.
  ///
  /// # Arguments
  ///
  /// * `row_id` - the row_id can either be exact, or start at 0 to get the earliest row in the
  ///              list.
  pub fn select_message(&self, row_id: i64) -> PersistenceResult<Option<(i64, Message)>> {
    assert!(self.version == CURRENT_VERSION, "schema version mismatch, schema_up() resolves this");

    let mut stmt = try_rethrow!(PersistenceError::SqliteError,
                                self.conn.prepare("SELECT _rowid_, message
                                                FROM messages
                                                WHERE _rowid_ >= $1
                                                LIMIT 1"));

    let message_opt: Option<Result<(i64, Message), SqliteError>> = try_rethrow!(PersistenceError::SqliteError,
                                                            stmt.query_and_then(&[&row_id],
                                                            |row| -> Result<(i64, Message), SqliteError> {
      let row_id: i64 = try!(row.get_checked(0));
      let message_bytes: Vec<u8> = try!(row.get_checked(1));
      let mut decoder = BinDecoder::new(&message_bytes);


      // todo add location to this...
      match Message::read(&mut decoder) {
        Ok(message) => Ok((row_id, message)),
        Err(decode_error) => Err(rusqlite::Error::FromSqlConversionFailure(Box::new(decode_error))),
      }
    })).next();

    //
    match message_opt {
      Some(Ok((row_id, message))) => Ok(Some((row_id, message))),
      Some(Err(err)) => Err(PersistenceError::SqliteError(error_loc!(), err)),
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
    let mut stmt = try_rethrow!(PersistenceError::SqliteError,
                            conn.prepare("SELECT name
                                            FROM sqlite_master
                                            WHERE type='table'
                                            AND name='tdns_schema'"));

    let tdns_schema_opt: Option<Result<String, _>> = try_rethrow!(PersistenceError::SqliteError,
                                                                  stmt.query_map(&[],
                                                                  |row| row.get(0)))
                                                    .next();

    let tdns_schema = match tdns_schema_opt {
      Some(Ok(string)) => string,
      Some(Err(err)) => return Err(PersistenceError::SqliteError(error_loc!(), err)),
      None => return Ok(-1),
    };

    assert_eq!(&tdns_schema, "tdns_schema");

    let version: i64 = try_rethrow!(PersistenceError::SqliteError,
                                    conn.query_row_safe("SELECT version
                                                          FROM tdns_schema",
                                                        &[],
                                                        |row| row.get(0)));

    Ok(version)
  }

  /// update the schema version
  fn update_schema_version(&self, new_version: i64) -> PersistenceResult<()> {
    // validate the versions of all the schemas...
    assert!(new_version <= CURRENT_VERSION);

    let count = try_rethrow!(PersistenceError::SqliteError,
                              self.conn.execute("UPDATE tdns_schema SET version = $1", &[&new_version]));

    //
    assert_eq!(count, 1);
    Ok(())
  }

  /// initilizes the schema for the Journal
  pub fn schema_up(&mut self) -> PersistenceResult<i64> {
    while self.version < CURRENT_VERSION {
      match self.version + 1 {
        0 => self.version = try!(self.init_up()),
        1 => self.version = try!(self.messages_up()),
        _ => panic!("incorrect version somewhere"),
      }

      try!(self.update_schema_version(self.version));
    }

    Ok(self.version)
  }

  /// initial schema, include the tdns_schema table for tracking the Journal version
  fn init_up(&self) -> PersistenceResult<i64> {
    let count = try_rethrow!(PersistenceError::SqliteError,
                              self.conn.execute("CREATE TABLE tdns_schema (
                              version          INTEGER NOT NULL
                            )", &[]));
    //
    assert_eq!(count, 0);

    let count = try_rethrow!(PersistenceError::SqliteError,
                              self.conn.execute("INSERT INTO tdns_schema (version)
                                            VALUES (0)", &[]));
    //
    assert_eq!(count, 1);

    Ok(0)
  }

  /// adds the messages table, this is the main and single table for the history of changes to an
  ///  authority.
  fn messages_up(&self) -> PersistenceResult<i64> {
    // we'll be using rowid for our primary key, basically: `rowid INTEGER PRIMARY KEY ASC`
    let count = try_rethrow!(PersistenceError::SqliteError,
                              self.conn.execute("CREATE TABLE messages (
                              client_id      INTEGER NOT NULL,
                              soa_serial      INTEGER NOT NULL,
                              timestamp       TEXT NOT NULL,
                              message         BLOB NOT NULL
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
  type Item = Message;

  fn next(&mut self) -> Option<Self::Item> {
    let next: PersistenceResult<Option<(i64, Message)>> = self.journal.select_message(self.current_row_id + 1);

    match next {
      Ok(Some((row_id, message))) => {
        self.current_row_id = row_id;
        Some(message)
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
fn create_test_journal() -> (Message, Journal) {
  use std::net::Ipv4Addr;
  use std::str::FromStr;

  use ::op::{Message, MessageType, OpCode, Query, UpdateMessage};
  use ::rr::{DNSClass, Name, RData, Record, RecordType};

  let zone_origin = Name::with_labels(vec!["example".to_string(), "com".to_string()]);
  let www = Name::with_labels(vec!["www".to_string(),"example".to_string(), "com".to_string()]);

  let mut message: Message = Message::new();
  message.id(10)
         .message_type(MessageType::Query)
         .op_code(OpCode::Update)
         .authoritative(false)
         .truncated(false)
         .recursion_desired(true)
         .recursion_available(false);
  //

  let mut zone: Query = Query::new();
  zone.name(zone_origin).query_class(DNSClass::IN).query_type(RecordType::SOA);

  // build the message
  message.add_zone(zone);

  let mut record = Record::new();
  record.name(www);
  record.rr_type(RecordType::A);
  record.rdata(RData::A(Ipv4Addr::from_str("127.0.0.1").unwrap()));

  message.add_update(record.clone());

  // test that this message can be inserted
  let conn = Connection::open_in_memory().expect("could not create in memory DB");
  let mut journal = Journal::new(conn).unwrap();
  journal.schema_up().unwrap();

  // insert the message
  journal.insert_message(0, &message).unwrap();

  // serialize the message to get a cononical message, then compare...
  let mut serial_message: Vec<u8> = Vec::with_capacity(512);
  {
    let mut encoder = BinEncoder::new(&mut serial_message);
    message.emit(&mut encoder).unwrap();
  }
  let mut decoder = BinDecoder::new(&serial_message);
  let mut message = Message::read(&mut decoder).unwrap();

  // insert another...
  message.id(11);
  journal.insert_message(0, &message).unwrap();

  (message, journal)
}

#[test]
fn test_insert_and_select_message() {
  let (mut message, journal) = create_test_journal();

  message.id(10);

  // select the message
  let (row_id, journal_message) = journal.select_message(0).expect("persistence error").expect("none");
  assert_eq!(journal_message, message);

  // insert another...
  message.id(11);
  let (row_id, journal_message) = journal.select_message(row_id + 1).expect("persistence error").expect("none");
  assert_eq!(journal_message, message);
  assert_eq!(message.get_id(), 11);

  // check that we get nothing for id over row_id
  let option_none = journal.select_message(row_id + 1).expect("persistence error");
  assert!(option_none.is_none());
}

#[test]
fn test_iterator() {
  let (mut message, journal) = create_test_journal();

  let mut iter = journal.iter();

  assert_eq!(message.id(10), &iter.next().unwrap());
  assert_eq!(message.id(11), &iter.next().unwrap());
  assert_eq!(None, iter.next());
}
