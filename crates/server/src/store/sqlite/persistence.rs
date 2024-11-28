// Copyright 2015-2016 Benjamin Fry <benjaminfry -@- me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! All zone persistence related types

use std::iter::Iterator;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::types::ToSql;
use rusqlite::{self, Connection};
use time;
use tracing::error;

use crate::error::{PersistenceError, PersistenceErrorKind};
use crate::proto::rr::Record;
use crate::proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};

/// The current Journal version of the application
pub const CURRENT_VERSION: i64 = 1;

/// The Journal is the audit log of all changes to a zone after initial creation.
pub struct Journal {
    conn: Mutex<Connection>,
    version: i64,
}

impl Journal {
    /// Constructs a new Journal, attaching to the specified Sqlite Connection
    pub fn new(conn: Connection) -> Result<Self, PersistenceError> {
        let version = Self::select_schema_version(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            version,
        })
    }

    /// Constructs a new Journal opening a Sqlite connection to the file at the specified path
    pub fn from_file(journal_file: &Path) -> Result<Self, PersistenceError> {
        let result = Self::new(Connection::open(journal_file)?);
        let mut journal = result?;
        journal.schema_up()?;
        Ok(journal)
    }

    /// Returns a reference to the Sqlite Connection
    pub fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().expect("conn poisoned")
    }

    /// Returns the current schema version of the journal
    pub fn schema_version(&self) -> i64 {
        self.version
    }

    /// this returns an iterator from the beginning of time, to be used to recreate an authority
    pub fn iter(&self) -> JournalIter<'_> {
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
    pub fn insert_record(&self, soa_serial: u32, record: &Record) -> Result<(), PersistenceError> {
        assert!(
            self.version == CURRENT_VERSION,
            "schema version mismatch, schema_up() resolves this"
        );

        let mut serial_record: Vec<u8> = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut serial_record);
            record.emit(&mut encoder)?;
        }

        let timestamp = time::OffsetDateTime::now_utc();
        let client_id: i64 = 0; // TODO: we need better id information about the client, like pub_key
        let soa_serial: i64 = i64::from(soa_serial);

        let count = self.conn.lock().expect("conn poisoned").execute(
            "INSERT
                                          \
                                            INTO records (client_id, soa_serial, timestamp, \
                                            record)
                                          \
                                            VALUES ($1, $2, $3, $4)",
            [
                &client_id as &dyn ToSql,
                &soa_serial,
                &timestamp,
                &serial_record,
            ],
        )?;
        //
        if count != 1 {
            return Err(PersistenceErrorKind::WrongInsertCount {
                got: count,
                expect: 1,
            }
            .into());
        };

        Ok(())
    }

    /// Inserts a set of records into the Journal, a convenience method for insert_record
    pub fn insert_records(
        &self,
        soa_serial: u32,
        records: &[Record],
    ) -> Result<(), PersistenceError> {
        // TODO: NEED TRANSACTION HERE
        for record in records {
            self.insert_record(soa_serial, record)?;
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
    pub fn select_record(&self, row_id: i64) -> Result<Option<(i64, Record)>, PersistenceError> {
        assert!(
            self.version == CURRENT_VERSION,
            "schema version mismatch, schema_up() resolves this"
        );

        let conn = self.conn.lock().expect("conn poisoned");
        let mut stmt = conn.prepare(
            "SELECT _rowid_, record
                                            \
                                               FROM records
                                            \
                                               WHERE _rowid_ >= $1
                                            \
                                               LIMIT 1",
        )?;

        let record_opt: Option<Result<(i64, Record), rusqlite::Error>> = stmt
            .query_and_then([&row_id], |row| -> Result<(i64, Record), rusqlite::Error> {
                let row_id: i64 = row.get(0)?;
                let record_bytes: Vec<u8> = row.get(1)?;
                let mut decoder = BinDecoder::new(&record_bytes);

                // todo add location to this...
                match Record::read(&mut decoder) {
                    Ok(record) => Ok((row_id, record)),
                    Err(decode_error) => Err(rusqlite::Error::InvalidParameterName(format!(
                        "could not decode: {decode_error}"
                    ))),
                }
            })?
            .next();

        //
        match record_opt {
            Some(Ok((row_id, record))) => Ok(Some((row_id, record))),
            Some(Err(err)) => Err(err.into()),
            None => Ok(None),
        }
    }

    /// selects the current schema version of the journal DB, returns -1 if there is no schema
    ///
    ///
    /// # Arguments
    ///
    /// * `conn` - db connection to use
    pub fn select_schema_version(conn: &Connection) -> Result<i64, PersistenceError> {
        // first see if our schema is there
        let mut stmt = conn.prepare(
            "SELECT name
                                        \
                                          FROM sqlite_master
                                        \
                                          WHERE type='table'
                                        \
                                          AND name='tdns_schema'",
        )?;

        let tdns_schema_opt: Option<Result<String, _>> =
            stmt.query_map([], |row| row.get(0))?.next();

        let tdns_schema = match tdns_schema_opt {
            Some(Ok(string)) => string,
            Some(Err(err)) => return Err(err.into()),
            None => return Ok(-1),
        };

        assert_eq!(&tdns_schema, "tdns_schema");

        let version: i64 = conn.query_row(
            "SELECT version
                                            \
                                                FROM tdns_schema",
            [],
            |row| row.get(0),
        )?;

        Ok(version)
    }

    /// update the schema version
    fn update_schema_version(&self, new_version: i64) -> Result<(), PersistenceError> {
        // validate the versions of all the schemas...
        assert!(new_version <= CURRENT_VERSION);

        let count = self
            .conn
            .lock()
            .expect("conn poisoned")
            .execute("UPDATE tdns_schema SET version = $1", [&new_version])?;

        //
        assert_eq!(count, 1);
        Ok(())
    }

    /// initializes the schema for the Journal
    pub fn schema_up(&mut self) -> Result<i64, PersistenceError> {
        while self.version < CURRENT_VERSION {
            match self.version + 1 {
                0 => self.version = self.init_up()?,
                1 => self.version = self.records_up()?,
                _ => panic!("incorrect version somewhere"), // valid panic, non-recoverable state
            }

            self.update_schema_version(self.version)?;
        }

        Ok(self.version)
    }

    /// initial schema, include the tdns_schema table for tracking the Journal version
    fn init_up(&self) -> Result<i64, PersistenceError> {
        let count = self.conn.lock().expect("conn poisoned").execute(
            "CREATE TABLE tdns_schema (
                                          \
                                            version INTEGER NOT NULL
                                        \
                                            )",
            [],
        )?;
        //
        assert_eq!(count, 0);

        let count = self
            .conn
            .lock()
            .expect("conn poisoned")
            .execute("INSERT INTO tdns_schema (version) VALUES (0)", [])?;
        //
        assert_eq!(count, 1);

        Ok(0)
    }

    /// adds the records table, this is the main and single table for the history of changes to an
    ///  authority. Each record is expected to be in the format of an update record
    fn records_up(&self) -> Result<i64, PersistenceError> {
        // we'll be using rowid for our primary key, basically: `rowid INTEGER PRIMARY KEY ASC`
        let count = self.conn.lock().expect("conn poisoned").execute(
            "CREATE TABLE records (
                                          \
                                            client_id      INTEGER NOT NULL,
                                          \
                                            soa_serial     INTEGER NOT NULL,
                                          \
                                            timestamp      TEXT NOT NULL,
                                          \
                                            record         BLOB NOT NULL
                                        \
                                            )",
            [],
        )?;
        //
        assert_eq!(count, 1);

        Ok(1)
    }
}

/// Returns an iterator over all items in a Journal
///
/// Useful for replaying an entire journal into memory to reconstruct a zone from disk
pub struct JournalIter<'j> {
    current_row_id: i64,
    journal: &'j Journal,
}

impl<'j> JournalIter<'j> {
    fn new(journal: &'j Journal) -> Self {
        JournalIter {
            current_row_id: 0,
            journal,
        }
    }
}

impl Iterator for JournalIter<'_> {
    type Item = Record;

    fn next(&mut self) -> Option<Self::Item> {
        match self.journal.select_record(self.current_row_id + 1) {
            Ok(Some((row_id, record))) => {
                self.current_row_id = row_id;
                Some(record)
            }
            Ok(None) => None,
            Err(err) => {
                error!("persistence error while iterating over journal: {}", err);
                None
            }
        }
    }
}
