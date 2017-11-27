// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt::Debug;

use trust_dns_proto::error::ProtoResult;

use rr::Record;
use super::{Message, MessageFinalizer, Query};

/// To reduce errors in using the Message struct as an Update, this will do the call throughs
///   to properly do that.
///
/// Generally rather than constructin this by hand, see the update methods on `Client`
pub trait UpdateMessage: Debug {
    /// see `Header::id`
    fn id(&self) -> u16;

    /// Adds the zone section, i.e. name.example.com would be example.com
    fn add_zone(&mut self, query: Query);

    /// Add the pre-requisite records
    ///
    /// These must exist, or not, for the Update request to go through.
    fn add_pre_requisite(&mut self, record: Record);

    /// Add all pre-requisites to the UpdateMessage
    #[deprecated(note = "will be removed post 0.9.x")]
    fn add_all_pre_requisites(&mut self, vector: &[&Record]);

    /// Add all the Records from the Iterator to the pre-reqisites section
    fn add_pre_requisites<R, I>(&mut self, records: R)
    where
        R: IntoIterator<Item = Record, IntoIter = I>,
        I: Iterator<Item = Record>;

    /// Add the Record to be updated
    fn add_update(&mut self, record: Record);

    /// Add the set of Records to be updated
    #[deprecated(note = "will be removed post 0.9.x")]
    fn add_all_updates(&mut self, vector: &[&Record]);

    /// Add the Records from the Iterator to the updates section
    fn add_updates<R, I>(&mut self, records: R)
    where
        R: IntoIterator<Item = Record, IntoIter = I>,
        I: Iterator<Item = Record>;

    /// Add Records to the additional Section of hte UpdateMessage
    fn add_additional(&mut self, record: Record);

    /// Returns the Zones to be updated, generally should only be one.
    fn zones(&self) -> &[Query];

    /// Returns the pre-requisites
    fn prerequisites(&self) -> &[Record];

    /// Returns the records to be updated
    fn updates(&self) -> &[Record];

    /// Returns the additonal records
    fn additionals(&self) -> &[Record];

    /// This is used to authenticate update messages.
    ///
    /// see `Message::sig0()` for more information.
    fn sig0(&self) -> &[Record];

    /// Finalize the message prior to sending.
    ///
    /// Subsequent to calling this, the Message should not change.
    fn finalize<MF: MessageFinalizer>(
        &mut self,
        finalizer: &MF,
        inception_time: u32,
    ) -> ProtoResult<()>;
}

/// to reduce errors in using the Message struct as an Update, this will do the call throughs
///   to properly do that.
impl UpdateMessage for Message {
    fn id(&self) -> u16 {
        self.id()
    }
    fn add_zone(&mut self, query: Query) {
        self.add_query(query);
    }
    fn add_pre_requisite(&mut self, record: Record) {
        self.add_answer(record);
    }
    fn add_all_pre_requisites(&mut self, vector: &[&Record]) {
        self.add_answers(vector.into_iter().map(|r| (*r).clone()));
    }
    fn add_pre_requisites<R, I>(&mut self, records: R)
    where
        R: IntoIterator<Item = Record, IntoIter = I>,
        I: Iterator<Item = Record>,
    {
        self.add_answers(records);
    }
    fn add_update(&mut self, record: Record) {
        self.add_name_server(record);
    }
    fn add_all_updates(&mut self, vector: &[&Record]) {
        self.add_name_servers(vector.into_iter().map(|r| (*r).clone()));
    }
    fn add_updates<R, I>(&mut self, records: R)
    where
        R: IntoIterator<Item = Record, IntoIter = I>,
        I: Iterator<Item = Record>,
    {
        self.add_name_servers(records);
    }
    fn add_additional(&mut self, record: Record) {
        self.add_additional(record);
    }

    fn zones(&self) -> &[Query] {
        self.queries()
    }
    fn prerequisites(&self) -> &[Record] {
        self.answers()
    }
    fn updates(&self) -> &[Record] {
        self.name_servers()
    }
    fn additionals(&self) -> &[Record] {
        self.additionals()
    }

    fn sig0(&self) -> &[Record] {
        self.sig0()
    }

    fn finalize<MF: MessageFinalizer>(
        &mut self,
        finalizer: &MF,
        inception_time: u32,
    ) -> ProtoResult<()> {
        self.finalize(finalizer, inception_time)
    }
}
