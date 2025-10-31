// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Lookup result from a resolution of ipv4 and ipv6 records with a Resolver.

use std::{
    cmp::min,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    cache::MAX_TTL,
    proto::{
        op::{Message, OpCode, Query},
        rr::{RData, Record},
    },
};

/// Result of a DNS query when querying for any record type supported by the Hickory DNS Proto library.
///
/// For IP resolution see LookupIp, as it has more features for A and AAAA lookups.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lookup {
    query: Query,
    message: Message,
    valid_until: Instant,
}

impl Lookup {
    /// Create a new Lookup from a complete DNS Message.
    pub fn new(query: Query, message: Message, valid_until: Instant) -> Self {
        Self {
            query,
            message,
            valid_until,
        }
    }

    /// Return new instance with given rdata and the maximum TTL.
    pub fn from_rdata(query: Query, rdata: RData) -> Self {
        let record = Record::from_rdata(query.name().clone(), MAX_TTL, rdata);
        Self::new_with_max_ttl(query, Arc::from([record]))
    }

    /// Return new instance with given records and the maximum TTL.
    pub fn new_with_max_ttl(query: Query, records: Arc<[Record]>) -> Self {
        let valid_until = Instant::now() + Duration::from_secs(u64::from(MAX_TTL));
        Self::new_with_deadline(query, records, valid_until)
    }

    /// Return a new instance with the given records and deadline.
    pub fn new_with_deadline(query: Query, records: Arc<[Record]>, valid_until: Instant) -> Self {
        // Build a response Message with the records in the answers section
        let mut message = Message::response(0, OpCode::Query);
        message.add_query(query.clone());
        message.add_answers(records.iter().cloned());

        Self {
            query,
            message,
            valid_until,
        }
    }

    /// Returns a reference to the `Query` that was used to produce this result.
    pub fn query(&self) -> &Query {
        &self.query
    }

    /// Returns a reference to the underlying DNS Message.
    pub fn message(&self) -> &Message {
        &self.message
    }

    /// Returns a reference to the answer records from the message.
    pub fn answers(&self) -> &[Record] {
        self.message.answers()
    }

    /// Returns the `Instant` at which this `Lookup` is no longer valid.
    pub fn valid_until(&self) -> Instant {
        self.valid_until
    }

    /// Combine two lookup results, preserving section structure
    ///
    /// Appends records from each section of `other` to the corresponding section of `self`.
    pub(crate) fn append(&self, other: Self) -> Self {
        // Clone self to get a mutable copy
        let mut result = self.clone();

        // Append each section separately to preserve structure
        result
            .message
            .add_answers(other.message.answers().iter().cloned());
        for authority in other.message.authorities() {
            result.message.add_authority(authority.clone());
        }
        result
            .message
            .add_additionals(other.message.additionals().iter().cloned());

        // Choose the sooner deadline of the two lookups
        result.valid_until = min(self.valid_until(), other.valid_until());

        result
    }

    /// Add new records to this lookup, without creating a new Lookup
    ///
    /// Records are added to the ANSWERS section while preserving existing section structure
    pub fn extend_answers(&mut self, other: Vec<Record>) {
        // Add new records to the answers section, preserving existing sections
        self.message.add_answers(other);
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::proto::op::Query;
    use crate::proto::rr::rdata::A;
    use crate::proto::rr::{Name, RData, Record};

    use super::*;

    #[test]
    #[cfg(feature = "__dnssec")]
    fn test_dnssec_lookup() {
        use hickory_proto::dnssec::Proof;

        let mut a1 = Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            80,
            RData::A(A::new(127, 0, 0, 1)),
        );
        a1.set_proof(Proof::Secure);

        let mut a2 = Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            80,
            RData::A(A::new(127, 0, 0, 2)),
        );
        a2.set_proof(Proof::Insecure);

        // Build a response Message with the records
        let mut message = Message::response(0, OpCode::Query);
        message.add_query(Query::default());
        message.add_answers([a1.clone(), a2.clone()]);

        let lookup = Lookup {
            query: Query::default(),
            message,
            valid_until: Instant::now(),
        };

        let mut iter = lookup.message().dnssec_answers();

        assert_eq!(
            *iter.next().unwrap().require(Proof::Secure).unwrap(),
            *a1.data()
        );
        assert_eq!(
            *iter.next().unwrap().require(Proof::Insecure).unwrap(),
            *a2.data()
        );
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_extend_answers_preserves_sections() {
        use crate::proto::rr::rdata::NS;

        // Create a message with records in different sections
        let mut message = Message::response(0, OpCode::Query);
        let query = Query::query(
            Name::from_str("www.example.com.").unwrap(),
            crate::proto::rr::RecordType::A,
        );
        message.add_query(query.clone());

        // Add answer
        message.add_answers(vec![Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            80,
            RData::A(A::new(127, 0, 0, 1)),
        )]);

        // Add authority
        message.add_authority(Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            80,
            RData::NS(NS(Name::from_str("ns1.example.com.").unwrap())),
        ));

        // Add additional
        message.add_additionals(vec![Record::from_rdata(
            Name::from_str("ns1.example.com.").unwrap(),
            80,
            RData::A(A::new(192, 0, 2, 1)),
        )]);

        let mut lookup = Lookup {
            query,
            message,
            valid_until: Instant::now(),
        };

        // Extend with new answer record
        let new_record = Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            80,
            RData::A(A::new(127, 0, 0, 2)),
        );
        lookup.extend_answers(vec![new_record.clone()]);

        // Verify that lookup.message was updated (not just a temporary reference)
        assert_eq!(lookup.answers().len(), 2);
        assert_eq!(lookup.answers()[1], new_record);

        // Verify sections were preserved
        assert_eq!(lookup.message.authorities().len(), 1);
        assert_eq!(lookup.message.additionals().len(), 1);

        // Verify the authority and additional records are intact
        if let RData::NS(ns) = lookup.message.authorities()[0].data() {
            assert_eq!(ns.0, Name::from_str("ns1.example.com.").unwrap());
        } else {
            panic!("Authority record should be NS");
        }

        if let RData::A(a) = lookup.message.additionals()[0].data() {
            assert_eq!(*a, A::new(192, 0, 2, 1));
        } else {
            panic!("Additional record should be A");
        }
    }

    #[test]
    fn test_append_preserves_sections() {
        use crate::proto::rr::rdata::NS;

        // Create first lookup with records in all sections
        let mut message1 = Message::response(0, OpCode::Query);
        let query = Query::query(
            Name::from_str("www.example.com.").unwrap(),
            crate::proto::rr::RecordType::A,
        );
        message1.add_query(query.clone());
        message1.add_answers(vec![Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            80,
            RData::A(A::new(127, 0, 0, 1)),
        )]);
        message1.add_authority(Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            80,
            RData::NS(NS(Name::from_str("ns1.example.com.").unwrap())),
        ));
        message1.add_additionals(vec![Record::from_rdata(
            Name::from_str("ns1.example.com.").unwrap(),
            80,
            RData::A(A::new(192, 0, 2, 1)),
        )]);

        let lookup1 = Lookup {
            query: query.clone(),
            message: message1,
            valid_until: Instant::now(),
        };

        // Create second lookup with different records in all sections
        let mut message2 = Message::response(0, OpCode::Query);
        message2.add_query(query.clone());
        message2.add_answers(vec![Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            80,
            RData::A(A::new(127, 0, 0, 2)),
        )]);
        message2.add_authority(Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            80,
            RData::NS(NS(Name::from_str("ns2.example.com.").unwrap())),
        ));
        message2.add_additionals(vec![Record::from_rdata(
            Name::from_str("ns2.example.com.").unwrap(),
            80,
            RData::A(A::new(192, 0, 2, 2)),
        )]);

        let lookup2 = Lookup {
            query,
            message: message2,
            valid_until: Instant::now(),
        };

        // Append lookup2 to lookup1
        let combined = lookup1.append(lookup2);

        // Verify that sections were preserved and combined
        assert_eq!(combined.answers().len(), 2);
        assert_eq!(combined.message.authorities().len(), 2);
        assert_eq!(combined.message.additionals().len(), 2);

        // Verify answer records
        if let RData::A(a) = combined.answers()[0].data() {
            assert_eq!(*a, A::new(127, 0, 0, 1));
        } else {
            panic!("First answer should be A");
        }
        if let RData::A(a) = combined.answers()[1].data() {
            assert_eq!(*a, A::new(127, 0, 0, 2));
        } else {
            panic!("Second answer should be A");
        }

        // Verify authority records
        if let RData::NS(ns) = combined.message.authorities()[0].data() {
            assert_eq!(ns.0, Name::from_str("ns1.example.com.").unwrap());
        } else {
            panic!("First authority should be NS");
        }
        if let RData::NS(ns) = combined.message.authorities()[1].data() {
            assert_eq!(ns.0, Name::from_str("ns2.example.com.").unwrap());
        } else {
            panic!("Second authority should be NS");
        }

        // Verify additional records
        if let RData::A(a) = combined.message.additionals()[0].data() {
            assert_eq!(*a, A::new(192, 0, 2, 1));
        } else {
            panic!("First additional should be A");
        }
        if let RData::A(a) = combined.message.additionals()[1].data() {
            assert_eq!(*a, A::new(192, 0, 2, 2));
        } else {
            panic!("Second additional should be A");
        }
    }
}
