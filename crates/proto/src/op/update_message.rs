// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Update related operations for Messages

use std::fmt::Debug;

use crate::{
    op::{Edns, Message, MessageType, OpCode, Query},
    rr::{rdata::SOA, DNSClass, Name, RData, Record, RecordSet, RecordType},
};

/// To reduce errors in using the Message struct as an Update, this will do the call throughs
///   to properly do that.
///
/// Generally rather than constructing this by hand, see the update methods on `Client`
pub trait UpdateMessage: Debug {
    /// see `Header::id`
    fn id(&self) -> u16;

    /// Adds the zone section, i.e. name.example.com would be example.com
    fn add_zone(&mut self, query: Query);

    /// Add the pre-requisite records
    ///
    /// These must exist, or not, for the Update request to go through.
    fn add_pre_requisite(&mut self, record: Record);

    /// Add all the Records from the Iterator to the pre-requisites section
    fn add_pre_requisites<R, I>(&mut self, records: R)
    where
        R: IntoIterator<Item = Record, IntoIter = I>,
        I: Iterator<Item = Record>;

    /// Add the Record to be updated
    fn add_update(&mut self, record: Record);

    /// Add the Records from the Iterator to the updates section
    fn add_updates<R, I>(&mut self, records: R)
    where
        R: IntoIterator<Item = Record, IntoIter = I>,
        I: Iterator<Item = Record>;

    /// Add Records to the additional Section of the UpdateMessage
    fn add_additional(&mut self, record: Record);

    /// Returns the Zones to be updated, generally should only be one.
    fn zones(&self) -> &[Query];

    /// Returns the pre-requisites
    fn prerequisites(&self) -> &[Record];

    /// Returns the records to be updated
    fn updates(&self) -> &[Record];

    /// Returns the additional records
    fn additionals(&self) -> &[Record];

    /// This is used to authenticate update messages.
    ///
    /// see `Message::sig0()` for more information.
    fn sig0(&self) -> &[Record];
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
}

/// Sends a record to create on the server, this will fail if the record exists (atomicity
///  depends on the server)
///
/// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
///
/// ```text
///  2.4.3 - RRset Does Not Exist
///
///   No RRs with a specified NAME and TYPE (in the zone and class denoted
///   by the Zone Section) can exist.
///
///   For this prerequisite, a requestor adds to the section a single RR
///   whose NAME and TYPE are equal to that of the RRset whose nonexistence
///   is required.  The RDLENGTH of this record is zero (0), and RDATA
///   field is therefore empty.  CLASS must be specified as NONE in order
///   to distinguish this condition from a valid RR whose RDLENGTH is
///   naturally zero (0) (for example, the NULL RR).  TTL must be specified
///   as zero (0).
///
/// 2.5.1 - Add To An RRset
///
///    RRs are added to the Update Section whose NAME, TYPE, TTL, RDLENGTH
///    and RDATA are those being added, and CLASS is the same as the zone
///    class.  Any duplicate RRs will be silently ignored by the Primary
///    Zone Server.
/// ```
///
/// # Arguments
///
/// * `rrset` - the record(s) to create
/// * `zone_origin` - the zone name to update, i.e. SOA name
///
/// The update must go to a zone authority (i.e. the server used in the ClientConnection)
pub fn create(rrset: RecordSet, zone_origin: Name, use_edns: bool) -> Message {
    // TODO: assert non-empty rrset?
    assert!(zone_origin.zone_of(rrset.name()));

    // for updates, the query section is used for the zone
    let mut zone: Query = Query::new();
    zone.set_name(zone_origin)
        .set_query_class(rrset.dns_class())
        .set_query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message
        .set_id(rand::random())
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Update)
        .set_recursion_desired(false);
    message.add_zone(zone);

    let mut prerequisite = Record::update0(rrset.name().clone(), 0, rrset.record_type());
    prerequisite.set_dns_class(DNSClass::NONE);
    message.add_pre_requisite(prerequisite.into_record_of_rdata());
    message.add_updates(rrset);

    // Extended dns
    if use_edns {
        message
            .extensions_mut()
            .get_or_insert_with(Edns::new)
            .set_max_payload(MAX_PAYLOAD_LEN)
            .set_version(0);
    }

    message
}

/// Appends a record to an existing rrset, optionally require the rrset to exist (atomicity
///  depends on the server)
///
/// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
///
/// ```text
/// 2.4.1 - RRset Exists (Value Independent)
///
///   At least one RR with a specified NAME and TYPE (in the zone and class
///   specified in the Zone Section) must exist.
///
///   For this prerequisite, a requestor adds to the section a single RR
///   whose NAME and TYPE are equal to that of the zone RRset whose
///   existence is required.  RDLENGTH is zero and RDATA is therefore
///   empty.  CLASS must be specified as ANY to differentiate this
///   condition from that of an actual RR whose RDLENGTH is naturally zero
///   (0) (e.g., NULL).  TTL is specified as zero (0).
///
/// 2.5.1 - Add To An RRset
///
///    RRs are added to the Update Section whose NAME, TYPE, TTL, RDLENGTH
///    and RDATA are those being added, and CLASS is the same as the zone
///    class.  Any duplicate RRs will be silently ignored by the Primary
///    Zone Server.
/// ```
///
/// # Arguments
///
/// * `rrset` - the record(s) to append to an RRSet
/// * `zone_origin` - the zone name to update, i.e. SOA name
/// * `must_exist` - if true, the request will fail if the record does not exist
///
/// The update must go to a zone authority (i.e. the server used in the ClientConnection). If
/// the rrset does not exist and must_exist is false, then the RRSet will be created.
pub fn append(rrset: RecordSet, zone_origin: Name, must_exist: bool, use_edns: bool) -> Message {
    assert!(zone_origin.zone_of(rrset.name()));

    // for updates, the query section is used for the zone
    let mut zone: Query = Query::new();
    zone.set_name(zone_origin)
        .set_query_class(rrset.dns_class())
        .set_query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message
        .set_id(rand::random())
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Update)
        .set_recursion_desired(false);
    message.add_zone(zone);

    if must_exist {
        let mut prerequisite = Record::update0(rrset.name().clone(), 0, rrset.record_type());
        prerequisite.set_dns_class(DNSClass::ANY);
        message.add_pre_requisite(prerequisite.into_record_of_rdata());
    }

    message.add_updates(rrset);

    // Extended dns
    if use_edns {
        message
            .extensions_mut()
            .get_or_insert_with(Edns::new)
            .set_max_payload(MAX_PAYLOAD_LEN)
            .set_version(0);
    }

    message
}

/// Compares and if it matches, swaps it for the new value (atomicity depends on the server)
///
/// ```text
///  2.4.2 - RRset Exists (Value Dependent)
///
///   A set of RRs with a specified NAME and TYPE exists and has the same
///   members with the same RDATAs as the RRset specified here in this
///   section.  While RRset ordering is undefined and therefore not
///   significant to this comparison, the sets be identical in their
///   extent.
///
///   For this prerequisite, a requestor adds to the section an entire
///   RRset whose preexistence is required.  NAME and TYPE are that of the
///   RRset being denoted.  CLASS is that of the zone.  TTL must be
///   specified as zero (0) and is ignored when comparing RRsets for
///   identity.
///
///  2.5.4 - Delete An RR From An RRset
///
///   RRs to be deleted are added to the Update Section.  The NAME, TYPE,
///   RDLENGTH and RDATA must match the RR being deleted.  TTL must be
///   specified as zero (0) and will otherwise be ignored by the Primary
///   Zone Server.  CLASS must be specified as NONE to distinguish this from an
///   RR addition.  If no such RRs exist, then this Update RR will be
///   silently ignored by the Primary Zone Server.
///
///  2.5.1 - Add To An RRset
///
///   RRs are added to the Update Section whose NAME, TYPE, TTL, RDLENGTH
///   and RDATA are those being added, and CLASS is the same as the zone
///   class.  Any duplicate RRs will be silently ignored by the Primary
///   Zone Server.
/// ```
///
/// # Arguments
///
/// * `current` - the current rrset which must exist for the swap to complete
/// * `new` - the new rrset with which to replace the current rrset
/// * `zone_origin` - the zone name to update, i.e. SOA name
///
/// The update must go to a zone authority (i.e. the server used in the ClientConnection).
pub fn compare_and_swap(
    current: RecordSet,
    new: RecordSet,
    zone_origin: Name,
    use_edns: bool,
) -> Message {
    assert!(zone_origin.zone_of(current.name()));
    assert!(zone_origin.zone_of(new.name()));

    // for updates, the query section is used for the zone
    let mut zone: Query = Query::new();
    zone.set_name(zone_origin)
        .set_query_class(new.dns_class())
        .set_query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message
        .set_id(rand::random())
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Update)
        .set_recursion_desired(false);
    message.add_zone(zone);

    // make sure the record is what is expected
    let mut prerequisite = current.clone();
    prerequisite.set_ttl(0);
    message.add_pre_requisites(prerequisite);

    // add the delete for the old record
    let mut delete = current;
    // the class must be none for delete
    delete.set_dns_class(DNSClass::NONE);
    // the TTL should be 0
    delete.set_ttl(0);
    message.add_updates(delete);

    // insert the new record...
    message.add_updates(new);

    // Extended dns
    if use_edns {
        message
            .extensions_mut()
            .get_or_insert_with(Edns::new)
            .set_max_payload(MAX_PAYLOAD_LEN)
            .set_version(0);
    }

    message
}

/// Deletes a record (by rdata) from an rrset, optionally require the rrset to exist.
///
/// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
///
/// ```text
/// 2.4.1 - RRset Exists (Value Independent)
///
///   At least one RR with a specified NAME and TYPE (in the zone and class
///   specified in the Zone Section) must exist.
///
///   For this prerequisite, a requestor adds to the section a single RR
///   whose NAME and TYPE are equal to that of the zone RRset whose
///   existence is required.  RDLENGTH is zero and RDATA is therefore
///   empty.  CLASS must be specified as ANY to differentiate this
///   condition from that of an actual RR whose RDLENGTH is naturally zero
///   (0) (e.g., NULL).  TTL is specified as zero (0).
///
/// 2.5.4 - Delete An RR From An RRset
///
///   RRs to be deleted are added to the Update Section.  The NAME, TYPE,
///   RDLENGTH and RDATA must match the RR being deleted.  TTL must be
///   specified as zero (0) and will otherwise be ignored by the Primary
///   Zone Server.  CLASS must be specified as NONE to distinguish this from an
///   RR addition.  If no such RRs exist, then this Update RR will be
///   silently ignored by the Primary Zone Server.
/// ```
///
/// # Arguments
///
/// * `rrset` - the record(s) to delete from a RRSet, the name, type and rdata must match the
///              record to delete
/// * `zone_origin` - the zone name to update, i.e. SOA name
/// * `signer` - the signer, with private key, to use to sign the request
///
/// The update must go to a zone authority (i.e. the server used in the ClientConnection). If
/// the rrset does not exist and must_exist is false, then the RRSet will be deleted.
pub fn delete_by_rdata(mut rrset: RecordSet, zone_origin: Name, use_edns: bool) -> Message {
    assert!(zone_origin.zone_of(rrset.name()));

    // for updates, the query section is used for the zone
    let mut zone: Query = Query::new();
    zone.set_name(zone_origin)
        .set_query_class(rrset.dns_class())
        .set_query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message
        .set_id(rand::random())
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Update)
        .set_recursion_desired(false);
    message.add_zone(zone);

    // the class must be none for delete
    rrset.set_dns_class(DNSClass::NONE);
    // the TTL should be 0
    rrset.set_ttl(0);
    message.add_updates(rrset);

    // Extended dns
    if use_edns {
        message
            .extensions_mut()
            .get_or_insert(Edns::new())
            .set_max_payload(MAX_PAYLOAD_LEN)
            .set_version(0);
    }

    message
}

/// Deletes an entire rrset, optionally require the rrset to exist.
///
/// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
///
/// ```text
/// 2.4.1 - RRset Exists (Value Independent)
///
///   At least one RR with a specified NAME and TYPE (in the zone and class
///   specified in the Zone Section) must exist.
///
///   For this prerequisite, a requestor adds to the section a single RR
///   whose NAME and TYPE are equal to that of the zone RRset whose
///   existence is required.  RDLENGTH is zero and RDATA is therefore
///   empty.  CLASS must be specified as ANY to differentiate this
///   condition from that of an actual RR whose RDLENGTH is naturally zero
///   (0) (e.g., NULL).  TTL is specified as zero (0).
///
/// 2.5.2 - Delete An RRset
///
///   One RR is added to the Update Section whose NAME and TYPE are those
///   of the RRset to be deleted.  TTL must be specified as zero (0) and is
///   otherwise not used by the Primary Zone Server.  CLASS must be specified as
///   ANY.  RDLENGTH must be zero (0) and RDATA must therefore be empty.
///   If no such RRset exists, then this Update RR will be silently ignored
///   by the Primary Zone Server.
/// ```
///
/// # Arguments
///
/// * `record` - The name, class and record_type will be used to match and delete the RecordSet
/// * `zone_origin` - the zone name to update, i.e. SOA name
///
/// The update must go to a zone authority (i.e. the server used in the ClientConnection). If
/// the rrset does not exist and must_exist is false, then the RRSet will be deleted.
pub fn delete_rrset(mut record: Record, zone_origin: Name, use_edns: bool) -> Message {
    assert!(zone_origin.zone_of(record.name()));

    // for updates, the query section is used for the zone
    let mut zone: Query = Query::new();
    zone.set_name(zone_origin)
        .set_query_class(record.dns_class())
        .set_query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message
        .set_id(rand::random())
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Update)
        .set_recursion_desired(false);
    message.add_zone(zone);

    // the class must be none for an rrset delete
    record.set_dns_class(DNSClass::ANY);
    // the TTL should be 0
    record.set_ttl(0);
    // the rdata must be null to delete all rrsets
    record.set_data(RData::Update0(record.record_type()));
    message.add_update(record);

    // Extended dns
    if use_edns {
        message
            .extensions_mut()
            .get_or_insert_with(Edns::new)
            .set_max_payload(MAX_PAYLOAD_LEN)
            .set_version(0);
    }

    message
}

/// Deletes all records at the specified name
///
/// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
///
/// ```text
/// 2.5.3 - Delete All RRsets From A Name
///
///   One RR is added to the Update Section whose NAME is that of the name
///   to be cleansed of RRsets.  TYPE must be specified as ANY.  TTL must
///   be specified as zero (0) and is otherwise not used by the Primary
///   Zone Server.  CLASS must be specified as ANY.  RDLENGTH must be zero (0)
///   and RDATA must therefore be empty.  If no such RRsets exist, then
///   this Update RR will be silently ignored by the Primary Zone Server.
/// ```
///
/// # Arguments
///
/// * `name_of_records` - the name of all the record sets to delete
/// * `zone_origin` - the zone name to update, i.e. SOA name
/// * `dns_class` - the class of the SOA
///
/// The update must go to a zone authority (i.e. the server used in the ClientConnection). This
/// operation attempts to delete all resource record sets the specified name regardless of
/// the record type.
pub fn delete_all(
    name_of_records: Name,
    zone_origin: Name,
    dns_class: DNSClass,
    use_edns: bool,
) -> Message {
    assert!(zone_origin.zone_of(&name_of_records));

    // for updates, the query section is used for the zone
    let mut zone: Query = Query::new();
    zone.set_name(zone_origin)
        .set_query_class(dns_class)
        .set_query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message
        .set_id(rand::random())
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Update)
        .set_recursion_desired(false);
    message.add_zone(zone);

    // the TTL should be 0
    // the rdata must be null to delete all rrsets
    // the record type must be any
    let mut record = Record::update0(name_of_records, 0, RecordType::ANY);

    // the class must be none for an rrset delete
    record.set_dns_class(DNSClass::ANY);

    message.add_update(record.into_record_of_rdata());

    // Extended dns
    if use_edns {
        message
            .extensions_mut()
            .get_or_insert_with(Edns::new)
            .set_max_payload(MAX_PAYLOAD_LEN)
            .set_version(0);
    }

    message
}

// not an update per-se, but it fits nicely with other functions here
/// Download all records from a zone, or all records modified since given SOA was observed.
/// The request will either be a AXFR Query (ask for full zone transfer) if a SOA was not
/// provided, or a IXFR Query (incremental zone transfer) if a SOA was provided.
///
/// # Arguments
/// * `zone_origin` - the zone name to update, i.e. SOA name
/// * `last_soa` - the last SOA known, if any. If provided, name must match `zone_origin`
pub fn zone_transfer(zone_origin: Name, last_soa: Option<SOA>) -> Message {
    if let Some(ref soa) = last_soa {
        assert_eq!(zone_origin, *soa.mname());
    }

    let mut zone: Query = Query::new();
    zone.set_name(zone_origin).set_query_class(DNSClass::IN);
    if last_soa.is_some() {
        zone.set_query_type(RecordType::IXFR);
    } else {
        zone.set_query_type(RecordType::AXFR);
    }

    // build the message
    let mut message: Message = Message::new();
    message
        .set_id(rand::random())
        .set_message_type(MessageType::Query)
        .set_recursion_desired(false);
    message.add_zone(zone);

    if let Some(soa) = last_soa {
        // for IXFR, old SOA is put as authority to indicate last known version
        let record = Record::from_rdata(soa.mname().clone(), 0, RData::SOA(soa));
        message.add_name_server(record);
    }

    // Extended dns
    {
        message
            .extensions_mut()
            .get_or_insert_with(Edns::new)
            .set_max_payload(MAX_PAYLOAD_LEN)
            .set_version(0);
    }

    message
}

// TODO: this should be configurable
// > An EDNS buffer size of 1232 bytes will avoid fragmentation on nearly all current networks.
// https://dnsflagday.net/2020/
/// Maximum payload length for EDNS update messages
pub const MAX_PAYLOAD_LEN: u16 = 1232;
