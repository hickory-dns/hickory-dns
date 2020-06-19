// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! All authority related types

use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use futures::future::Future;

use trust_dns_client::op::LowerQuery;
use trust_dns_client::op::ResponseCode;
use trust_dns_client::proto::rr::dnssec::rdata::key::KEY;
use trust_dns_client::rr::dnssec::{DnsSecResult, Signer, SupportedAlgorithms};
use trust_dns_client::rr::{
    DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType, RrKey,
};

#[cfg(feature = "dnssec")]
use crate::authority::UpdateRequest;
use crate::authority::{Authority, LookupError, MessageRequest, UpdateResult, ZoneType};
use crate::error::{PersistenceErrorKind, PersistenceResult};
use crate::store::in_memory::InMemoryAuthority;
use crate::store::sqlite::{Journal, SqliteConfig};

/// SqliteAuthority is responsible for storing the resource records for a particular zone.
///
/// Authorities default to DNSClass IN. The ZoneType specifies if this should be treated as the
/// start of authority for the zone, is a Secondary, or a cached zone.
pub struct SqliteAuthority {
    in_memory: InMemoryAuthority,
    journal: Option<Journal>,
    allow_update: bool,
    is_dnssec_enabled: bool,
}

impl SqliteAuthority {
    /// Creates a new Authority.
    ///
    /// # Arguments
    ///
    /// * `in_memory` - InMemoryAuthority for all records.
    /// * `allow_update` - If true, then this zone accepts dynamic updates.
    /// * `is_dnssec_enabled` - If true, then the zone will sign the zone with all registered keys,
    ///                         (see `add_zone_signing_key()`)
    ///
    /// # Return value
    ///
    /// The new `Authority`.
    pub fn new(in_memory: InMemoryAuthority, allow_update: bool, is_dnssec_enabled: bool) -> Self {
        Self {
            in_memory,
            journal: None,
            allow_update,
            is_dnssec_enabled,
        }
    }

    /// load the authority from the configuration
    pub fn try_from_config(
        origin: Name,
        zone_type: ZoneType,
        allow_axfr: bool,
        enable_dnssec: bool,
        root_dir: Option<&Path>,
        config: &SqliteConfig,
    ) -> Result<Self, String> {
        use crate::store::file::{FileAuthority, FileConfig};

        let zone_name: Name = origin;

        let root_zone_dir = root_dir.map(PathBuf::from).unwrap_or_else(PathBuf::new);

        // to be compatible with previous versions, the extension might be zone, not jrnl
        let journal_path: PathBuf = root_zone_dir.join(&config.journal_file_path);
        let zone_path: PathBuf = root_zone_dir.join(&config.zone_file_path);

        // load the zone
        if journal_path.exists() {
            info!("recovering zone from journal: {:?}", journal_path);
            let journal = Journal::from_file(&journal_path)
                .map_err(|e| format!("error opening journal: {:?}: {}", journal_path, e))?;

            let in_memory = InMemoryAuthority::empty(zone_name.clone(), zone_type, allow_axfr);
            let mut authority = SqliteAuthority::new(in_memory, config.allow_update, enable_dnssec);
            authority
                .recover_with_journal(&journal)
                .map_err(|e| format!("error recovering from journal: {}", e))?;

            authority.set_journal(journal);
            info!("recovered zone: {}", zone_name);

            Ok(authority)
        } else if zone_path.exists() {
            // TODO: deprecate this portion of loading, instantiate the journal through a separate tool
            info!("loading zone file: {:?}", zone_path);

            let file_config = FileConfig {
                zone_file_path: config.zone_file_path.clone(),
            };

            let in_memory = FileAuthority::try_from_config(
                zone_name.clone(),
                zone_type,
                allow_axfr,
                root_dir,
                &file_config,
            )?
            .unwrap();

            let mut authority = SqliteAuthority::new(in_memory, config.allow_update, enable_dnssec);

            // if dynamic update is enabled, enable the journal
            info!("creating new journal: {:?}", journal_path);
            let journal = Journal::from_file(&journal_path)
                .map_err(|e| format!("error creating journal {:?}: {}", journal_path, e))?;

            authority.set_journal(journal);

            // preserve to the new journal, i.e. we just loaded the zone from disk, start the journal
            authority
                .persist_to_journal()
                .map_err(|e| format!("error persisting to journal {:?}: {}", journal_path, e))?;

            info!("zone file loaded: {}", zone_name);
            Ok(authority)
        } else {
            Err(format!(
                "no zone file or journal defined at: {:?}",
                zone_path
            ))
        }
    }

    /// Recovers the zone from a Journal, returns an error on failure to recover the zone.
    ///
    /// # Arguments
    ///
    /// * `journal` - the journal from which to load the persisted zone.
    pub fn recover_with_journal(&mut self, journal: &Journal) -> PersistenceResult<()> {
        assert!(
            self.in_memory.records().is_empty(),
            "records should be empty during a recovery"
        );

        info!("recovering from journal");
        for record in journal.iter() {
            // AXFR is special, it is used to mark the dump of a full zone.
            //  when recovering, if an AXFR is encountered, we should remove all the records in the
            //  authority.
            if record.rr_type() == RecordType::AXFR {
                self.in_memory.clear();
            } else if let Err(error) = self.update_records(&[record], false) {
                return Err(PersistenceErrorKind::Recovery(error.to_str()).into());
            }
        }

        Ok(())
    }

    /// Persist the state of the current zone to the journal, does nothing if there is no associated
    ///  Journal.
    ///
    /// Returns an error if there was an issue writing to the persistence layer.
    pub fn persist_to_journal(&self) -> PersistenceResult<()> {
        if let Some(journal) = self.journal.as_ref() {
            let serial = self.serial();

            info!("persisting zone to journal at SOA.serial: {}", serial);

            // TODO: THIS NEEDS TO BE IN A TRANSACTION!!!
            journal.insert_record(serial, Record::new().set_rr_type(RecordType::AXFR))?;

            for rr_set in self.in_memory.records().values() {
                // TODO: should we preserve rr_sets or not?
                for record in rr_set.records_without_rrsigs() {
                    journal.insert_record(serial, record)?;
                }
            }

            // TODO: COMMIT THE TRANSACTION!!!
        }

        Ok(())
    }

    /// Associate a backing Journal with this Authority for Updatable zones
    pub fn set_journal(&mut self, journal: Journal) {
        self.journal = Some(journal);
    }

    /// Returns the associated Journal
    pub fn journal(&self) -> Option<&Journal> {
        self.journal.as_ref()
    }

    /// Enables the zone for dynamic DNS updates
    pub fn set_allow_update(&mut self, allow_update: bool) {
        self.allow_update = allow_update;
    }

    /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    ///
    /// 3.2 - Process Prerequisite Section
    ///
    ///   Next, the Prerequisite Section is checked to see that all
    ///   prerequisites are satisfied by the current state of the zone.  Using
    ///   the definitions expressed in Section 1.2, if any RR's NAME is not
    ///   within the zone specified in the Zone Section, signal NOTZONE to the
    ///   requestor.
    ///
    /// 3.2.1. For RRs in this section whose CLASS is ANY, test to see that
    ///   TTL and RDLENGTH are both zero (0), else signal FORMERR to the
    ///   requestor.  If TYPE is ANY, test to see that there is at least one RR
    ///   in the zone whose NAME is the same as that of the Prerequisite RR,
    ///   else signal NXDOMAIN to the requestor.  If TYPE is not ANY, test to
    ///   see that there is at least one RR in the zone whose NAME and TYPE are
    ///   the same as that of the Prerequisite RR, else signal NXRRSET to the
    ///   requestor.
    ///
    /// 3.2.2. For RRs in this section whose CLASS is NONE, test to see that
    ///   the TTL and RDLENGTH are both zero (0), else signal FORMERR to the
    ///   requestor.  If the TYPE is ANY, test to see that there are no RRs in
    ///   the zone whose NAME is the same as that of the Prerequisite RR, else
    ///   signal YXDOMAIN to the requestor.  If the TYPE is not ANY, test to
    ///   see that there are no RRs in the zone whose NAME and TYPE are the
    ///   same as that of the Prerequisite RR, else signal YXRRSET to the
    ///   requestor.
    ///
    /// 3.2.3. For RRs in this section whose CLASS is the same as the ZCLASS,
    ///   test to see that the TTL is zero (0), else signal FORMERR to the
    ///   requestor.  Then, build an RRset for each unique <NAME,TYPE> and
    ///   compare each resulting RRset for set equality (same members, no more,
    ///   no less) with RRsets in the zone.  If any Prerequisite RRset is not
    ///   entirely and exactly matched by a zone RRset, signal NXRRSET to the
    ///   requestor.  If any RR in this section has a CLASS other than ZCLASS
    ///   or NONE or ANY, signal FORMERR to the requestor.
    ///
    /// 3.2.4 - Table Of Metavalues Used In Prerequisite Section
    ///
    ///   CLASS    TYPE     RDATA    Meaning
    ///   ------------------------------------------------------------
    ///   ANY      ANY      empty    Name is in use
    ///   ANY      rrset    empty    RRset exists (value independent)
    ///   NONE     ANY      empty    Name is not in use
    ///   NONE     rrset    empty    RRset does not exist
    ///   zone     rrset    rr       RRset exists (value dependent)
    /// ```
    pub fn verify_prerequisites(&self, pre_requisites: &[Record]) -> UpdateResult<()> {
        use futures::executor::block_on;

        //   3.2.5 - Pseudocode for Prerequisite Section Processing
        //
        //      for rr in prerequisites
        //           if (rr.ttl != 0)
        //                return (FORMERR)
        //           if (zone_of(rr.name) != ZNAME)
        //                return (NOTZONE);
        //           if (rr.class == ANY)
        //                if (rr.rdlength != 0)
        //                     return (FORMERR)
        //                if (rr.type == ANY)
        //                     if (!zone_name<rr.name>)
        //                          return (NXDOMAIN)
        //                else
        //                     if (!zone_rrset<rr.name, rr.type>)
        //                          return (NXRRSET)
        //           if (rr.class == NONE)
        //                if (rr.rdlength != 0)
        //                     return (FORMERR)
        //                if (rr.type == ANY)
        //                     if (zone_name<rr.name>)
        //                          return (YXDOMAIN)
        //                else
        //                     if (zone_rrset<rr.name, rr.type>)
        //                          return (YXRRSET)
        //           if (rr.class == zclass)
        //                temp<rr.name, rr.type> += rr
        //           else
        //                return (FORMERR)
        //
        //      for rrset in temp
        //           if (zone_rrset<rrset.name, rrset.type> != rrset)
        //                return (NXRRSET)
        for require in pre_requisites {
            let required_name = LowerName::from(require.name());

            if require.ttl() != 0 {
                warn!("ttl must be 0 for: {:?}", require);
                return Err(ResponseCode::FormErr);
            }

            if !self.origin().zone_of(&require.name().into()) {
                warn!("{} is not a zone_of {}", require.name(), self.origin());
                return Err(ResponseCode::NotZone);
            }

            match require.dns_class() {
                DNSClass::ANY => {
                    if let RData::NULL(..) = *require.rdata() {
                        match require.rr_type() {
                            // ANY      ANY      empty    Name is in use
                            RecordType::ANY => {
                                /*TODO: this works because the future here is always complete*/
                                if block_on(self.lookup(
                                    &required_name,
                                    RecordType::ANY,
                                    false,
                                    SupportedAlgorithms::new(),
                                ))
                                .unwrap_or_default()
                                .was_empty()
                                {
                                    return Err(ResponseCode::NXDomain);
                                } else {
                                    continue;
                                }
                            }
                            // ANY      rrset    empty    RRset exists (value independent)
                            rrset => {
                                /*TODO: this works because the future here is always complete*/
                                if block_on(self.lookup(
                                    &required_name,
                                    rrset,
                                    false,
                                    SupportedAlgorithms::new(),
                                ))
                                .unwrap_or_default()
                                .was_empty()
                                {
                                    return Err(ResponseCode::NXRRSet);
                                } else {
                                    continue;
                                }
                            }
                        }
                    } else {
                        return Err(ResponseCode::FormErr);
                    }
                }
                DNSClass::NONE => {
                    if let RData::NULL(..) = *require.rdata() {
                        match require.rr_type() {
                            // NONE     ANY      empty    Name is not in use
                            RecordType::ANY => {
                                /*TODO: this works because the future here is always complete*/
                                if !block_on(self.lookup(
                                    &required_name,
                                    RecordType::ANY,
                                    false,
                                    SupportedAlgorithms::new(),
                                ))
                                .unwrap_or_default()
                                .was_empty()
                                {
                                    return Err(ResponseCode::YXDomain);
                                } else {
                                    continue;
                                }
                            }
                            // NONE     rrset    empty    RRset does not exist
                            rrset => {
                                /*TODO: this works because the future here is always complete*/
                                if !block_on(self.lookup(
                                    &required_name,
                                    rrset,
                                    false,
                                    SupportedAlgorithms::new(),
                                ))
                                .unwrap_or_default()
                                .was_empty()
                                {
                                    return Err(ResponseCode::YXRRSet);
                                } else {
                                    continue;
                                }
                            }
                        }
                    } else {
                        return Err(ResponseCode::FormErr);
                    }
                }
                class if class == self.class() =>
                // zone     rrset    rr       RRset exists (value dependent)
                {
                    /*TODO: this works because the future here is always complete*/
                    if block_on(self.lookup(
                        &required_name,
                        require.rr_type(),
                        false,
                        SupportedAlgorithms::new(),
                    ))
                    .unwrap_or_default()
                    .iter()
                    .find(|rr| *rr == require)
                    .is_none()
                    {
                        return Err(ResponseCode::NXRRSet);
                    } else {
                        continue;
                    }
                }
                _ => return Err(ResponseCode::FormErr),
            }
        }

        // if we didn't bail everything checked out...
        Ok(())
    }

    /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    ///
    /// 3.3 - Check Requestor's Permissions
    ///
    /// 3.3.1. Next, the requestor's permission to update the RRs named in
    ///   the Update Section may be tested in an implementation dependent
    ///   fashion or using mechanisms specified in a subsequent Secure DNS
    ///   Update protocol.  If the requestor does not have permission to
    ///   perform these updates, the server may write a warning message in its
    ///   operations log, and may either signal REFUSED to the requestor, or
    ///   ignore the permission problem and proceed with the update.
    ///
    /// 3.3.2. While the exact processing is implementation defined, if these
    ///   verification activities are to be performed, this is the point in the
    ///   server's processing where such performance should take place, since
    ///   if a REFUSED condition is encountered after an update has been
    ///   partially applied, it will be necessary to undo the partial update
    ///   and restore the zone to its original state before answering the
    ///   requestor.
    /// ```
    ///
    #[cfg(feature = "dnssec")]
    #[allow(clippy::block_in_if_condition_stmt)]
    pub fn authorize(&self, update_message: &MessageRequest) -> UpdateResult<()> {
        use futures::executor::block_on;

        use proto::rr::dnssec::Verifier;
        use trust_dns_client::rr::rdata::{DNSSECRData, DNSSECRecordType};

        // 3.3.3 - Pseudocode for Permission Checking
        //
        //      if (security policy exists)
        //           if (this update is not permitted)
        //                if (local option)
        //                     log a message about permission problem
        //                if (local option)
        //                     return (REFUSED)

        // does this authority allow_updates?
        if !self.allow_update {
            warn!(
                "update attempted on non-updatable Authority: {}",
                self.origin()
            );
            return Err(ResponseCode::Refused);
        }

        // verify sig0, currently the only authorization that is accepted.
        let sig0s: &[Record] = update_message.sig0();
        debug!("authorizing with: {:?}", sig0s);
        if !sig0s.is_empty()
            && sig0s
                .iter()
                .filter_map(|sig0| {
                    if let RData::DNSSEC(DNSSECRData::SIG(ref sig)) = *sig0.rdata() {
                        Some(sig)
                    } else {
                        None
                    }
                })
                .any(|sig| {
                    let name = LowerName::from(sig.signer_name());
                    // TODO: updates should be async as well.
                    let keys = block_on(self.lookup(
                        &name,
                        RecordType::DNSSEC(DNSSECRecordType::KEY),
                        false,
                        SupportedAlgorithms::new(),
                    ));

                    let keys = match keys {
                        Ok(keys) => keys,
                        Err(_) => return false,
                    };

                    debug!("found keys {:?}", keys);
                    // TODO: check key usage flags and restrictions
                    keys.iter()
                        .filter_map(|rr_set| {
                            if let RData::DNSSEC(DNSSECRData::KEY(ref key)) = *rr_set.rdata() {
                                Some(key)
                            } else {
                                None
                            }
                        })
                        .any(|key| {
                            key.verify_message(update_message, sig.sig(), sig)
                                .map(|_| {
                                    info!("verified sig: {:?} with key: {:?}", sig, key);
                                    true
                                })
                                .unwrap_or_else(|_| {
                                    debug!("did not verify sig: {:?} with key: {:?}", sig, key);
                                    false
                                })
                        })
                })
        {
            return Ok(());
        } else {
            warn!(
                "no sig0 matched registered records: id {}",
                update_message.id()
            );
        }

        // getting here, we will always default to rejecting the request
        //  the code will only ever explicitly return authorized actions.
        Err(ResponseCode::Refused)
    }

    /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    ///
    /// 3.4 - Process Update Section
    ///
    ///   Next, the Update Section is processed as follows.
    ///
    /// 3.4.1 - Prescan
    ///
    ///   The Update Section is parsed into RRs and each RR's CLASS is checked
    ///   to see if it is ANY, NONE, or the same as the Zone Class, else signal
    ///   a FORMERR to the requestor.  Using the definitions in Section 1.2,
    ///   each RR's NAME must be in the zone specified by the Zone Section,
    ///   else signal NOTZONE to the requestor.
    ///
    /// 3.4.1.2. For RRs whose CLASS is not ANY, check the TYPE and if it is
    ///   ANY, AXFR, MAILA, MAILB, or any other QUERY metatype, or any
    ///   unrecognized type, then signal FORMERR to the requestor.  For RRs
    ///   whose CLASS is ANY or NONE, check the TTL to see that it is zero (0),
    ///   else signal a FORMERR to the requestor.  For any RR whose CLASS is
    ///   ANY, check the RDLENGTH to make sure that it is zero (0) (that is,
    ///   the RDATA field is empty), and that the TYPE is not AXFR, MAILA,
    ///   MAILB, or any other QUERY metatype besides ANY, or any unrecognized
    ///   type, else signal FORMERR to the requestor.
    /// ```
    #[allow(clippy::unused_unit)]
    pub fn pre_scan(&self, records: &[Record]) -> UpdateResult<()> {
        // 3.4.1.3 - Pseudocode For Update Section Prescan
        //
        //      [rr] for rr in updates
        //           if (zone_of(rr.name) != ZNAME)
        //                return (NOTZONE);
        //           if (rr.class == zclass)
        //                if (rr.type & ANY|AXFR|MAILA|MAILB)
        //                     return (FORMERR)
        //           elsif (rr.class == ANY)
        //                if (rr.ttl != 0 || rr.rdlength != 0
        //                    || rr.type & AXFR|MAILA|MAILB)
        //                     return (FORMERR)
        //           elsif (rr.class == NONE)
        //                if (rr.ttl != 0 || rr.type & ANY|AXFR|MAILA|MAILB)
        //                     return (FORMERR)
        //           else
        //                return (FORMERR)
        for rr in records {
            if !self.origin().zone_of(&rr.name().into()) {
                return Err(ResponseCode::NotZone);
            }

            let class: DNSClass = rr.dns_class();
            if class == self.class() {
                match rr.rr_type() {
                    RecordType::ANY | RecordType::AXFR | RecordType::IXFR => {
                        return Err(ResponseCode::FormErr);
                    }
                    _ => (),
                }
            } else {
                match class {
                    DNSClass::ANY => {
                        if rr.ttl() != 0 {
                            return Err(ResponseCode::FormErr);
                        }
                        if let RData::NULL(..) = *rr.rdata() {
                            ()
                        } else {
                            return Err(ResponseCode::FormErr);
                        }
                        match rr.rr_type() {
                            RecordType::AXFR | RecordType::IXFR => {
                                return Err(ResponseCode::FormErr);
                            }
                            _ => (),
                        }
                    }
                    DNSClass::NONE => {
                        if rr.ttl() != 0 {
                            return Err(ResponseCode::FormErr);
                        }
                        match rr.rr_type() {
                            RecordType::ANY | RecordType::AXFR | RecordType::IXFR => {
                                return Err(ResponseCode::FormErr);
                            }
                            _ => (),
                        }
                    }
                    _ => return Err(ResponseCode::FormErr),
                }
            }
        }

        Ok(())
    }

    /// Updates the specified records according to the update section.
    ///
    /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    ///
    /// 3.4.2.6 - Table Of Metavalues Used In Update Section
    ///
    ///   CLASS    TYPE     RDATA    Meaning
    ///   ---------------------------------------------------------
    ///   ANY      ANY      empty    Delete all RRsets from a name
    ///   ANY      rrset    empty    Delete an RRset
    ///   NONE     rrset    rr       Delete an RR from an RRset
    ///   zone     rrset    rr       Add to an RRset
    /// ```
    ///
    /// # Arguments
    ///
    /// * `records` - set of record instructions for update following above rules
    /// * `auto_signing_and_increment` - if true, the zone will sign and increment the SOA, this
    ///                                  should be disabled during recovery.
    pub fn update_records(
        &mut self,
        records: &[Record],
        auto_signing_and_increment: bool,
    ) -> UpdateResult<bool> {
        let mut updated = false;
        let serial: u32 = self.serial();

        // the persistence act as a write-ahead log. The WAL will also be used for recovery of a zone
        //  subsequent to a failure of the server.
        if let Some(ref journal) = self.journal {
            if let Err(error) = journal.insert_records(serial, records) {
                error!("could not persist update records: {}", error);
                return Err(ResponseCode::ServFail);
            }
        }

        // 3.4.2.7 - Pseudocode For Update Section Processing
        //
        //      [rr] for rr in updates
        //           if (rr.class == zclass)
        //                if (rr.type == CNAME)
        //                     if (zone_rrset<rr.name, ~CNAME>)
        //                          next [rr]
        //                elsif (zone_rrset<rr.name, CNAME>)
        //                     next [rr]
        //                if (rr.type == SOA)
        //                     if (!zone_rrset<rr.name, SOA> ||
        //                         zone_rr<rr.name, SOA>.serial > rr.soa.serial)
        //                          next [rr]
        //                for zrr in zone_rrset<rr.name, rr.type>
        //                     if (rr.type == CNAME || rr.type == SOA ||
        //                         (rr.type == WKS && rr.proto == zrr.proto &&
        //                          rr.address == zrr.address) ||
        //                         rr.rdata == zrr.rdata)
        //                          zrr = rr
        //                          next [rr]
        //                zone_rrset<rr.name, rr.type> += rr
        //           elsif (rr.class == ANY)
        //                if (rr.type == ANY)
        //                     if (rr.name == zname)
        //                          zone_rrset<rr.name, ~(SOA|NS)> = Nil
        //                     else
        //                          zone_rrset<rr.name, *> = Nil
        //                elsif (rr.name == zname &&
        //                       (rr.type == SOA || rr.type == NS))
        //                     next [rr]
        //                else
        //                     zone_rrset<rr.name, rr.type> = Nil
        //           elsif (rr.class == NONE)
        //                if (rr.type == SOA)
        //                     next [rr]
        //                if (rr.type == NS && zone_rrset<rr.name, NS> == rr)
        //                     next [rr]
        //                zone_rr<rr.name, rr.type, rr.data> = Nil
        //      return (NOERROR)
        for rr in records {
            let rr_name = LowerName::from(rr.name());
            let rr_key = RrKey::new(rr_name.clone(), rr.rr_type());

            match rr.dns_class() {
                class if class == self.class() => {
                    // RFC 2136 - 3.4.2.2. Any Update RR whose CLASS is the same as ZCLASS is added to
                    //  the zone.  In case of duplicate RDATAs (which for SOA RRs is always
                    //  the case, and for WKS RRs is the case if the ADDRESS and PROTOCOL
                    //  fields both match), the Zone RR is replaced by Update RR.  If the
                    //  TYPE is SOA and there is no Zone SOA RR, or the new SOA.SERIAL is
                    //  lower (according to [RFC1982]) than or equal to the current Zone SOA
                    //  RR's SOA.SERIAL, the Update RR is ignored.  In the case of a CNAME
                    //  Update RR and a non-CNAME Zone RRset or vice versa, ignore the CNAME
                    //  Update RR, otherwise replace the CNAME Zone RR with the CNAME Update
                    //  RR.

                    // zone     rrset    rr       Add to an RRset
                    info!("upserting record: {:?}", rr);
                    updated = self.upsert(rr.clone(), serial) || updated;
                }
                DNSClass::ANY => {
                    // This is a delete of entire RRSETs, either many or one. In either case, the spec is clear:
                    match rr.rr_type() {
                        t @ RecordType::SOA | t @ RecordType::NS if rr_name == *self.origin() => {
                            // SOA and NS records are not to be deleted if they are the origin records
                            info!("skipping delete of {:?} see RFC 2136 - 3.4.2.3", t);
                            continue;
                        }
                        RecordType::ANY => {
                            // RFC 2136 - 3.4.2.3. For any Update RR whose CLASS is ANY and whose TYPE is ANY,
                            //   all Zone RRs with the same NAME are deleted, unless the NAME is the
                            //   same as ZNAME in which case only those RRs whose TYPE is other than
                            //   SOA or NS are deleted.

                            // ANY      ANY      empty    Delete all RRsets from a name
                            info!(
                                "deleting all records at name (not SOA or NS at origin): {:?}",
                                rr_name
                            );
                            let to_delete = self
                                .records()
                                .keys()
                                .filter(|k| {
                                    !((k.record_type == RecordType::SOA
                                        || k.record_type == RecordType::NS)
                                        && k.name != *self.origin())
                                })
                                .filter(|k| k.name == rr_name)
                                .cloned()
                                .collect::<Vec<RrKey>>();
                            for delete in to_delete {
                                self.records_mut().remove(&delete);
                                updated = true;
                            }
                        }
                        _ => {
                            // RFC 2136 - 3.4.2.3. For any Update RR whose CLASS is ANY and
                            //   whose TYPE is not ANY all Zone RRs with the same NAME and TYPE are
                            //   deleted, unless the NAME is the same as ZNAME in which case neither
                            //   SOA or NS RRs will be deleted.

                            // ANY      rrset    empty    Delete an RRset
                            if let RData::NULL(..) = *rr.rdata() {
                                let deleted = self.records_mut().remove(&rr_key);
                                info!("deleted rrset: {:?}", deleted);
                                updated = updated || deleted.is_some();
                            } else {
                                info!("expected empty rdata: {:?}", rr);
                                return Err(ResponseCode::FormErr);
                            }
                        }
                    }
                }
                DNSClass::NONE => {
                    info!("deleting specific record: {:?}", rr);
                    // NONE     rrset    rr       Delete an RR from an RRset
                    if let Some(rrset) = self.records_mut().get_mut(&rr_key) {
                        // b/c this is an Arc, we need to clone, then remove, and replace the node.
                        let mut rrset_clone: RecordSet = RecordSet::clone(&*rrset);
                        let deleted = rrset_clone.remove(rr, serial);
                        info!("deleted ({}) specific record: {:?}", deleted, rr);
                        updated = updated || deleted;

                        if deleted {
                            *rrset = Arc::new(rrset_clone);
                        }
                    }
                }
                class => {
                    info!("unexpected DNS Class: {:?}", class);
                    return Err(ResponseCode::FormErr);
                }
            }
        }

        // update the serial...
        if updated && auto_signing_and_increment {
            if self.is_dnssec_enabled {
                self.secure_zone().map_err(|e| {
                    error!("failure securing zone: {}", e);
                    ResponseCode::ServFail
                })?
            } else {
                // the secure_zone() function increments the SOA during it's operation, if we're not
                //  dnssec, then we need to do it here...
                self.increment_soa_serial();
            }
        }

        Ok(updated)
    }
}

impl Deref for SqliteAuthority {
    type Target = InMemoryAuthority;

    fn deref(&self) -> &Self::Target {
        &self.in_memory
    }
}

impl DerefMut for SqliteAuthority {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.in_memory
    }
}

impl Authority for SqliteAuthority {
    type Lookup = <InMemoryAuthority as Authority>::Lookup;
    type LookupFuture = <InMemoryAuthority as Authority>::LookupFuture;

    /// What type is this zone
    fn zone_type(&self) -> ZoneType {
        self.in_memory.zone_type()
    }

    /// Return true if AXFR is allowed
    fn is_axfr_allowed(&self) -> bool {
        self.in_memory.is_axfr_allowed()
    }

    /// Takes the UpdateMessage, extracts the Records, and applies the changes to the record set.
    ///
    /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    ///
    /// 3.4 - Process Update Section
    ///
    ///   Next, the Update Section is processed as follows.
    ///
    /// 3.4.2 - Update
    ///
    ///   The Update Section is parsed into RRs and these RRs are processed in
    ///   order.
    ///
    /// 3.4.2.1. If any system failure (such as an out of memory condition,
    ///   or a hardware error in persistent storage) occurs during the
    ///   processing of this section, signal SERVFAIL to the requestor and undo
    ///   all updates applied to the zone during this transaction.
    ///
    /// 3.4.2.2. Any Update RR whose CLASS is the same as ZCLASS is added to
    ///   the zone.  In case of duplicate RDATAs (which for SOA RRs is always
    ///   the case, and for WKS RRs is the case if the ADDRESS and PROTOCOL
    ///   fields both match), the Zone RR is replaced by Update RR.  If the
    ///   TYPE is SOA and there is no Zone SOA RR, or the new SOA.SERIAL is
    ///   lower (according to [RFC1982]) than or equal to the current Zone SOA
    ///   RR's SOA.SERIAL, the Update RR is ignored.  In the case of a CNAME
    ///   Update RR and a non-CNAME Zone RRset or vice versa, ignore the CNAME
    ///   Update RR, otherwise replace the CNAME Zone RR with the CNAME Update
    ///   RR.
    ///
    /// 3.4.2.3. For any Update RR whose CLASS is ANY and whose TYPE is ANY,
    ///   all Zone RRs with the same NAME are deleted, unless the NAME is the
    ///   same as ZNAME in which case only those RRs whose TYPE is other than
    ///   SOA or NS are deleted.  For any Update RR whose CLASS is ANY and
    ///   whose TYPE is not ANY all Zone RRs with the same NAME and TYPE are
    ///   deleted, unless the NAME is the same as ZNAME in which case neither
    ///   SOA or NS RRs will be deleted.
    ///
    /// 3.4.2.4. For any Update RR whose class is NONE, any Zone RR whose
    ///   NAME, TYPE, RDATA and RDLENGTH are equal to the Update RR is deleted,
    ///   unless the NAME is the same as ZNAME and either the TYPE is SOA or
    ///   the TYPE is NS and the matching Zone RR is the only NS remaining in
    ///   the RRset, in which case this Update RR is ignored.
    ///
    /// 3.4.2.5. Signal NOERROR to the requestor.
    /// ```
    ///
    /// # Arguments
    ///
    /// * `update` - The `UpdateMessage` records will be extracted and used to perform the update
    ///              actions as specified in the above RFC.
    ///
    /// # Return value
    ///
    /// true if any of additions, updates or deletes were made to the zone, false otherwise. Err is
    ///  returned in the case of bad data, etc.
    #[cfg(feature = "dnssec")]
    fn update(&mut self, update: &MessageRequest) -> UpdateResult<bool> {
        // the spec says to authorize after prereqs, seems better to auth first.
        self.authorize(update)?;
        self.verify_prerequisites(update.prerequisites())?;
        self.pre_scan(update.updates())?;

        self.update_records(update.updates(), true)
    }

    /// Always fail when DNSSEC is disabled.
    #[cfg(not(feature = "dnssec"))]
    fn update(&mut self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName {
        self.in_memory.origin()
    }

    /// Looks up all Resource Records matching the giving `Name` and `RecordType`.
    ///
    /// # Arguments
    ///
    /// * `name` - The `Name`, label, to lookup.
    /// * `rtype` - The `RecordType`, to lookup. `RecordType::ANY` will return all records matching
    ///             `name`. `RecordType::AXFR` will return all record types except `RecordType::SOA`
    ///             due to the requirements that on zone transfers the `RecordType::SOA` must both
    ///             precede and follow all other records.
    /// * `is_secure` - If the DO bit is set on the EDNS OPT record, then return RRSIGs as well.
    ///
    /// # Return value
    ///
    /// None if there are no matching records, otherwise a `Vec` containing the found records.
    fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        self.in_memory
            .lookup(name, rtype, is_secure, supported_algorithms)
    }

    fn search(
        &self,
        query: &LowerQuery,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        self.in_memory
            .search(query, is_secure, supported_algorithms)
    }

    /// Return the NSEC records based on the given name
    ///
    /// # Arguments
    ///
    /// * `name` - given this name (i.e. the lookup name), return the NSEC record that is less than
    ///            this
    /// * `is_secure` - if true then it will return RRSIG records as well
    fn get_nsec_records(
        &self,
        name: &LowerName,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        self.in_memory
            .get_nsec_records(name, is_secure, supported_algorithms)
    }

    fn add_update_auth_key(&mut self, name: Name, key: KEY) -> DnsSecResult<()> {
        self.in_memory.add_update_auth_key(name, key)
    }

    /// By adding a secure key, this will implicitly enable dnssec for the zone.
    ///
    /// # Arguments
    ///
    /// * `signer` - Signer with associated private key
    fn add_zone_signing_key(&mut self, signer: Signer) -> DnsSecResult<()> {
        self.in_memory.add_zone_signing_key(signer)
    }

    /// (Re)generates the nsec records, increments the serial number and signs the zone
    fn secure_zone(&mut self) -> DnsSecResult<()> {
        Authority::secure_zone(&mut self.in_memory)
    }
}
