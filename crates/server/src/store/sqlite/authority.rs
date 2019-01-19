// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! All authority related types

#[cfg(feature = "dnssec")]
use std::borrow::Borrow;
use std::collections::btree_map::Values;
use std::collections::BTreeMap;

use proto::rr::RrsetRecords;
#[cfg(feature = "dnssec")]
use trust_dns::error::*;
use trust_dns::op::{LowerQuery, ResponseCode};
use trust_dns::rr::dnssec::{Signer, SupportedAlgorithms};
use trust_dns::rr::{DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType, RrKey};

#[cfg(feature = "dnssec")]
use authority::UpdateRequest;
use authority::{AuthLookup, Authority, MessageRequest, UpdateResult, ZoneType};
use store::sqlite::Journal;

use error::{PersistenceErrorKind, PersistenceResult};

/// SqliteAuthority is responsible for storing the resource records for a particular zone.
///
/// Authorities default to DNSClass IN. The ZoneType specifies if this should be treated as the
/// start of authority for the zone, is a slave, or a cached zone.
pub struct SqliteAuthority {
    origin: LowerName,
    class: DNSClass,
    journal: Option<Journal>,
    records: BTreeMap<RrKey, RecordSet>,
    zone_type: ZoneType,
    allow_update: bool,
    allow_axfr: bool,
    is_dnssec_enabled: bool,
    // Private key mapped to the Record of the DNSKey
    //  TODO: these private_keys should be stored securely. Ideally, we have keys only stored per
    //   server instance, but that requires requesting updates from the parent zone, which may or
    //   may not support dynamic updates to register the new key... Trust-DNS will provide support
    //   for this, in some form, perhaps alternate root zones...
    secure_keys: Vec<Signer>,
}

impl SqliteAuthority {
    /// Creates a new Authority.
    ///
    /// # Arguments
    ///
    /// * `origin` - The zone `Name` being created, this should match that of the `RecordType::SOA`
    ///              record.
    /// * `records` - The map of the initial set of records in the zone.
    /// * `zone_type` - The type of zone, i.e. is this authoritative?
    /// * `allow_update` - If true, then this zone accepts dynamic updates.
    /// * `is_dnssec_enabled` - If true, then the zone will sign the zone with all registered keys,
    ///                         (see `add_secure_key()`)
    ///
    /// # Return value
    ///
    /// The new `Authority`.
    pub fn new(
        origin: Name,
        records: BTreeMap<RrKey, RecordSet>,
        zone_type: ZoneType,
        allow_update: bool,
        allow_axfr: bool,
        is_dnssec_enabled: bool,
    ) -> Self {
        Self {
            origin: LowerName::new(&origin),
            class: DNSClass::IN,
            journal: None,
            records,
            zone_type,
            allow_update,
            allow_axfr,
            is_dnssec_enabled,
            secure_keys: Vec::new(),
        }
    }

    /// By adding a secure key, this will implicitly enable dnssec for the zone.
    ///
    /// # Arguments
    ///
    /// * `signer` - Signer with associated private key
    #[cfg(feature = "dnssec")]
    pub fn add_secure_key(&mut self, signer: Signer) -> DnsSecResult<()> {
        use trust_dns::rr::rdata::{DNSSECRData, DNSSECRecordType};

        // also add the key to the zone
        let zone_ttl = self.minimum_ttl();
        let dnskey = signer.key().to_dnskey(signer.algorithm())?;
        let dnskey = Record::from_rdata(
            self.origin.clone().into(),
            zone_ttl,
            RecordType::DNSSEC(DNSSECRecordType::DNSKEY),
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
        );

        // TODO: also generate the CDS and CDNSKEY
        let serial = self.serial();
        self.upsert(dnskey, serial);
        self.secure_keys.push(signer);
        Ok(())
    }

    /// Recovers the zone from a Journal, returns an error on failure to recover the zone.
    ///
    /// # Arguments
    ///
    /// * `journal` - the journal from which to load the persisted zone.
    pub fn recover_with_journal(&mut self, journal: &Journal) -> PersistenceResult<()> {
        assert!(
            self.records.is_empty(),
            "records should be empty during a recovery"
        );

        info!("recovering from journal");
        for record in journal.iter() {
            // AXFR is special, it is used to mark the dump of a full zone.
            //  when recovering, if an AXFR is encountered, we should remove all the records in the
            //  authority.
            if record.rr_type() == RecordType::AXFR {
                self.records.clear();
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

            for rr_set in self.records.values() {
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

    /// Enables AXFRs of all the zones records
    pub fn set_allow_axfr(&mut self, allow_axfr: bool) {
        self.allow_axfr = allow_axfr;
    }

    /// Retrieve the Signer, which contains the private keys, for this zone
    pub fn secure_keys(&self) -> &[Signer] {
        &self.secure_keys
    }

    /// Get all the
    pub fn records(&self) -> &BTreeMap<RrKey, RecordSet> {
        &self.records
    }

    /// Returns the minimum ttl (as used in the SOA record)
    pub fn minimum_ttl(&self) -> u32 {
        self.soa().next().map_or(0, |soa| {
            if let RData::SOA(ref rdata) = *soa.rdata() {
                rdata.minimum()
            } else {
                0
            }
        })
    }

    /// get the current serial number for the zone.
    pub fn serial(&self) -> u32 {
        self.soa().next().map_or_else(
            || {
                warn!("no soa record found for zone: {}", self.origin);
                0
            },
            |soa| {
                if let RData::SOA(ref soa_rdata) = *soa.rdata() {
                    soa_rdata.serial()
                } else {
                    panic!("This was not an SOA record"); // valid panic, never should happen
                }
            },
        )
    }

    fn increment_soa_serial(&mut self) -> u32 {
        let opt_soa_serial = self.soa().next().map(|soa| {
            // TODO: can we get a mut reference to SOA directly?
            let mut soa: Record = soa.clone();

            let serial = if let RData::SOA(ref mut soa_rdata) = *soa.rdata_mut() {
                soa_rdata.increment_serial();
                soa_rdata.serial()
            } else {
                panic!("This was not an SOA record"); // valid panic, never should happen
            };

            (soa, serial)
        });

        if let Some((soa, serial)) = opt_soa_serial {
            self.upsert(soa, serial);
            serial
        } else {
            error!(
                "no soa record found for zone while attempting increment: {}",
                self.origin
            );
            0
        }
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

            if !self.origin.zone_of(&require.name().into()) {
                warn!("{} is not a zone_of {}", require.name(), self.origin);
                return Err(ResponseCode::NotZone);
            }

            match require.dns_class() {
                DNSClass::ANY => if let RData::NULL(..) = *require.rdata() {
                    match require.rr_type() {
                        // ANY      ANY      empty    Name is in use
                        RecordType::ANY => {
                            if self
                                .lookup(
                                    &required_name,
                                    RecordType::ANY,
                                    false,
                                    SupportedAlgorithms::new(),
                                ).was_empty()
                            {
                                return Err(ResponseCode::NXDomain);
                            } else {
                                continue;
                            }
                        }
                        // ANY      rrset    empty    RRset exists (value independent)
                        rrset => {
                            if self
                                .lookup(&required_name, rrset, false, SupportedAlgorithms::new())
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
                },
                DNSClass::NONE => if let RData::NULL(..) = *require.rdata() {
                    match require.rr_type() {
                        // NONE     ANY      empty    Name is not in use
                        RecordType::ANY => {
                            if !self
                                .lookup(
                                    &required_name,
                                    RecordType::ANY,
                                    false,
                                    SupportedAlgorithms::new(),
                                ).was_empty()
                            {
                                return Err(ResponseCode::YXDomain);
                            } else {
                                continue;
                            }
                        }
                        // NONE     rrset    empty    RRset does not exist
                        rrset => {
                            if !self
                                .lookup(&required_name, rrset, false, SupportedAlgorithms::new())
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
                },
                class if class == self.class =>
                // zone     rrset    rr       RRset exists (value dependent)
                {
                    if self
                        .lookup(
                            &required_name,
                            require.rr_type(),
                            false,
                            SupportedAlgorithms::new(),
                        ).find(|rr| *rr == require)
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
    pub fn authorize(&self, update_message: &MessageRequest) -> UpdateResult<()> {
        use proto::rr::dnssec::Verifier;
        use trust_dns::rr::rdata::{DNSSECRData, DNSSECRecordType};

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
                self.origin
            );
            return Err(ResponseCode::Refused);
        }

        // verify sig0, currently the only authorization that is accepted.
        let sig0s: &[Record] = update_message.sig0();
        debug!("authorizing with: {:?}", sig0s);
        if !sig0s.is_empty() && sig0s
            .iter()
            .filter_map(|sig0| {
                if let RData::DNSSEC(DNSSECRData::SIG(ref sig)) = *sig0.rdata() {
                    Some(sig)
                } else {
                    None
                }
            }).any(|sig| {
                let name = LowerName::from(sig.signer_name());
                let keys = self.lookup(
                    &name,
                    RecordType::DNSSEC(DNSSECRecordType::KEY),
                    false,
                    SupportedAlgorithms::new(),
                );
                debug!("found keys {:?}", keys);
                // FIXME: check key usage flags and restrictions
                keys.filter_map(|rr_set| {
                    if let RData::DNSSEC(DNSSECRData::KEY(ref key)) = *rr_set.rdata() {
                        Some(key)
                    } else {
                        None
                    }
                }).any(|key| {
                    key.verify_message(update_message, sig.sig(), sig)
                        .map(|_| {
                            info!("verified sig: {:?} with key: {:?}", sig, key);
                            true
                        }).unwrap_or_else(|_| {
                            debug!("did not verify sig: {:?} with key: {:?}", sig, key);
                            false
                        })
                })
            }) {
            return Ok(());
        } else {
            warn!(
                "no sig0 matched registered records: id {}",
                update_message.id()
            );
        }

        // getting here, we will always default to rejecting the request
        //  the code will only ever explcitly return authrorized actions.
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
            if class == self.class {
                match rr.rr_type() {
                    RecordType::ANY | RecordType::AXFR | RecordType::IXFR => {
                        return Err(ResponseCode::FormErr)
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
                                return Err(ResponseCode::FormErr)
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
                                return Err(ResponseCode::FormErr)
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
                class if class == self.class => {
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
                        t @ RecordType::SOA | t @ RecordType::NS if rr_name == self.origin => {
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
                                .records
                                .keys()
                                .filter(|k| {
                                    !((k.record_type == RecordType::SOA
                                        || k.record_type == RecordType::NS)
                                        && k.name != self.origin)
                                }).filter(|k| k.name == rr_name)
                                .cloned()
                                .collect::<Vec<RrKey>>();
                            for delete in to_delete {
                                self.records.remove(&delete);
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
                                let deleted = self.records.remove(&rr_key);
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
                    if let Some(rrset) = self.records.get_mut(&rr_key) {
                        let deleted = rrset.remove(rr, serial);
                        info!("deleted ({}) specific record: {:?}", deleted, rr);
                        updated = updated || deleted;
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

    /// Inserts or updates a `Record` depending on it's existence in the authority.
    ///
    /// Guarantees that SOA, CNAME only has one record, will implicitly update if they already exist.
    ///
    /// # Arguments
    ///
    /// * `record` - The `Record` to be inserted or updated.
    /// * `serial` - Current serial number to be recorded against updates.
    ///
    /// # Return value
    ///
    /// Ok() on success or Err() with the `ResponseCode` associated with the error.
    pub fn upsert(&mut self, record: Record, serial: u32) -> bool {
        assert_eq!(self.class, record.dns_class());

        let rr_key = RrKey::new(record.name().into(), record.rr_type());
        let records: &mut RecordSet = self
            .records
            .entry(rr_key)
            .or_insert_with(|| RecordSet::new(record.name(), record.rr_type(), serial));

        records.insert(record, serial)
    }

    /// Looks up all Resource Records matching the giving `Name` and `RecordType`.
    ///
    /// # Arguments
    ///
    /// * `name` - The `Name`, label, to lookup.
    /// * `rtype` - The `RecordType`, to lookup. `RecordType::ANY` will return all records matching
    ///             `name`. `RecordType::AXFR` will return all record types except `RecordType::SOA`
    ///             due to the requirements that on zone transfers the `RecordType::SOA` must both
    ///             preceed and follow all other records.
    /// * `is_secure` - If the DO bit is set on the EDNS OPT record, then return RRSIGs as well.
    ///
    /// # Return value
    ///
    /// None if there are no matching records, otherwise a `Vec` containing the found records.
    pub fn lookup<'s, 'q>(
        &'s self,
        name: &'q LowerName,
        rtype: RecordType,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> LookupRecords<'s, 'q> {
        let rr_key = RrKey::new(name.clone(), rtype);

        // Collect the records from each rr_set
        let result: LookupRecords = match rtype {
            RecordType::AXFR | RecordType::ANY => {
                let result = AnyRecordsIter::new(
                    is_secure,
                    supported_algorithms,
                    self.records.values(),
                    rtype,
                    name,
                );
                LookupRecords::AnyRecordsIter(result)
            }
            _ => self
                .records
                .get(&rr_key)
                .map_or(LookupRecords::NxDomain, |rr_set| {
                    LookupRecords::from(rr_set.records(is_secure, supported_algorithms))
                }),
        };

        // This is annoying. The 1035 spec literally specifies that most DNS authorities would want to store
        //   records in a list except when there are a lot of records. But this makes indexed lookups by name+type
        //   always return empty sets. This is only important in the negative case, where other DNS authorities
        //   generally return NoError and no results when other types exist at the same name. bah.
        if result.is_nx_domain() {
            if self.records.keys().any(|key| key.name() == name) {
                return LookupRecords::NameExists;
            } else {
                return LookupRecords::NxDomain;
            }
        }

        result
    }

    /// (Re)generates the nsec records, increments the serial number nad signs the zone
    #[cfg(feature = "dnssec")]
    pub fn secure_zone(&mut self) -> DnsSecResult<()> {
        // TODO: only call nsec_zone after adds/deletes
        // needs to be called before incrementing the soa serial, to make sur IXFR works properly
        self.nsec_zone();

        // need to resign any records at the current serial number and bump the number.
        // first bump the serial number on the SOA, so that it is resigned with the new serial.
        self.increment_soa_serial();

        // TODO: should we auto sign here? or maybe up a level...
        self.sign_zone()
    }

    /// (Re)generates the nsec records, increments the serial number nad signs the zone
    #[cfg(not(feature = "dnssec"))]
    pub fn secure_zone(&mut self) -> Result<(), &str> {
        Err("DNSSEC is not enabled.")
    }

    /// Dummy implementation for when DNSSEC is disabled.
    #[cfg(feature = "dnssec")]
    fn nsec_zone(&mut self) {
        use trust_dns::rr::rdata::{DNSSECRData, DNSSECRecordType, NSEC};

        // only create nsec records for secure zones
        if self.secure_keys.is_empty() {
            return;
        }
        debug!("generating nsec records: {}", self.origin);

        // first remove all existing nsec records
        let delete_keys: Vec<RrKey> = self
            .records
            .keys()
            .filter(|k| k.record_type == RecordType::DNSSEC(DNSSECRecordType::NSEC))
            .cloned()
            .collect();

        for key in delete_keys {
            self.records.remove(&key);
        }

        // now go through and generate the nsec records
        let ttl = self.minimum_ttl();
        let serial = self.serial();
        let mut records: Vec<Record> = vec![];

        {
            let mut nsec_info: Option<(&Name, Vec<RecordType>)> = None;
            for key in self.records.keys() {
                match nsec_info {
                    None => nsec_info = Some((key.name.borrow(), vec![key.record_type])),
                    Some((name, ref mut vec)) if LowerName::new(name) == key.name => {
                        vec.push(key.record_type)
                    }
                    Some((name, vec)) => {
                        // names aren't equal, create the NSEC record
                        let mut record = Record::with(
                            name.clone(),
                            RecordType::DNSSEC(DNSSECRecordType::NSEC),
                            ttl,
                        );
                        let rdata = NSEC::new(key.name.clone().into(), vec);
                        record.set_rdata(RData::DNSSEC(DNSSECRData::NSEC(rdata)));
                        records.push(record);

                        // new record...
                        nsec_info = Some((&key.name.borrow(), vec![key.record_type]))
                    }
                }
            }

            // the last record
            if let Some((name, vec)) = nsec_info {
                // names aren't equal, create the NSEC record
                let mut record = Record::with(
                    name.clone(),
                    RecordType::DNSSEC(DNSSECRecordType::NSEC),
                    ttl,
                );
                let rdata = NSEC::new(self.origin().clone().into(), vec);
                record.set_rdata(RData::DNSSEC(DNSSECRData::NSEC(rdata)));
                records.push(record);
            }
        }

        // insert all the nsec records
        for record in records {
            self.upsert(record, serial);
        }
    }

    /// Signs any records in the zone that have serial numbers greater than or equal to `serial`
    #[cfg(feature = "dnssec")]
    fn sign_zone(&mut self) -> DnsSecResult<()> {
        use chrono::Utc;
        use trust_dns::rr::dnssec::tbs;
        use trust_dns::rr::rdata::{DNSSECRData, DNSSECRecordType, SIG};

        debug!("signing zone: {}", self.origin);
        let inception = Utc::now();
        let zone_ttl = self.minimum_ttl();

        // TODO: should this be an error?
        if self.secure_keys.is_empty() {
            warn!("attempt to sign_zone for dnssec, but no keys available!")
        }

        // sign all record_sets, as of 0.12.1 this includes DNSKEY
        for rr_set in self.records.values_mut() {
            rr_set.clear_rrsigs();
            let rrsig_temp = Record::with(
                rr_set.name().clone(),
                RecordType::DNSSEC(DNSSECRecordType::RRSIG),
                zone_ttl,
            );

            for signer in &self.secure_keys {
                debug!(
                    "signing rr_set: {}, {} with: {}",
                    rr_set.name(),
                    rr_set.record_type(),
                    signer.algorithm(),
                );

                let expiration = inception + signer.sig_duration();

                let tbs = tbs::rrset_tbs(
                    rr_set.name(),
                    self.class,
                    rr_set.name().num_labels(),
                    rr_set.record_type(),
                    signer.algorithm(),
                    rr_set.ttl(),
                    expiration.timestamp() as u32,
                    inception.timestamp() as u32,
                    signer.calculate_key_tag()?,
                    signer.signer_name(),
                    // TODO: this is a nasty clone... the issue is that the vec
                    //  from records is of Vec<&R>, but we really want &[R]
                    &rr_set
                        .records_without_rrsigs()
                        .cloned()
                        .collect::<Vec<Record>>(),
                );

                // TODO, maybe chain these with some ETL operations instead?
                let tbs = match tbs {
                    Ok(tbs) => tbs,
                    Err(err) => {
                        error!("could not serialize rrset to sign: {}", err);
                        continue;
                    }
                };

                let signature = signer.sign(&tbs);
                let signature = match signature {
                    Ok(signature) => signature,
                    Err(err) => {
                        error!("could not sign rrset: {}", err);
                        continue;
                    }
                };

                let mut rrsig = rrsig_temp.clone();
                rrsig.set_rdata(RData::DNSSEC(DNSSECRData::SIG(SIG::new(
                    // type_covered: RecordType,
                    rr_set.record_type(),
                    // algorithm: Algorithm,
                    signer.algorithm(),
                    // num_labels: u8,
                    rr_set.name().num_labels(),
                    // original_ttl: u32,
                    rr_set.ttl(),
                    // sig_expiration: u32,
                    expiration.timestamp() as u32,
                    // sig_inception: u32,
                    inception.timestamp() as u32,
                    // key_tag: u16,
                    signer.calculate_key_tag()?,
                    // signer_name: Name,
                    signer.signer_name().clone(),
                    // sig: Vec<u8>
                    signature,
                ))));

                rr_set.insert_rrsig(rrsig);
            }
        }

        Ok(())
    }
}

impl Authority for SqliteAuthority {
    /// What type is this zone
    fn zone_type(&self) -> ZoneType {
        self.zone_type
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
        &self.origin
    }

    /// Using the specified query, perform a lookup against this zone.
    ///
    /// # Arguments
    ///
    /// * `query` - the query to perform the lookup with.
    /// * `is_secure` - if true, then RRSIG records (if this is a secure zone) will be returned.
    ///
    /// # Return value
    ///
    /// Returns a vectory containing the results of the query, it will be empty if not found. If
    ///  `is_secure` is true, in the case of no records found then NSEC records will be returned.
    fn search<'s, 'q>(
        &'s self,
        query: &'q LowerQuery,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> AuthLookup<'s, 'q> {
        let lookup_name = query.name();
        let record_type: RecordType = query.query_type();

        // if this is an AXFR zone transfer, verify that this is either the slave or master
        //  for AXFR the first and last record must be the SOA
        if RecordType::AXFR == record_type {
            // TODO: support more advanced AXFR options
            if !self.allow_axfr {
                return AuthLookup::Refused;
            }

            match self.zone_type() {
                ZoneType::Master | ZoneType::Slave => (),
                // TODO: Forward?
                _ => return AuthLookup::NxDomain, // TODO: this sould be an error.
            }
        }

        // perform the actual lookup
        match record_type {
            RecordType::SOA => {
                let lookup =
                    self.lookup(&self.origin, record_type, is_secure, supported_algorithms);

                match lookup {
                    LookupRecords::NxDomain => AuthLookup::NxDomain,
                    LookupRecords::NameExists => AuthLookup::NameExists,
                    lookup => AuthLookup::SOA(lookup),
                }
            }
            RecordType::AXFR => {
                // FIXME: shouldn't these SOA's be secure? at least the first, perhaps not the last?
                let start_soa = self.soa();
                let end_soa = self.soa();
                let records =
                    self.lookup(lookup_name, record_type, is_secure, supported_algorithms);

                match start_soa {
                    LookupRecords::NxDomain => AuthLookup::NxDomain,
                    LookupRecords::NameExists => AuthLookup::NameExists,
                    start_soa => AuthLookup::AXFR(start_soa.chain(records).chain(end_soa)),
                }
            }
            _ => {
                let lookup = self.lookup(lookup_name, record_type, is_secure, supported_algorithms);

                match lookup {
                    LookupRecords::NxDomain => AuthLookup::NxDomain,
                    LookupRecords::NameExists => AuthLookup::NameExists,
                    lookup => AuthLookup::Records(lookup),
                }
            }
        }
    }

    /// Get the NS, NameServer, record for the zone
    fn ns(&self, is_secure: bool, supported_algorithms: SupportedAlgorithms) -> LookupRecords {
        self.lookup(
            &self.origin,
            RecordType::NS,
            is_secure,
            supported_algorithms,
        )
    }

    /// Return the NSEC records based on the given name
    ///
    /// # Arguments
    ///
    /// * `name` - given this name (i.e. the lookup name), return the NSEC record that is less than
    ///            this
    /// * `is_secure` - if true then it will return RRSIG records as well
    fn get_nsec_records<'s, 'q>(
        &'s self,
        name: &'q LowerName,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> LookupRecords<'s, 'q> {
        #[cfg(feature = "dnssec")]
        fn is_nsec_rrset(rr_set: &RecordSet) -> bool {
            use trust_dns::rr::rdata::DNSSECRecordType;

            rr_set.record_type() == RecordType::DNSSEC(DNSSECRecordType::NSEC)
        }

        #[cfg(not(feature = "dnssec"))]
        fn is_nsec_rrset(_record: &RecordSet) -> bool {
            // There's no way to create an NSEC record when DNSSEC is disabled
            // at build time.
            false
        }

        self.records
            .values()
            .filter(|rr_set| is_nsec_rrset(rr_set))
            .skip_while(|rr_set| *name < rr_set.name().into())
            .next()
            .map_or(LookupRecords::NxDomain, |rr_set| {
                LookupRecords::from(rr_set.records(is_secure, supported_algorithms))
            })
    }

    /// Returns the SOA of the authority.
    ///
    /// *Note*: This will only return the SOA, if this is fullfilling a request, a standard lookup
    ///  should be used, see `soa_secure()`, which will optionally return RRSIGs.
    fn soa(&self) -> LookupRecords {
        // SOA should be origin|SOA
        self.lookup(
            &self.origin,
            RecordType::SOA,
            false,
            SupportedAlgorithms::new(),
        )
    }

    /// Returns the SOA record for the zone
    fn soa_secure(
        &self,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> LookupRecords {
        self.lookup(
            &self.origin,
            RecordType::SOA,
            is_secure,
            supported_algorithms,
        )
    }
}

/// An iterator over an ANY query for Records.
///
/// The length of this result cannot be known without consuming the iterator.
///
/// # Lifetimes
///
/// * `'r` - the record_set's lifetime, from the catalog
/// * `'q` - the lifetime of the query/request
#[derive(Debug)]
pub struct AnyRecordsIter<'r, 'q> {
    is_secure: bool,
    supported_algorithms: SupportedAlgorithms,
    rrsets: Values<'r, RrKey, RecordSet>,
    rrset: Option<&'r RecordSet>,
    records: Option<RrsetRecords<'r>>,
    query_type: RecordType,
    query_name: &'q LowerName,
}

impl<'r, 'q> AnyRecordsIter<'r, 'q> {
    fn new(
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
        rrsets: Values<'r, RrKey, RecordSet>,
        query_type: RecordType,
        query_name: &'q LowerName,
    ) -> Self {
        AnyRecordsIter {
            is_secure,
            supported_algorithms,
            rrsets,
            rrset: None,
            records: None,
            query_type,
            query_name,
        }
    }
}

impl<'r, 'q> Iterator for AnyRecordsIter<'r, 'q> {
    type Item = &'r Record;

    fn next(&mut self) -> Option<Self::Item> {
        let query_type = self.query_type;
        let query_name = self.query_name;

        loop {
            if let Some(ref mut records) = self.records {
                let record = records
                    .by_ref()
                    .filter(|rr_set| {
                        query_type == RecordType::ANY || rr_set.record_type() != RecordType::SOA
                    }).find(|rr_set| {
                        query_type == RecordType::AXFR
                            || &LowerName::from(rr_set.name()) == query_name
                    });

                if record.is_some() {
                    return record;
                }
            }

            self.rrset = self.rrsets.next();

            // if there are no more RecordSets, then return
            self.rrset?;

            // getting here, we must have exhausted our records from the rrset
            self.records = Some(
                self.rrset
                    .expect("rrset should not be None at this point")
                    .records(self.is_secure, self.supported_algorithms),
            );
        }
    }
}

/// The result of a lookup
#[derive(Debug)]
pub enum LookupRecords<'r, 'q> {
    /// There is no record by the name
    NxDomain,
    /// There is no record for the given query, but there are other records at that name
    NameExists,
    /// The associate records
    RecordsIter(RrsetRecords<'r>),
    /// A generic lookup response where anything is desired
    AnyRecordsIter(AnyRecordsIter<'r, 'q>),
}

impl<'r, 'q> LookupRecords<'r, 'q> {
    /// This is an NxDomain or NameExists, and has no associated records
    ///
    /// this consumes the iterator, and verifies it is empty
    pub fn was_empty(self) -> bool {
        self.count() == 0
    }

    /// This is an NxDomain
    pub fn is_nx_domain(&self) -> bool {
        match *self {
            LookupRecords::NxDomain => true,
            _ => false,
        }
    }

    /// This is a NameExists
    pub fn is_name_exists(&self) -> bool {
        match *self {
            LookupRecords::NameExists => true,
            _ => false,
        }
    }
}

impl<'r, 'q> Iterator for LookupRecords<'r, 'q> {
    type Item = &'r Record;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            LookupRecords::NxDomain | LookupRecords::NameExists => None,
            LookupRecords::RecordsIter(ref mut i) => i.next(),
            LookupRecords::AnyRecordsIter(ref mut i) => i.next(),
        }
    }
}

impl<'r, 'q> From<RrsetRecords<'r>> for LookupRecords<'r, 'q> {
    fn from(rrset_records: RrsetRecords<'r>) -> Self {
        match rrset_records {
            RrsetRecords::Empty => LookupRecords::NxDomain,
            rrset_records => LookupRecords::RecordsIter(rrset_records),
        }
    }
}

impl<'r, 'q> From<AnyRecordsIter<'r, 'q>> for LookupRecords<'r, 'q> {
    fn from(rrset_records: AnyRecordsIter<'r, 'q>) -> Self {
        LookupRecords::AnyRecordsIter(rrset_records)
    }
}
