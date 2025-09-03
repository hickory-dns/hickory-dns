// Copyright 2015-2018 Benjamin Fry <benjaminfry -@- me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! SQLite serving with Dynamic DNS and journaling support

#[cfg(feature = "__dnssec")]
use std::fs;
use std::marker::PhantomData;
#[cfg(feature = "__dnssec")]
use std::str::FromStr;
use std::{
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    sync::Arc,
};

use futures_util::lock::Mutex;
use serde::Deserialize;
use tracing::{debug, error, info, warn};

#[cfg(feature = "metrics")]
use crate::store::metrics::PersistentStoreMetrics;
#[cfg(feature = "__dnssec")]
use crate::{
    dnssec::NxProofKind,
    proto::{
        dnssec::{
            DnsSecResult, SigSigner, TSigResponseContext, TSigner, Verifier,
            rdata::{
                DNSSECRData,
                key::KEY,
                tsig::{TsigAlgorithm, TsigError},
            },
        },
        op::MessageSignature,
    },
    zone_handler::{DnssecZoneHandler, Nsec3QueryInfo, UpdateRequest},
};
use crate::{
    error::{PersistenceError, PersistenceErrorKind},
    proto::{
        op::{ResponseCode, ResponseSigner},
        rr::{DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType, RrKey},
        runtime::{RuntimeProvider, TokioRuntimeProvider},
    },
    server::{Request, RequestInfo},
    store::{
        file::rooted,
        in_memory::{InMemoryZoneHandler, zone_from_path},
    },
    zone_handler::{
        AuthLookup, AxfrPolicy, LookupControlFlow, LookupError, LookupOptions, ZoneHandler,
        ZoneTransfer, ZoneType,
    },
};
#[cfg(feature = "__dnssec")]
use LookupControlFlow::Continue;

pub mod persistence;
pub use persistence::Journal;

/// SqliteZoneHandler is responsible for storing the resource records for a particular zone.
///
/// Zone handlers default to DNSClass IN. The ZoneType specifies if this should be treated as the
/// start of authority for the zone, is a Secondary, or a cached zone.
#[allow(dead_code)]
pub struct SqliteZoneHandler<P = TokioRuntimeProvider> {
    in_memory: InMemoryZoneHandler<P>,
    journal: Mutex<Option<Journal>>,
    axfr_policy: AxfrPolicy,
    allow_update: bool,
    is_dnssec_enabled: bool,
    #[cfg(feature = "metrics")]
    metrics: PersistentStoreMetrics,
    #[cfg(feature = "__dnssec")]
    tsig_signers: Vec<TSigner>,
    _phantom: PhantomData<P>,
}

impl<P: RuntimeProvider + Send + Sync> SqliteZoneHandler<P> {
    /// Creates a new ZoneHandler.
    ///
    /// # Arguments
    ///
    /// * `in_memory` - InMemoryZoneHandler for all records.
    /// * `axfr_policy` - A policy for determining if AXFR requests are allowed.
    /// * `allow_update` - If true, then this zone accepts dynamic updates.
    /// * `is_dnssec_enabled` - If true, then the zone will sign the zone with all registered keys,
    ///   (see `add_zone_signing_key()`)
    ///
    /// # Return value
    ///
    /// The new `ZoneHandler`.
    pub fn new(
        in_memory: InMemoryZoneHandler<P>,
        axfr_policy: AxfrPolicy,
        allow_update: bool,
        is_dnssec_enabled: bool,
    ) -> Self {
        Self {
            in_memory,
            journal: Mutex::new(None),
            axfr_policy,
            allow_update,
            is_dnssec_enabled,
            #[cfg(feature = "metrics")]
            metrics: PersistentStoreMetrics::new("sqlite"),
            #[cfg(feature = "__dnssec")]
            tsig_signers: Vec::new(),
            _phantom: PhantomData,
        }
    }

    /// load the zone handler from the configuration
    pub async fn try_from_config(
        origin: Name,
        zone_type: ZoneType,
        axfr_policy: AxfrPolicy,
        enable_dnssec: bool,
        root_dir: Option<&Path>,
        config: &SqliteConfig,
        #[cfg(feature = "__dnssec")] nx_proof_kind: Option<NxProofKind>,
    ) -> Result<Self, String> {
        let zone_name = origin;

        // to be compatible with previous versions, the extension might be zone, not jrnl
        let zone_path = rooted(&config.zone_path, root_dir);
        let journal_path = rooted(&config.journal_path, root_dir);

        #[cfg_attr(not(feature = "__dnssec"), allow(unused_mut))]
        let mut handler = if journal_path.exists() {
            // load the zone
            info!("recovering zone from journal: {journal_path:?}",);
            let journal = Journal::from_file(&journal_path)
                .map_err(|e| format!("error opening journal: {journal_path:?}: {e}"))?;

            let in_memory = InMemoryZoneHandler::empty(
                zone_name.clone(),
                zone_type,
                AxfrPolicy::AllowAll, // We apply our own AXFR policy before invoking the InMemoryZoneHandler.
                #[cfg(feature = "__dnssec")]
                nx_proof_kind,
            );
            let mut handler = Self::new(in_memory, axfr_policy, config.allow_update, enable_dnssec);

            handler
                .recover_with_journal(&journal)
                .await
                .map_err(|e| format!("error recovering from journal: {e}"))?;

            handler.set_journal(journal).await;
            info!("recovered zone: {zone_name}");

            handler
        } else if zone_path.exists() {
            // TODO: deprecate this portion of loading, instantiate the journal through a separate tool
            info!("loading zone file: {zone_path:?}");

            let records = zone_from_path(&zone_path, zone_name.clone())
                .map_err(|e| format!("failed to load zone file: {e}"))?;

            let in_memory = InMemoryZoneHandler::new(
                zone_name.clone(),
                records,
                zone_type,
                AxfrPolicy::AllowAll, // We apply our own AXFR policy before invoking the InMemoryZoneHandler.
                #[cfg(feature = "__dnssec")]
                nx_proof_kind,
            )?;

            let mut handler = Self::new(in_memory, axfr_policy, config.allow_update, enable_dnssec);

            // if dynamic update is enabled, enable the journal
            info!("creating new journal: {journal_path:?}");
            let journal = Journal::from_file(&journal_path)
                .map_err(|e| format!("error creating journal {journal_path:?}: {e}"))?;

            handler.set_journal(journal).await;

            // preserve to the new journal, i.e. we just loaded the zone from disk, start the journal
            handler
                .persist_to_journal()
                .await
                .map_err(|e| format!("error persisting to journal {journal_path:?}: {e}"))?;

            info!("zone file loaded: {zone_name}");
            handler
        } else {
            return Err(format!("no zone file or journal defined at: {zone_path:?}"));
        };

        #[cfg(feature = "__dnssec")]
        for config in &config.tsig_keys {
            handler.tsig_signers.push(config.to_signer(&zone_name)?);
        }

        Ok(handler)
    }

    /// Recovers the zone from a Journal, returns an error on failure to recover the zone.
    ///
    /// # Arguments
    ///
    /// * `journal` - the journal from which to load the persisted zone.
    pub async fn recover_with_journal(
        &mut self,
        journal: &Journal,
    ) -> Result<(), PersistenceError> {
        assert!(
            self.in_memory.records_get_mut().is_empty(),
            "records should be empty during a recovery"
        );

        info!("recovering from journal");
        for record in journal.iter() {
            // AXFR is special, it is used to mark the dump of a full zone.
            //  when recovering, if an AXFR is encountered, we should remove all the records in the
            //  zone.
            if record.record_type() == RecordType::AXFR {
                self.in_memory.clear();
            } else {
                match self.update_records(&[record], false).await {
                    Ok(_) => {
                        #[cfg(feature = "metrics")]
                        self.metrics.zone_records.increment(1);
                    }
                    Err(error) => return Err(PersistenceErrorKind::Recovery(error.to_str()).into()),
                }
            }
        }

        Ok(())
    }

    /// Persist the state of the current zone to the journal, does nothing if there is no associated
    ///  Journal.
    ///
    /// Returns an error if there was an issue writing to the persistence layer.
    pub async fn persist_to_journal(&self) -> Result<(), PersistenceError> {
        if let Some(journal) = self.journal.lock().await.as_ref() {
            let serial = self.in_memory.serial().await;

            info!("persisting zone to journal at SOA.serial: {serial}");

            // TODO: THIS NEEDS TO BE IN A TRANSACTION!!!
            journal.insert_record(
                serial,
                &Record::update0(Name::new(), 0, RecordType::AXFR).into_record_of_rdata(),
            )?;

            for rr_set in self.in_memory.records().await.values() {
                // TODO: should we preserve rr_sets or not?
                for record in rr_set.records_without_rrsigs() {
                    journal.insert_record(serial, record)?;

                    #[cfg(feature = "metrics")]
                    self.metrics.zone_records.increment(1);
                }
            }

            // TODO: COMMIT THE TRANSACTION!!!
        }

        Ok(())
    }

    /// Associate a backing Journal with this ZoneHandler for Updatable zones
    pub async fn set_journal(&mut self, journal: Journal) {
        *self.journal.lock().await = Some(journal);
    }

    /// Returns the associated Journal
    #[cfg(any(test, feature = "testing"))]
    pub async fn journal(&self) -> impl Deref<Target = Option<Journal>> + '_ {
        self.journal.lock().await
    }

    /// Enables the zone for dynamic DNS updates
    pub fn set_allow_update(&mut self, allow_update: bool) {
        self.allow_update = allow_update;
    }

    /// Set the TSIG signers allowed to authenticate updates when `allow_update` is true
    #[cfg(all(any(test, feature = "testing"), feature = "__dnssec"))]
    pub fn set_tsig_signers(&mut self, signers: Vec<TSigner>) {
        self.tsig_signers = signers;
    }

    /// Set the AXFR policy for testing purposes
    #[cfg(feature = "testing")]
    pub fn set_axfr_policy(&mut self, policy: AxfrPolicy) {
        self.axfr_policy = policy;
    }

    /// Get serial
    #[cfg(any(test, feature = "testing"))]
    pub async fn serial(&self) -> u32 {
        self.in_memory.serial().await
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
    pub async fn verify_prerequisites(
        &self,
        pre_requisites: &[Record],
    ) -> Result<(), ResponseCode> {
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
                warn!("ttl must be 0 for: {require:?}");
                return Err(ResponseCode::FormErr);
            }

            let origin = self.origin();
            if !origin.zone_of(&require.name().into()) {
                warn!("{} is not a zone_of {origin}", require.name());
                return Err(ResponseCode::NotZone);
            }

            match require.dns_class() {
                DNSClass::ANY => {
                    if let RData::Update0(_) | RData::NULL(..) = require.data() {
                        match require.record_type() {
                            // ANY      ANY      empty    Name is in use
                            RecordType::ANY => {
                                if self
                                    .lookup(
                                        &required_name,
                                        RecordType::ANY,
                                        None,
                                        LookupOptions::default(),
                                    )
                                    .await
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
                                if self
                                    .lookup(&required_name, rrset, None, LookupOptions::default())
                                    .await
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
                    if let RData::Update0(_) | RData::NULL(..) = require.data() {
                        match require.record_type() {
                            // NONE     ANY      empty    Name is not in use
                            RecordType::ANY => {
                                if !self
                                    .lookup(
                                        &required_name,
                                        RecordType::ANY,
                                        None,
                                        LookupOptions::default(),
                                    )
                                    .await
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
                                if !self
                                    .lookup(&required_name, rrset, None, LookupOptions::default())
                                    .await
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
                class if class == self.in_memory.class() =>
                // zone     rrset    rr       RRset exists (value dependent)
                {
                    if !self
                        .lookup(
                            &required_name,
                            require.record_type(),
                            None,
                            LookupOptions::default(),
                        )
                        .await
                        .unwrap_or_default()
                        .iter()
                        .any(|rr| rr == require)
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
    #[cfg(feature = "__dnssec")]
    pub async fn authorize_update(
        &self,
        request: &Request,
        now: u64,
    ) -> (Result<(), ResponseCode>, Option<Box<dyn ResponseSigner>>) {
        // 3.3.3 - Pseudocode for Permission Checking
        //
        //      if (security policy exists)
        //           if (this update is not permitted)
        //                if (local option)
        //                     log a message about permission problem
        //                if (local option)
        //                     return (REFUSED)

        // does this zone handler allow_updates?
        if !self.allow_update {
            warn!(
                "update attempted on non-updatable ZoneHandler: {}",
                self.origin()
            );
            return (Err(ResponseCode::Refused), None);
        }

        match request.signature() {
            MessageSignature::Sig0(sig0) => (self.authorized_sig0(sig0, request).await, None),
            MessageSignature::Tsig(tsig) => {
                let (resp, signer) = self.authorized_tsig(tsig, request, now).await;
                (resp, Some(signer))
            }
            MessageSignature::Unsigned => (Err(ResponseCode::Refused), None),
        }
    }

    /// Checks that an AXFR `Request` has a valid signature, or returns an error
    async fn authorize_axfr(
        &self,
        _request: &Request,
        _now: u64,
    ) -> (Result<(), ResponseCode>, Option<Box<dyn ResponseSigner>>) {
        match self.axfr_policy {
            // Deny without checking any signatures.
            AxfrPolicy::Deny => (Err(ResponseCode::Refused), None),
            // Allow without checking any signatures.
            AxfrPolicy::AllowAll => (Ok(()), None),
            // Allow only if a valid signature is present.
            #[cfg(feature = "__dnssec")]
            AxfrPolicy::AllowSigned => match _request.signature() {
                MessageSignature::Sig0(sig0) => (self.authorized_sig0(sig0, _request).await, None),
                MessageSignature::Tsig(tsig) => {
                    let (resp, signer) = self.authorized_tsig(tsig, _request, _now).await;
                    (resp, Some(signer))
                }
                MessageSignature::Unsigned => {
                    warn!("AXFR request was not signed");
                    (Err(ResponseCode::Refused), None)
                }
            },
        }
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
    pub async fn pre_scan(&self, records: &[Record]) -> Result<(), ResponseCode> {
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
            if class == self.in_memory.class() {
                match rr.record_type() {
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

                        match rr.data() {
                            RData::Update0(_) | RData::NULL(..) => {}
                            _ => return Err(ResponseCode::FormErr),
                        }

                        match rr.record_type() {
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
                        match rr.record_type() {
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
    ///   should be disabled during recovery.
    pub async fn update_records(
        &self,
        records: &[Record],
        auto_signing_and_increment: bool,
    ) -> Result<bool, ResponseCode> {
        let mut updated = false;
        let serial: u32 = self.in_memory.serial().await;

        // the persistence act as a write-ahead log. The WAL will also be used for recovery of a zone
        //  subsequent to a failure of the server.
        if let Some(journal) = &*self.journal.lock().await {
            if let Err(error) = journal.insert_records(serial, records) {
                error!("could not persist update records: {error}");
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
            let rr_key = RrKey::new(rr_name.clone(), rr.record_type());

            match rr.dns_class() {
                class if class == self.in_memory.class() => {
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
                    info!("upserting record: {rr:?}");
                    let upserted = self.in_memory.upsert(rr.clone(), serial).await;

                    #[cfg(all(feature = "metrics", feature = "__dnssec"))]
                    if auto_signing_and_increment {
                        if upserted {
                            self.metrics.added();
                        } else {
                            self.metrics.updated();
                        }
                    }

                    updated = upserted || updated
                }
                DNSClass::ANY => {
                    // This is a delete of entire RRSETs, either many or one. In either case, the spec is clear:
                    match rr.record_type() {
                        t @ RecordType::SOA | t @ RecordType::NS if rr_name == *self.origin() => {
                            // SOA and NS records are not to be deleted if they are the origin records
                            info!("skipping delete of {t:?} see RFC 2136 - 3.4.2.3");
                            continue;
                        }
                        RecordType::ANY => {
                            // RFC 2136 - 3.4.2.3. For any Update RR whose CLASS is ANY and whose TYPE is ANY,
                            //   all Zone RRs with the same NAME are deleted, unless the NAME is the
                            //   same as ZNAME in which case only those RRs whose TYPE is other than
                            //   SOA or NS are deleted.

                            // ANY      ANY      empty    Delete all RRsets from a name
                            info!(
                                "deleting all records at name (not SOA or NS at origin): {rr_name:?}"
                            );
                            let origin = self.origin();

                            let mut records = self.in_memory.records_mut().await;
                            let old_size = records.len();
                            records.retain(|k, _| {
                                k.name != rr_name
                                    || ((k.record_type == RecordType::SOA
                                        || k.record_type == RecordType::NS)
                                        && k.name != *origin)
                            });
                            let new_size = records.len();
                            drop(records);

                            if new_size < old_size {
                                updated = true;
                            }

                            #[cfg(all(feature = "metrics", feature = "__dnssec"))]
                            for _ in 0..old_size - new_size {
                                if auto_signing_and_increment {
                                    self.metrics.deleted()
                                }
                            }
                        }
                        _ => {
                            // RFC 2136 - 3.4.2.3. For any Update RR whose CLASS is ANY and
                            //   whose TYPE is not ANY all Zone RRs with the same NAME and TYPE are
                            //   deleted, unless the NAME is the same as ZNAME in which case neither
                            //   SOA or NS RRs will be deleted.

                            // ANY      rrset    empty    Delete an RRset
                            if let RData::Update0(_) | RData::NULL(..) = rr.data() {
                                let deleted = self.in_memory.records_mut().await.remove(&rr_key);
                                info!("deleted rrset: {deleted:?}");
                                updated = updated || deleted.is_some();

                                #[cfg(all(feature = "metrics", feature = "__dnssec"))]
                                if auto_signing_and_increment {
                                    self.metrics.deleted()
                                }
                            } else {
                                info!("expected empty rdata: {rr:?}");
                                return Err(ResponseCode::FormErr);
                            }
                        }
                    }
                }
                DNSClass::NONE => {
                    info!("deleting specific record: {rr:?}");
                    // NONE     rrset    rr       Delete an RR from an RRset
                    if let Some(rrset) = self.in_memory.records_mut().await.get_mut(&rr_key) {
                        // b/c this is an Arc, we need to clone, then remove, and replace the node.
                        let mut rrset_clone: RecordSet = RecordSet::clone(&*rrset);
                        let deleted = rrset_clone.remove(rr, serial);
                        info!("deleted ({deleted}) specific record: {rr:?}");
                        updated = updated || deleted;

                        if deleted {
                            *rrset = Arc::new(rrset_clone);
                        }

                        #[cfg(all(feature = "metrics", feature = "__dnssec"))]
                        if auto_signing_and_increment {
                            self.metrics.deleted()
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
                cfg_if::cfg_if! {
                    if #[cfg(feature = "__dnssec")] {
                        self.secure_zone().await.map_err(|error| {
                            error!(%error, "failure securing zone");
                            ResponseCode::ServFail
                        })?
                    } else {
                        error!("failure securing zone, dnssec feature not enabled");
                        return Err(ResponseCode::ServFail)
                    }
                }
            } else {
                // the secure_zone() function increments the SOA during it's operation, if we're not
                //  dnssec, then we need to do it here...
                self.in_memory.increment_soa_serial().await;
            }
        }

        Ok(updated)
    }

    #[cfg(feature = "__dnssec")]
    async fn authorized_sig0(&self, sig0: &Record, request: &Request) -> Result<(), ResponseCode> {
        debug!("authorizing with: {sig0:?}");

        let Some(sig0) = sig0.data().as_dnssec().and_then(DNSSECRData::as_sig) else {
            warn!("no sig0 matched registered records: id {}", request.id());
            return Err(ResponseCode::Refused);
        };

        let name = LowerName::from(&sig0.input().signer_name);

        let Continue(Ok(keys)) = self
            .lookup(&name, RecordType::KEY, None, LookupOptions::default())
            .await
        else {
            warn!("no sig0 key name matched: id {}", request.id());
            return Err(ResponseCode::Refused);
        };

        debug!("found keys {keys:?}");
        let verified = keys
            .iter()
            .filter_map(|rr_set| rr_set.data().as_dnssec().and_then(DNSSECRData::as_key))
            .any(
                |key| match key.verify_message(&request.message, sig0.sig(), sig0.input()) {
                    Ok(_) => {
                        info!("verified sig: {sig0:?} with key: {key:?}");
                        true
                    }
                    Err(_) => {
                        debug!("did not verify sig: {sig0:?} with key: {key:?}");
                        false
                    }
                },
            );
        match verified {
            true => Ok(()),
            false => {
                warn!("invalid sig0 signature: id {}", request.id());
                Err(ResponseCode::Refused)
            }
        }
    }

    #[cfg(feature = "__dnssec")]
    async fn authorized_tsig(
        &self,
        tsig: &Record,
        request: &Request,
        now: u64,
    ) -> (Result<(), ResponseCode>, Box<dyn ResponseSigner>) {
        let req_id = request.header().id();
        let cx = TSigResponseContext::new(req_id, now);

        debug!("authorizing with: {tsig:?}");
        let Some(tsigner) = self
            .tsig_signers
            .iter()
            .find(|tsigner| tsigner.signer_name() == tsig.name())
        else {
            warn!("no TSIG key name matched: id {req_id}");
            return (
                Err(ResponseCode::NotAuth),
                cx.unknown_key(tsig.name().clone()),
            );
        };

        let Ok((_, _, range)) = tsigner.verify_message_byte(request.as_slice(), None, true) else {
            warn!("invalid TSIG signature: id {req_id}");
            return (
                Err(ResponseCode::NotAuth),
                cx.bad_signature(tsigner.clone()),
            );
        };

        let mut error = None;
        let mut response = Ok(());

        if !range.contains(&now) {
            warn!("expired TSIG signature: id {req_id}");
            // "A response indicating a BADTIME error MUST be signed by the same key as the request."
            response = Err(ResponseCode::NotAuth);
            error = Some(TsigError::BadTime);
        }

        // Unwrap safety: verify_message_byte() has already successfully extracted & parsed the
        // TSIG RR.
        let req_tsig = tsig
            .data()
            .as_dnssec()
            .and_then(DNSSECRData::as_tsig)
            .unwrap();
        (response, cx.sign(req_tsig, error, tsigner.clone()))
    }
}

impl<P> Deref for SqliteZoneHandler<P> {
    type Target = InMemoryZoneHandler<P>;

    fn deref(&self) -> &Self::Target {
        &self.in_memory
    }
}

impl<P> DerefMut for SqliteZoneHandler<P> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.in_memory
    }
}

#[async_trait::async_trait]
impl<P: RuntimeProvider + Send + Sync> ZoneHandler for SqliteZoneHandler<P> {
    /// What type is this zone
    fn zone_type(&self) -> ZoneType {
        self.in_memory.zone_type()
    }

    /// Return a policy that can be used to determine how AXFR requests should be handled.
    fn axfr_policy(&self) -> AxfrPolicy {
        self.axfr_policy
    }

    /// Takes the UpdateMessage, extracts the Records, and applies the changes to the record set.
    ///
    /// # Arguments
    ///
    /// * `update` - The `UpdateMessage` records will be extracted and used to perform the update
    ///              actions as specified in the above RFC.
    ///
    /// # Return value
    ///
    /// Always returns `Err(NotImp)` if DNSSEC is disabled. Returns `Ok(true)` if any of additions,
    /// updates or deletes were made to the zone, false otherwise. Err is returned in the case of
    /// bad data, etc.
    ///
    /// See [RFC 2136](https://datatracker.ietf.org/doc/html/rfc2136#section-3) section 3.4 for
    /// details.
    async fn update(
        &self,
        _request: &Request,
        _now: u64,
    ) -> (Result<bool, ResponseCode>, Option<Box<dyn ResponseSigner>>) {
        #[cfg(feature = "__dnssec")]
        {
            // the spec says to authorize after prereqs, seems better to auth first.
            let signer = match self.authorize_update(_request, _now).await {
                (Err(e), signer) => return (Err(e), signer),
                (_, signer) => signer,
            };

            if let Err(code) = self.verify_prerequisites(_request.prerequisites()).await {
                return (Err(code), signer);
            }

            if let Err(code) = self.pre_scan(_request.updates()).await {
                return (Err(code), signer);
            }

            (self.update_records(_request.updates(), true).await, signer)
        }
        #[cfg(not(feature = "__dnssec"))]
        {
            // if we don't have dnssec, we can't do updates.
            (Err(ResponseCode::NotImp), None)
        }
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName {
        self.in_memory.origin()
    }

    /// Looks up all Resource Records matching the given `Name` and `RecordType`.
    ///
    /// # Arguments
    ///
    /// * `name` - The name to look up.
    /// * `rtype` - The `RecordType` to look up. `RecordType::ANY` will return all records matching
    ///             `name`. `RecordType::AXFR` will return all record types except `RecordType::SOA`
    ///             due to the requirements that on zone transfers the `RecordType::SOA` must both
    ///             precede and follow all other records.
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///                      algorithms, etc.)
    ///
    /// # Return value
    ///
    /// A LookupControlFlow containing the lookup that should be returned to the client.
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.in_memory
            .lookup(name, rtype, request_info, lookup_options)
            .await
    }

    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (
        LookupControlFlow<AuthLookup>,
        Option<Box<dyn ResponseSigner>>,
    ) {
        let request_info = match request.request_info() {
            Ok(info) => info,
            Err(e) => return (LookupControlFlow::Break(Err(e)), None),
        };

        if request_info.query.query_type() == RecordType::AXFR {
            return (
                LookupControlFlow::Break(Err(LookupError::ProtoError(
                    "AXFR must be handled with ZoneHandler::zone_transfer()".into(),
                ))),
                None,
            );
        }

        let (search, _) = self.in_memory.search(request, lookup_options).await;

        (search, None)
    }

    async fn zone_transfer(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
        now: u64,
    ) -> Option<(
        Result<ZoneTransfer, LookupError>,
        Option<Box<dyn ResponseSigner>>,
    )> {
        let (resp, signer) = self.authorize_axfr(request, now).await;
        if let Err(code) = resp {
            warn!(axfr_policy = ?self.axfr_policy, "rejected AXFR");
            return Some((Err(LookupError::ResponseCode(code)), signer));
        }
        debug!(axfr_policy = ?self.axfr_policy, "authorized AXFR");

        let (zone_transfer, _) = self
            .in_memory
            .zone_transfer(request, lookup_options, now)
            .await?;

        Some((zone_transfer, signer))
    }

    /// Return the NSEC records based on the given name
    ///
    /// # Arguments
    ///
    /// * `name` - given this name (i.e. the lookup name), return the NSEC record that is less than
    ///            this
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///                      algorithms, etc.)
    async fn nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.in_memory.nsec_records(name, lookup_options).await
    }

    #[cfg(feature = "__dnssec")]
    async fn nsec3_records(
        &self,
        info: Nsec3QueryInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.in_memory.nsec3_records(info, lookup_options).await
    }

    #[cfg(feature = "__dnssec")]
    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        self.in_memory.nx_proof_kind()
    }

    #[cfg(feature = "metrics")]
    fn metrics_label(&self) -> &'static str {
        "sqlite"
    }
}

#[cfg(feature = "__dnssec")]
#[async_trait::async_trait]
impl<P: RuntimeProvider + Send + Sync> DnssecZoneHandler for SqliteZoneHandler<P> {
    async fn add_update_auth_key(&self, name: Name, key: KEY) -> DnsSecResult<()> {
        self.in_memory.add_update_auth_key(name, key).await
    }

    /// By adding a secure key, this will implicitly enable dnssec for the zone.
    ///
    /// # Arguments
    ///
    /// * `signer` - Signer with associated private key
    async fn add_zone_signing_key(&self, signer: SigSigner) -> DnsSecResult<()> {
        self.in_memory.add_zone_signing_key(signer).await
    }

    /// (Re)generates the nsec records, increments the serial number and signs the zone
    async fn secure_zone(&self) -> DnsSecResult<()> {
        self.in_memory.secure_zone().await
    }
}

/// Configuration for zone file for sqlite based zones
#[derive(Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct SqliteConfig {
    /// path to initial zone file
    pub zone_path: PathBuf,
    /// path to the sqlite journal file
    pub journal_path: PathBuf,
    /// Are updates allowed to this zone
    #[serde(default)]
    pub allow_update: bool,
    /// TSIG keys allowed to authenticate updates if `allow_update` is true
    #[cfg(feature = "__dnssec")]
    #[serde(default)]
    pub tsig_keys: Vec<TsigKeyConfig>,
}

/// Configuration for a TSIG authentication signer key
#[derive(Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
#[cfg(feature = "__dnssec")]
pub struct TsigKeyConfig {
    /// The key name
    pub name: String,
    /// A path to the unencoded symmetric HMAC key data
    pub key_file: PathBuf,
    /// The key algorithm
    pub algorithm: TsigAlgorithm,
    /// Allowed +/- difference (in seconds) between the time a TSIG request was signed
    /// and when it is verified.
    ///
    /// A fudge value that is too large may leave the server open to replay attacks.
    /// A fudge value that is too small may cause failures from latency and clock
    /// desynchronization.
    ///
    /// RFC 8945 recommends a fudge value of 300 seconds (the default if not specified).
    #[serde(default = "default_fudge")]
    pub fudge: u16,
}

#[cfg(feature = "__dnssec")]
impl TsigKeyConfig {
    fn to_signer(&self, zone_name: &Name) -> Result<TSigner, String> {
        let key_data = fs::read(&self.key_file).map_err(|e| {
            format!(
                "error reading TSIG key file: {}: {e}",
                self.key_file.display()
            )
        })?;
        let signer_name = Name::from_str(&self.name).unwrap_or(zone_name.clone());

        TSigner::new(key_data, self.algorithm.clone(), signer_name, self.fudge)
            .map_err(|e| format!("invalid TSIG key configuration: {e}"))
    }
}

/// Default TSIG fudge value (seconds).
///
/// Per RFC 8945 §10:
///   "The RECOMMENDED value in most situations is 300 seconds."
#[cfg(feature = "__dnssec")]
pub(crate) fn default_fudge() -> u16 {
    300
}

#[cfg(test)]
#[allow(clippy::extra_unused_type_parameters)]
mod tests {
    use crate::store::sqlite::SqliteZoneHandler;

    #[test]
    fn test_is_send_sync() {
        fn send_sync<T: Send + Sync>() -> bool {
            true
        }

        assert!(send_sync::<SqliteZoneHandler>());
    }
}
