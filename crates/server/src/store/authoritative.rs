//! Authoritative zone data

use std::{collections::BTreeMap, marker::PhantomData, ops::Deref, sync::Arc};

use async_trait::async_trait;
#[cfg(feature = "__dnssec")]
use time::OffsetDateTime;
#[cfg(all(feature = "__dnssec", feature = "testing"))]
use tokio::sync::RwLockWriteGuard;
use tokio::sync::{RwLock, RwLockReadGuard};
use tracing::{debug, error, info, warn};

#[cfg(feature = "metrics")]
use crate::store::metrics::PersistentStoreMetrics;
use crate::{
    authority::{
        AuthLookup, Authority, AxfrPolicy, AxfrRecords, LookupControlFlow, LookupError,
        LookupOptions, LookupRecords, UpdateResult, ZoneTransfer, ZoneType,
    },
    proto::{
        op::{ResponseCode, message::ResponseSigner},
        rr::{DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType, RrKey},
        runtime::RuntimeProvider,
    },
    server::{Request, RequestInfo},
    store::{StoreBackend, StoreBackendExt},
};
#[cfg(feature = "__dnssec")]
use crate::{
    authority::{DnssecAuthority, Nsec3QueryInfo, UpdateRequest},
    dnssec::NxProofKind,
    proto::{
        dnssec::{
            DnsSecResult, SigSigner, TSigResponseContext, TSigner, Verifier,
            rdata::{DNSKEY, DNSSECRData, KEY, tsig::TsigError},
        },
        op::MessageSignature,
        runtime::Time,
    },
};

/// Serves an authoritative zone.
pub struct AuthoritativeAuthority<B, P> {
    origin: LowerName,
    class: DNSClass,
    pub(super) backend: RwLock<B>,
    /// Indicates if this is a primary or secondary server for this zone.
    zone_type: ZoneType,
    axfr_policy: AxfrPolicy,
    allow_update: bool,
    /// Indicates whether the zone should be re-signed after each UPDATE.
    ///
    /// This is irrelevant for read-only zones.
    is_dnssec_enabled: bool,

    #[cfg(feature = "__dnssec")]
    nx_proof_kind: Option<NxProofKind>,
    #[cfg(feature = "__dnssec")]
    pub(super) tsig_signers: Vec<TSigner>,

    #[cfg(feature = "metrics")]
    #[allow(unused)]
    pub(super) metrics: PersistentStoreMetrics,
    #[cfg(feature = "metrics")]
    metrics_label: &'static str,

    _phantom: PhantomData<P>,
}

impl<B: StoreBackend + Send + Sync, P: RuntimeProvider> AuthoritativeAuthority<B, P> {
    /// Construct an authority from a storage backend and other configuration.
    pub fn new(
        origin: Name,
        store: B,
        zone_type: ZoneType,
        axfr_policy: AxfrPolicy,
        allow_update: bool,
        enable_dnssec: bool,
        #[cfg(feature = "__dnssec")] nx_proof_kind: Option<NxProofKind>,
    ) -> Self {
        #[cfg(feature = "metrics")]
        let metrics_label = store.metrics_label();
        #[cfg(feature = "metrics")]
        let metrics = PersistentStoreMetrics::new(metrics_label);
        Self {
            origin: origin.into(),
            class: DNSClass::IN,
            backend: RwLock::new(store),
            zone_type,
            axfr_policy,
            allow_update,
            is_dnssec_enabled: enable_dnssec,

            #[cfg(feature = "__dnssec")]
            nx_proof_kind,
            #[cfg(feature = "__dnssec")]
            tsig_signers: Vec::new(),

            #[cfg(feature = "metrics")]
            metrics,
            #[cfg(feature = "metrics")]
            metrics_label,

            _phantom: PhantomData,
        }
    }

    /// Get a reference to the records.
    pub async fn records(&self) -> impl Deref<Target = BTreeMap<RrKey, Arc<RecordSet>>> + '_ {
        RwLockReadGuard::map(self.backend.read().await, |backend| backend.records())
    }

    /// Get a mutable reference to the records.
    pub fn records_mut(&mut self) -> &mut BTreeMap<RrKey, Arc<RecordSet>> {
        self.backend.get_mut().records_mut()
    }

    /// Get the DNS class of the zone.
    pub fn class(&self) -> DNSClass {
        self.class
    }

    /// Enables the zone for dynamic DNS updates.
    pub fn set_allow_update(&mut self, allow_update: bool) {
        self.allow_update = allow_update;
    }

    /// Set the TSIG signers allowed to authenticate updates when `allow_update` is true.
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
    pub async fn serial(&self) -> u32 {
        self.backend.read().await.serial(&self.origin)
    }

    /// Retrieve the Signer, which contains the private keys, for this zone
    #[cfg(all(feature = "__dnssec", feature = "testing"))]
    pub async fn secure_keys(&self) -> impl Deref<Target = Vec<SigSigner>> + '_ {
        RwLockWriteGuard::map(self.backend.write().await, |backend| {
            backend.secure_keys_mut()
        })
    }

    /// Non-async version of upsert when behind a mutable reference.
    pub fn upsert_mut(&mut self, record: Record, serial: u32) -> bool {
        self.backend.get_mut().upsert(record, serial, self.class)
    }

    /// Add a (Sig0) key that is authorized to perform updates against this authority.
    #[cfg(feature = "__dnssec")]
    fn inner_add_update_auth_key(
        backend: &mut B,
        name: Name,
        key: KEY,
        origin: &LowerName,
        dns_class: DNSClass,
    ) -> DnsSecResult<()> {
        let rdata = RData::DNSSEC(DNSSECRData::KEY(key));
        // TODO: what TTL?
        let record = Record::from_rdata(name, 86400, rdata);

        let serial = backend.serial(origin);
        if backend.upsert(record, serial, dns_class) {
            Ok(())
        } else {
            Err("failed to add auth key".into())
        }
    }

    /// Non-async method of add_update_auth_key when behind a mutable reference.
    #[cfg(feature = "__dnssec")]
    pub fn add_update_auth_key_mut(&mut self, name: Name, key: KEY) -> DnsSecResult<()> {
        Self::inner_add_update_auth_key(self.backend.get_mut(), name, key, &self.origin, self.class)
    }

    /// By adding a secure key, this will implicitly enable dnssec for the zone.
    #[cfg(feature = "__dnssec")]
    fn inner_add_zone_signing_key(
        backend: &mut B,
        signer: SigSigner,
        origin: &LowerName,
        dns_class: DNSClass,
    ) -> DnsSecResult<()> {
        // also add the key to the zone
        let zone_ttl = backend.minimum_ttl(origin);
        let dnskey = DNSKEY::from_key(&signer.key().to_public_key()?);
        let dnskey = Record::from_rdata(
            origin.clone().into(),
            zone_ttl,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
        );

        // TODO: also generate the CDS and CDNSKEY
        let serial = backend.serial(origin);
        backend.upsert(dnskey, serial, dns_class);
        backend.secure_keys_mut().push(signer);
        Ok(())
    }

    /// Non-async method of add_zone_signing_key when behind a mutable reference
    #[cfg(feature = "__dnssec")]
    pub fn add_zone_signing_key_mut(&mut self, signer: SigSigner) -> DnsSecResult<()> {
        Self::inner_add_zone_signing_key(self.backend.get_mut(), signer, &self.origin, self.class)
    }

    /// (Re)generates the nsec records, increments the serial number and signs the zone
    #[cfg(feature = "__dnssec")]
    pub fn secure_zone_mut(&mut self) -> DnsSecResult<()> {
        self.backend.get_mut().secure_zone_mut(
            &self.origin,
            self.class,
            self.nx_proof_kind.as_ref(),
            Self::current_time()?,
        )
    }

    #[cfg(feature = "__dnssec")]
    fn current_time() -> DnsSecResult<OffsetDateTime> {
        let timestamp_unsigned = P::Timer::current_time();
        let timestamp_signed = timestamp_unsigned
            .try_into()
            .map_err(|_| "current time is out of range")?;
        OffsetDateTime::from_unix_timestamp(timestamp_signed)
            .map_err(|_| "current time is out of range".into())
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
    ) -> UpdateResult<bool> {
        let mut updated = false;
        let mut backend = self.backend.write().await;
        let serial = backend.serial(self.origin());

        // the persistence act as a write-ahead log. The WAL will also be used for recovery of a zone
        //  subsequent to a failure of the server.
        #[cfg(feature = "sqlite")]
        if let Some(journal) = backend.journal() {
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
                    info!("upserting record: {rr:?}");
                    let upserted = backend.upsert(rr.clone(), serial, self.class);

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

                            let records = backend.records_mut();
                            let old_size = records.len();
                            records.retain(|k, _| {
                                k.name != rr_name
                                    || ((k.record_type == RecordType::SOA
                                        || k.record_type == RecordType::NS)
                                        && k.name != *origin)
                            });
                            let new_size = records.len();

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
                                let deleted = backend.records_mut().remove(&rr_key);
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
                    if let Some(rrset) = backend.records_mut().get_mut(&rr_key) {
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
                        let time = Self::current_time()
                            .map_err(|error| {
                                error!(%error, "failure getting current time");
                                ResponseCode::ServFail
                            })?;
                        backend
                            .secure_zone_mut(
                                &self.origin,
                                self.class,
                                self.nx_proof_kind.as_ref(),
                                time,
                            )
                            .map_err(|error| {
                                error!(%error, "failure securing zone");
                                ResponseCode::ServFail
                            })?;
                    } else {
                        error!("failure securing zone, dnssec feature not enabled");
                        return Err(ResponseCode::ServFail)
                    }
                }
            } else {
                // the secure_zone() function increments the SOA during it's operation, if we're not
                //  dnssec, then we need to do it here...
                backend.increment_soa_serial(&self.origin, self.class);
            }
        }

        Ok(updated)
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
    pub async fn verify_prerequisites(&self, pre_requisites: &[Record]) -> UpdateResult<()> {
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
                class if class == self.class =>
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
    ) -> (UpdateResult<()>, Option<Box<dyn ResponseSigner>>) {
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
            return (Err(ResponseCode::Refused), None);
        }

        match request.signature() {
            MessageSignature::Sig0(sig0) => (self.authorized_sig0(sig0, request).await, None),
            MessageSignature::Tsig(tsig) => {
                let (resp, signer) = self.authorized_tsig(tsig, request).await;
                (resp, Some(signer))
            }
            MessageSignature::Unsigned => (Err(ResponseCode::Refused), None),
        }
    }

    /// Checks that an AXFR `Request` has a valid signature, or returns an error
    async fn authorize_axfr(
        &self,
        _request: &Request,
    ) -> (Result<(), ResponseCode>, Option<Box<dyn ResponseSigner>>) {
        match self.axfr_policy {
            // Deny without checking any signatures.
            AxfrPolicy::Deny => (Err(ResponseCode::NotAuth), None),
            // Allow without checking any signatures.
            AxfrPolicy::AllowAll => (Ok(()), None),
            // Allow only if a valid signature is present.
            #[cfg(feature = "__dnssec")]
            AxfrPolicy::AllowSigned => match _request.signature() {
                MessageSignature::Sig0(sig0) => (self.authorized_sig0(sig0, _request).await, None),
                MessageSignature::Tsig(tsig) => {
                    let (resp, signer) = self.authorized_tsig(tsig, _request).await;
                    (resp, Some(signer))
                }
                MessageSignature::Unsigned => {
                    warn!("AXFR request was not signed");
                    (Err(ResponseCode::NotAuth), None)
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
    pub async fn pre_scan(&self, records: &[Record]) -> UpdateResult<()> {
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

    #[cfg(feature = "__dnssec")]
    async fn authorized_sig0(&self, sig0: &Record, request: &Request) -> UpdateResult<()> {
        debug!("authorizing with: {sig0:?}");

        let Some(sig0) = sig0.data().as_dnssec().and_then(DNSSECRData::as_sig) else {
            warn!("no sig0 matched registered records: id {}", request.id());
            return Err(ResponseCode::Refused);
        };

        let name = LowerName::from(&sig0.input().signer_name);

        let LookupControlFlow::Continue(Ok(keys)) = self
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
    ) -> (UpdateResult<()>, Box<dyn ResponseSigner>) {
        let req_id = request.header().id();
        let now = P::Timer::current_time();
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

    /// Returns a reference to the storage backend of this zone.
    #[cfg(feature = "testing")]
    pub async fn backend(&self) -> impl Deref<Target = B> + '_ {
        self.backend.read().await
    }
}

#[async_trait]
impl<B: StoreBackend + Send + Sync, P: RuntimeProvider + Send + Sync> Authority
    for AuthoritativeAuthority<B, P>
{
    fn zone_type(&self) -> ZoneType {
        self.zone_type
    }

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
    ) -> (UpdateResult<bool>, Option<Box<dyn ResponseSigner>>) {
        #[cfg(feature = "__dnssec")]
        {
            // the spec says to authorize after prereqs, seems better to auth first.

            let signer = match self.authorize_update(_request).await {
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

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    async fn lookup(
        &self,
        name: &LowerName,
        mut query_type: RecordType,
        _request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        let backend = self.backend.read().await;

        if query_type == RecordType::AXFR {
            return LookupControlFlow::Break(Err(LookupError::ProtoError(
                "AXFR must be handled with Authority::zone_transfer()".into(),
            )));
        }

        if query_type == RecordType::ANY {
            query_type = backend.replace_any(name);
        }

        let answer = backend.inner_lookup(name, query_type, lookup_options);

        // evaluate any cnames for additional inclusion
        let additionals_root_chain_type: Option<(_, _)> = answer
            .as_ref()
            .and_then(|a| maybe_next_name(a, query_type))
            .and_then(|(search_name, search_type)| {
                backend
                    .additional_search(name, query_type, search_name, search_type, lookup_options)
                    .map(|adds| (adds, search_type))
            });

        // if the chain started with an ANAME, take the A or AAAA record from the list
        let (additionals, answer) = match (additionals_root_chain_type, answer, query_type) {
            (Some((additionals, RecordType::ANAME)), Some(answer), RecordType::A)
            | (Some((additionals, RecordType::ANAME)), Some(answer), RecordType::AAAA) => {
                // This should always be true...
                debug_assert_eq!(answer.record_type(), RecordType::ANAME);

                // in the case of ANAME the final record should be the A or AAAA record
                let (rdatas, a_aaaa_ttl) = {
                    let last_record = additionals.last();
                    let a_aaaa_ttl = last_record.map_or(u32::MAX, |r| r.ttl());

                    // grap the rdatas
                    let rdatas: Option<Vec<RData>> = last_record
                        .and_then(|record| match record.record_type() {
                            RecordType::A | RecordType::AAAA => {
                                // the RRSIGS will be useless since we're changing the record type
                                Some(record.records_without_rrsigs())
                            }
                            _ => None,
                        })
                        .map(|records| records.map(Record::data).cloned().collect::<Vec<_>>());

                    (rdatas, a_aaaa_ttl)
                };

                // now build up a new RecordSet
                //   the name comes from the ANAME record
                //   according to the rfc the ttl is from the ANAME
                //   TODO: technically we should take the min of the potential CNAME chain
                let ttl = answer.ttl().min(a_aaaa_ttl);
                let mut new_answer = RecordSet::new(answer.name().clone(), query_type, ttl);

                for rdata in rdatas.into_iter().flatten() {
                    new_answer.add_rdata(rdata);
                }

                // if DNSSEC is enabled, and the request had the DO set, sign the recordset
                #[cfg(feature = "__dnssec")]
                // ANAME's are constructed on demand, so need to be signed before return
                if lookup_options.dnssec_ok {
                    let result = Self::current_time().and_then(|time| {
                        B::sign_rrset(
                            &mut new_answer,
                            backend.secure_keys(),
                            backend.minimum_ttl(self.origin()),
                            self.class,
                            time,
                        )
                    });
                    if let Err(error) = result {
                        // rather than failing the request, we'll just warn
                        warn!(%error, "failed to sign ANAME record")
                    }
                }

                // prepend answer to additionals here (answer is the ANAME record)
                let additionals = std::iter::once(answer).chain(additionals).collect();

                // return the new answer
                //   because the searched set was an Arc, we need to arc too
                (Some(additionals), Some(Arc::new(new_answer)))
            }
            (Some((additionals, _)), answer, _) => (Some(additionals), answer),
            (None, answer, _) => (None, answer),
        };

        // This is annoying. The 1035 spec literally specifies that most DNS authorities would want to store
        //   records in a list except when there are a lot of records. But this makes indexed lookups by name+type
        //   always return empty sets. This is only important in the negative case, where other DNS authorities
        //   generally return NoError and no results when other types exist at the same name. bah.
        // TODO: can we get rid of this?
        use LookupControlFlow::*;
        let answers = match answer {
            Some(rr_set) => LookupRecords::new(lookup_options, rr_set),
            None => {
                return Continue(Err(
                    if backend
                        .records()
                        .keys()
                        .any(|key| key.name() == name || name.zone_of(key.name()))
                    {
                        LookupError::NameExists
                    } else {
                        LookupError::from(match self.origin().zone_of(name) {
                            true => ResponseCode::NXDomain,
                            false => ResponseCode::Refused,
                        })
                    },
                ));
            }
        };

        LookupControlFlow::Continue(Ok(AuthLookup::answers(
            answers,
            additionals.map(|a| LookupRecords::many(lookup_options, a)),
        )))
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
            Err(e) => return (LookupControlFlow::Break(Err(LookupError::from(e))), None),
        };
        debug!(
            "searching AuthoritativeAuthority for: {}",
            request_info.query
        );

        let lookup_name = request_info.query.name();
        let record_type: RecordType = request_info.query.query_type();

        // perform the actual lookup
        match record_type {
            RecordType::SOA => (
                self.lookup(
                    self.origin(),
                    record_type,
                    Some(&request_info),
                    lookup_options,
                )
                .await,
                None,
            ),
            RecordType::AXFR => (
                LookupControlFlow::Break(Err(LookupError::ProtoError(
                    "AXFR must be handled with Authority::zone_transfer()".into(),
                ))),
                None,
            ),
            // A standard Lookup path
            _ => (
                self.lookup(
                    lookup_name,
                    record_type,
                    Some(&request_info),
                    lookup_options,
                )
                .await,
                None,
            ),
        }
    }

    async fn zone_transfer(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> Option<(
        Result<ZoneTransfer, LookupError>,
        Option<Box<dyn ResponseSigner>>,
    )> {
        let (resp, signer) = self.authorize_axfr(request).await;
        if let Err(code) = resp {
            warn!(axfr_policy = ?self.axfr_policy, response_code = ?code, "rejected AXFR");
            return Some((Err(LookupError::ResponseCode(code)), signer));
        }
        debug!(axfr_policy = ?self.axfr_policy, "authorized AXFR");

        let backend = self.backend.read().await;

        let start_soa =
            if let LookupControlFlow::Continue(Ok(res)) = self.soa_secure(lookup_options).await {
                res.unwrap_records()
            } else {
                LookupRecords::Empty
            };
        let end_soa = if let LookupControlFlow::Continue(Ok(res)) = self.soa().await {
            res.unwrap_records()
        } else {
            LookupRecords::Empty
        };

        let records = AxfrRecords::new(
            lookup_options.dnssec_ok,
            backend.records().values().cloned().collect(),
        );

        Some((
            Ok(ZoneTransfer {
                start_soa,
                records,
                end_soa,
            }),
            signer,
        ))
    }

    #[cfg(feature = "__dnssec")]
    async fn nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        let backend = self.backend.read().await;

        // TODO: need a BorrowdRrKey
        let rr_key = RrKey::new(name.clone(), RecordType::NSEC);
        let no_data = backend
            .records()
            .get(&rr_key)
            .map(|rr_set| LookupRecords::new(lookup_options, rr_set.clone()));

        if let Some(no_data) = no_data {
            return LookupControlFlow::Continue(Ok(no_data.into()));
        }

        let closest_proof = backend.closest_nsec(name);

        // we need the wildcard proof, but make sure that it's still part of the zone.
        let wildcard = name.base_name();
        let origin = self.origin();
        let wildcard = if origin.zone_of(&wildcard) {
            wildcard
        } else {
            origin.clone()
        };

        // don't duplicate the record...
        let wildcard_proof = if wildcard != *name {
            backend.closest_nsec(&wildcard)
        } else {
            None
        };

        let proofs = match (closest_proof, wildcard_proof) {
            (Some(closest_proof), Some(wildcard_proof)) => {
                // dedup with the wildcard proof
                if wildcard_proof != closest_proof {
                    vec![wildcard_proof, closest_proof]
                } else {
                    vec![closest_proof]
                }
            }
            (None, Some(proof)) | (Some(proof), None) => vec![proof],
            (None, None) => vec![],
        };

        LookupControlFlow::Continue(Ok(LookupRecords::many(lookup_options, proofs).into()))
    }

    #[cfg(not(feature = "__dnssec"))]
    async fn nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        LookupControlFlow::Continue(Ok(AuthLookup::default()))
    }

    #[cfg(feature = "__dnssec")]
    async fn nsec3_records(
        &self,
        info: Nsec3QueryInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        let backend = self.backend.read().await;
        LookupControlFlow::Continue(
            backend
                .proof(info, self.origin())
                .map(|proof| LookupRecords::many(lookup_options, proof).into()),
        )
    }

    #[cfg(feature = "__dnssec")]
    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        self.nx_proof_kind.as_ref()
    }

    #[cfg(feature = "metrics")]
    fn metrics_label(&self) -> &'static str {
        self.metrics_label
    }
}

#[cfg(feature = "__dnssec")]
#[async_trait]
impl<B, P> DnssecAuthority for AuthoritativeAuthority<B, P>
where
    B: StoreBackend + Send + Sync,
    P: RuntimeProvider + Send + Sync,
{
    async fn add_update_auth_key(&self, name: Name, key: KEY) -> DnsSecResult<()> {
        let mut backend = self.backend.write().await;
        Self::inner_add_update_auth_key(&mut backend, name, key, &self.origin, self.class)
    }

    async fn add_zone_signing_key(&self, signer: SigSigner) -> DnsSecResult<()> {
        let mut backend = self.backend.write().await;
        Self::inner_add_zone_signing_key(&mut backend, signer, &self.origin, self.class)
    }

    async fn secure_zone(&self) -> DnsSecResult<()> {
        let mut backend = self.backend.write().await;
        backend.secure_zone_mut(
            &self.origin,
            self.class,
            self.nx_proof_kind.as_ref(),
            Self::current_time()?,
        )
    }
}

/// Gets the next search name, and returns the RecordType that it originated from
pub(super) fn maybe_next_name(
    record_set: &RecordSet,
    query_type: RecordType,
) -> Option<(LowerName, RecordType)> {
    match (record_set.record_type(), query_type) {
        // ANAME is similar to CNAME,
        //  unlike CNAME, it is only something that continue to additional processing if the
        //  the query was for address (A, AAAA, or ANAME itself) record types.
        (t @ RecordType::ANAME, RecordType::A)
        | (t @ RecordType::ANAME, RecordType::AAAA)
        | (t @ RecordType::ANAME, RecordType::ANAME) => record_set
            .records_without_rrsigs()
            .next()
            .map(Record::data)
            .and_then(RData::as_aname)
            .map(|aname| LowerName::from(&aname.0))
            .map(|name| (name, t)),
        (t @ RecordType::NS, RecordType::NS) => record_set
            .records_without_rrsigs()
            .next()
            .map(Record::data)
            .and_then(RData::as_ns)
            .map(|ns| LowerName::from(&ns.0))
            .map(|name| (name, t)),
        // CNAME will continue to additional processing for any query type
        (t @ RecordType::CNAME, _) => record_set
            .records_without_rrsigs()
            .next()
            .map(Record::data)
            .and_then(RData::as_cname)
            .map(|cname| LowerName::from(&cname.0))
            .map(|name| (name, t)),
        (t @ RecordType::MX, RecordType::MX) => record_set
            .records_without_rrsigs()
            .next()
            .map(Record::data)
            .and_then(RData::as_mx)
            .map(|mx| mx.exchange().clone())
            .map(LowerName::from)
            .map(|name| (name, t)),
        (t @ RecordType::SRV, RecordType::SRV) => record_set
            .records_without_rrsigs()
            .next()
            .map(Record::data)
            .and_then(RData::as_srv)
            .map(|srv| srv.target().clone())
            .map(LowerName::from)
            .map(|name| (name, t)),
        // other additional collectors can be added here can be added here
        _ => None,
    }
}
