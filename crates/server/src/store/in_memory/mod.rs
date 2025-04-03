// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Zone file based serving with Dynamic DNS and journaling support

#[cfg(all(feature = "__dnssec", feature = "testing"))]
use std::ops::Deref;
use std::{collections::BTreeMap, ops::DerefMut, sync::Arc};

use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::debug;
#[cfg(feature = "__dnssec")]
use tracing::warn;

use crate::{
    authority::{
        AnyRecords, AuthLookup, Authority, LookupControlFlow, LookupError, LookupOptions,
        LookupRecords, MessageRequest, UpdateResult, ZoneType,
    },
    proto::{
        op::ResponseCode,
        rr::{DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType, RrKey, rdata::SOA},
    },
    server::RequestInfo,
};
#[cfg(feature = "__dnssec")]
use crate::{
    authority::{DnssecAuthority, Nsec3QueryInfo},
    dnssec::NxProofKind,
    proto::dnssec::{
        DnsSecResult, SigSigner,
        rdata::{DNSKEY, DNSSECRData, key::KEY},
    },
};

mod inner;
use inner::InnerInMemory;

/// InMemoryAuthority is responsible for storing the resource records for a particular zone.
///
/// Authorities default to DNSClass IN. The ZoneType specifies if this should be treated as the
/// start of authority for the zone, is a Secondary, or a cached zone.
pub struct InMemoryAuthority {
    origin: LowerName,
    class: DNSClass,
    zone_type: ZoneType,
    allow_axfr: bool,
    inner: RwLock<InnerInMemory>,
    #[cfg(feature = "__dnssec")]
    nx_proof_kind: Option<NxProofKind>,
}

impl InMemoryAuthority {
    /// Creates a new Authority.
    ///
    /// # Arguments
    ///
    /// * `origin` - The zone `Name` being created, this should match that of the `RecordType::SOA`
    ///   record.
    /// * `records` - The map of the initial set of records in the zone.
    /// * `zone_type` - The type of zone, i.e. is this authoritative?
    /// * `allow_axfr` - Whether AXFR is allowed.
    /// * `nx_proof_kind` - The kind of non-existence proof to be used by the server.
    ///
    /// # Return value
    ///
    /// The new `Authority`.
    pub fn new(
        origin: Name,
        records: BTreeMap<RrKey, RecordSet>,
        zone_type: ZoneType,
        allow_axfr: bool,
        #[cfg(feature = "__dnssec")] nx_proof_kind: Option<NxProofKind>,
    ) -> Result<Self, String> {
        let mut this = Self::empty(
            origin.clone(),
            zone_type,
            allow_axfr,
            #[cfg(feature = "__dnssec")]
            nx_proof_kind,
        );
        let inner = this.inner.get_mut();

        // SOA must be present
        let serial = records
            .iter()
            .find(|(key, _)| key.record_type == RecordType::SOA)
            .and_then(|(_, rrset)| rrset.records_without_rrsigs().next())
            .map(Record::data)
            .and_then(RData::as_soa)
            .map(SOA::serial)
            .ok_or_else(|| format!("SOA record must be present: {origin}"))?;

        let iter = records.into_values();

        // add soa to the records
        for rrset in iter {
            let name = rrset.name().clone();
            let rr_type = rrset.record_type();

            for record in rrset.records_without_rrsigs() {
                if !inner.upsert(record.clone(), serial, this.class) {
                    return Err(format!(
                        "Failed to insert {name} {rr_type} to zone: {origin}"
                    ));
                };
            }
        }

        Ok(this)
    }

    /// Creates an empty Authority
    ///
    /// # Warning
    ///
    /// This is an invalid zone, SOA must be added
    pub fn empty(
        origin: Name,
        zone_type: ZoneType,
        allow_axfr: bool,
        #[cfg(feature = "__dnssec")] nx_proof_kind: Option<NxProofKind>,
    ) -> Self {
        Self {
            origin: LowerName::new(&origin),
            class: DNSClass::IN,
            zone_type,
            allow_axfr,
            inner: RwLock::new(InnerInMemory::default()),

            #[cfg(feature = "__dnssec")]
            nx_proof_kind,
        }
    }

    /// The DNSClass of this zone
    pub fn class(&self) -> DNSClass {
        self.class
    }

    /// Allow AXFR's (zone transfers)
    #[cfg(any(test, feature = "testing"))]
    pub fn set_allow_axfr(&mut self, allow_axfr: bool) {
        self.allow_axfr = allow_axfr;
    }

    /// Clears all records (including SOA, etc)
    pub fn clear(&mut self) {
        self.inner.get_mut().records.clear()
    }

    /// Retrieve the Signer, which contains the private keys, for this zone
    #[cfg(all(feature = "__dnssec", feature = "testing"))]
    pub async fn secure_keys(&self) -> impl Deref<Target = [SigSigner]> + '_ {
        RwLockWriteGuard::map(self.inner.write().await, |i| i.secure_keys.as_mut_slice())
    }

    /// Get all the records
    pub async fn records(&self) -> BTreeMap<RrKey, Arc<RecordSet>> {
        let records = RwLockReadGuard::map(self.inner.read().await, |i| &i.records);
        records.clone()
    }

    /// Get a mutable reference to the records
    pub async fn records_mut(
        &self,
    ) -> impl DerefMut<Target = BTreeMap<RrKey, Arc<RecordSet>>> + '_ {
        RwLockWriteGuard::map(self.inner.write().await, |i| &mut i.records)
    }

    /// Get a mutable reference to the records
    pub fn records_get_mut(&mut self) -> &mut BTreeMap<RrKey, Arc<RecordSet>> {
        &mut self.inner.get_mut().records
    }

    /// Returns the minimum ttl (as used in the SOA record)
    pub async fn minimum_ttl(&self) -> u32 {
        self.inner.read().await.minimum_ttl(self.origin())
    }

    /// get the current serial number for the zone.
    pub async fn serial(&self) -> u32 {
        self.inner.read().await.serial(self.origin())
    }

    #[cfg(any(feature = "__dnssec", feature = "sqlite"))]
    #[allow(unused)]
    pub(crate) async fn increment_soa_serial(&self) -> u32 {
        self.inner
            .write()
            .await
            .increment_soa_serial(self.origin(), self.class)
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
    /// true if the value was inserted, false otherwise
    pub async fn upsert(&self, record: Record, serial: u32) -> bool {
        self.inner.write().await.upsert(record, serial, self.class)
    }

    /// Non-async version of upsert when behind a mutable reference.
    pub fn upsert_mut(&mut self, record: Record, serial: u32) -> bool {
        self.inner.get_mut().upsert(record, serial, self.class)
    }

    /// Add a (Sig0) key that is authorized to perform updates against this authority
    #[cfg(feature = "__dnssec")]
    fn inner_add_update_auth_key(
        inner: &mut InnerInMemory,

        name: Name,
        key: KEY,
        origin: &LowerName,
        dns_class: DNSClass,
    ) -> DnsSecResult<()> {
        let rdata = RData::DNSSEC(DNSSECRData::KEY(key));
        // TODO: what TTL?
        let record = Record::from_rdata(name, 86400, rdata);

        let serial = inner.serial(origin);
        if inner.upsert(record, serial, dns_class) {
            Ok(())
        } else {
            Err("failed to add auth key".into())
        }
    }

    /// Non-async method of add_update_auth_key when behind a mutable reference
    #[cfg(feature = "__dnssec")]
    pub fn add_update_auth_key_mut(&mut self, name: Name, key: KEY) -> DnsSecResult<()> {
        let Self {
            origin,
            inner,
            class,
            ..
        } = self;

        Self::inner_add_update_auth_key(inner.get_mut(), name, key, origin, *class)
    }

    /// By adding a secure key, this will implicitly enable dnssec for the zone.
    ///
    /// # Arguments
    ///
    /// * `signer` - Signer with associated private key
    #[cfg(feature = "__dnssec")]
    fn inner_add_zone_signing_key(
        inner: &mut InnerInMemory,
        signer: SigSigner,
        origin: &LowerName,
        dns_class: DNSClass,
    ) -> DnsSecResult<()> {
        // also add the key to the zone
        let zone_ttl = inner.minimum_ttl(origin);
        let dnskey = DNSKEY::from_key(&signer.key().to_public_key()?);
        let dnskey = Record::from_rdata(
            origin.clone().into(),
            zone_ttl,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
        );

        // TODO: also generate the CDS and CDNSKEY
        let serial = inner.serial(origin);
        inner.upsert(dnskey, serial, dns_class);
        inner.secure_keys.push(signer);
        Ok(())
    }

    /// Non-async method of add_zone_signing_key when behind a mutable reference
    #[cfg(feature = "__dnssec")]
    pub fn add_zone_signing_key_mut(&mut self, signer: SigSigner) -> DnsSecResult<()> {
        let Self {
            origin,
            inner,
            class,
            ..
        } = self;

        Self::inner_add_zone_signing_key(inner.get_mut(), signer, origin, *class)
    }

    /// (Re)generates the nsec records, increments the serial number and signs the zone
    #[cfg(feature = "__dnssec")]
    pub fn secure_zone_mut(&mut self) -> DnsSecResult<()> {
        let Self { origin, inner, .. } = self;
        inner
            .get_mut()
            .secure_zone_mut(origin, self.class, self.nx_proof_kind.as_ref())
    }

    /// (Re)generates the nsec records, increments the serial number and signs the zone
    #[cfg(not(feature = "__dnssec"))]
    pub fn secure_zone_mut(&mut self) -> Result<(), &str> {
        Err("DNSSEC was not enabled during compilation.")
    }
}

#[async_trait::async_trait]
impl Authority for InMemoryAuthority {
    type Lookup = AuthLookup;

    /// What type is this zone
    fn zone_type(&self) -> ZoneType {
        self.zone_type
    }

    /// Return true if AXFR is allowed
    fn is_axfr_allowed(&self) -> bool {
        self.allow_axfr
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
    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName {
        &self.origin
    }

    /// Looks up all Resource Records matching the given `Name` and `RecordType`.
    ///
    /// # Arguments
    ///
    /// * `name` - The name to look up.
    /// * `query_type` - The `RecordType` to look up. `RecordType::ANY` will return all records
    ///                  matching `name`. `RecordType::AXFR` will return all record types except
    ///                  `RecordType::SOA` due to the requirements that on zone transfers the
    ///                  `RecordType::SOA` must both precede and follow all other records.
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///                      algorithms, etc.)
    ///
    /// # Return value
    ///
    /// A LookupControlFlow containing the lookup that should be returned to the client.
    async fn lookup(
        &self,
        name: &LowerName,
        query_type: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        let inner = self.inner.read().await;

        // Collect the records from each rr_set
        let (result, additionals): (LookupControlFlow<LookupRecords, _>, Option<LookupRecords>) =
            match query_type {
                RecordType::AXFR | RecordType::ANY => {
                    let result = AnyRecords::new(
                        lookup_options,
                        inner.records.values().cloned().collect(),
                        query_type,
                        name.clone(),
                    );
                    (
                        LookupControlFlow::Continue(Ok(LookupRecords::AnyRecords(result))),
                        None,
                    )
                }
                _ => {
                    // perform the lookup
                    let answer = inner.inner_lookup(name, query_type, lookup_options);

                    // evaluate any cnames for additional inclusion
                    let additionals_root_chain_type: Option<(_, _)> = answer
                        .as_ref()
                        .and_then(|a| maybe_next_name(a, query_type))
                        .and_then(|(search_name, search_type)| {
                            inner
                                .additional_search(
                                    name,
                                    query_type,
                                    search_name,
                                    search_type,
                                    lookup_options,
                                )
                                .map(|adds| (adds, search_type))
                        });

                    // if the chain started with an ANAME, take the A or AAAA record from the list
                    let (additionals, answer) =
                        match (additionals_root_chain_type, answer, query_type) {
                            (
                                Some((additionals, RecordType::ANAME)),
                                Some(answer),
                                RecordType::A,
                            )
                            | (
                                Some((additionals, RecordType::ANAME)),
                                Some(answer),
                                RecordType::AAAA,
                            ) => {
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
                                        .map(|records| {
                                            records.map(Record::data).cloned().collect::<Vec<_>>()
                                        });

                                    (rdatas, a_aaaa_ttl)
                                };

                                // now build up a new RecordSet
                                //   the name comes from the ANAME record
                                //   according to the rfc the ttl is from the ANAME
                                //   TODO: technically we should take the min of the potential CNAME chain
                                let ttl = answer.ttl().min(a_aaaa_ttl);
                                let mut new_answer =
                                    RecordSet::new(answer.name().clone(), query_type, ttl);

                                for rdata in rdatas.into_iter().flatten() {
                                    new_answer.add_rdata(rdata);
                                }

                                // if DNSSEC is enabled, and the request had the DO set, sign the recordset
                                #[cfg(feature = "__dnssec")]
                                // ANAME's are constructed on demand, so need to be signed before return
                                if lookup_options.dnssec_ok() {
                                    InnerInMemory::sign_rrset(
                                        &mut new_answer,
                                        &inner.secure_keys,
                                        inner.minimum_ttl(self.origin()),
                                        self.class(),
                                    )
                                    // rather than failing the request, we'll just warn
                                    .map_err(|e| warn!("failed to sign ANAME record: {}", e))
                                    .ok();
                                }

                                // prepend answer to additionals here (answer is the ANAME record)
                                let additionals =
                                    std::iter::once(answer).chain(additionals).collect();

                                // return the new answer
                                //   because the searched set was an Arc, we need to arc too
                                (Some(additionals), Some(Arc::new(new_answer)))
                            }
                            (Some((additionals, _)), answer, _) => (Some(additionals), answer),
                            (None, answer, _) => (None, answer),
                        };

                    // map the answer to a result
                    let answer = answer.map_or(
                        LookupControlFlow::Continue(Err(LookupError::from(ResponseCode::NXDomain))),
                        |rr_set| {
                            LookupControlFlow::Continue(Ok(LookupRecords::new(
                                lookup_options,
                                rr_set,
                            )))
                        },
                    );

                    let additionals = additionals.map(|a| LookupRecords::many(lookup_options, a));

                    (answer, additionals)
                }
            };

        // This is annoying. The 1035 spec literally specifies that most DNS authorities would want to store
        //   records in a list except when there are a lot of records. But this makes indexed lookups by name+type
        //   always return empty sets. This is only important in the negative case, where other DNS authorities
        //   generally return NoError and no results when other types exist at the same name. bah.
        // TODO: can we get rid of this?
        use LookupControlFlow::*;
        let result = match result {
            Continue(Err(LookupError::ResponseCode(ResponseCode::NXDomain))) => {
                if inner
                    .records
                    .keys()
                    .any(|key| key.name() == name || name.zone_of(key.name()))
                {
                    return Continue(Err(LookupError::NameExists));
                } else {
                    let code = if self.origin().zone_of(name) {
                        ResponseCode::NXDomain
                    } else {
                        ResponseCode::Refused
                    };
                    return Continue(Err(LookupError::from(code)));
                }
            }
            Continue(Err(e)) => return Continue(Err(e)),
            o => o,
        };

        result.map(|answers| AuthLookup::answers(answers, additionals))
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        debug!("searching InMemoryAuthority for: {}", request_info.query);

        let lookup_name = request_info.query.name();
        let record_type: RecordType = request_info.query.query_type();

        // if this is an AXFR zone transfer, verify that this is either the Secondary or Primary
        //  for AXFR the first and last record must be the SOA
        if RecordType::AXFR == record_type {
            // TODO: support more advanced AXFR options
            if !self.is_axfr_allowed() {
                return LookupControlFlow::Continue(Err(LookupError::from(ResponseCode::Refused)));
            }

            #[allow(deprecated)]
            match self.zone_type() {
                ZoneType::Primary | ZoneType::Secondary | ZoneType::Master | ZoneType::Slave => (),
                // TODO: Forward?
                _ => {
                    return LookupControlFlow::Continue(Err(LookupError::from(
                        ResponseCode::NXDomain,
                    )));
                }
            }
        }

        // perform the actual lookup
        match record_type {
            RecordType::SOA => {
                self.lookup(self.origin(), record_type, lookup_options)
                    .await
            }
            RecordType::AXFR => {
                // TODO: shouldn't these SOA's be secure? at least the first, perhaps not the last?
                use LookupControlFlow::Continue;
                let start_soa = if let Continue(Ok(res)) = self.soa_secure(lookup_options).await {
                    res.unwrap_records()
                } else {
                    LookupRecords::Empty
                };
                let end_soa = if let Continue(Ok(res)) = self.soa().await {
                    res.unwrap_records()
                } else {
                    LookupRecords::Empty
                };

                let records = if let Continue(Ok(res)) =
                    self.lookup(lookup_name, record_type, lookup_options).await
                {
                    res.unwrap_records()
                } else {
                    LookupRecords::Empty
                };

                LookupControlFlow::Continue(Ok(AuthLookup::AXFR {
                    start_soa,
                    end_soa,
                    records,
                }))
            }
            // A standard Lookup path
            _ => self.lookup(lookup_name, record_type, lookup_options).await,
        }
    }

    /// Return the NSEC records based on the given name
    ///
    /// # Arguments
    ///
    /// * `name` - given this name (i.e. the lookup name), return the NSEC record that is less than
    ///            this
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///                      algorithms, etc.)
    #[cfg(feature = "__dnssec")]
    async fn get_nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        let inner = self.inner.read().await;

        // TODO: need a BorrowdRrKey
        let rr_key = RrKey::new(name.clone(), RecordType::NSEC);
        let no_data = inner
            .records
            .get(&rr_key)
            .map(|rr_set| LookupRecords::new(lookup_options, rr_set.clone()));

        if let Some(no_data) = no_data {
            return LookupControlFlow::Continue(Ok(no_data.into()));
        }

        let closest_proof = inner.closest_nsec(name);

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
            inner.closest_nsec(&wildcard)
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
    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        LookupControlFlow::Continue(Ok(AuthLookup::default()))
    }

    #[cfg(feature = "__dnssec")]
    async fn get_nsec3_records(
        &self,
        info: Nsec3QueryInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        let inner = self.inner.read().await;
        LookupControlFlow::Continue(
            inner
                .proof(info, self.origin())
                .map(|proof| LookupRecords::many(lookup_options, proof).into()),
        )
    }

    #[cfg(feature = "__dnssec")]
    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        self.nx_proof_kind.as_ref()
    }
}

#[cfg(feature = "__dnssec")]
#[async_trait::async_trait]
impl DnssecAuthority for InMemoryAuthority {
    /// Add a (Sig0) key that is authorized to perform updates against this authority
    async fn add_update_auth_key(&self, name: Name, key: KEY) -> DnsSecResult<()> {
        let mut inner = self.inner.write().await;

        Self::inner_add_update_auth_key(&mut inner, name, key, self.origin(), self.class)
    }

    /// By adding a secure key, this will implicitly enable dnssec for the zone.
    ///
    /// # Arguments
    ///
    /// * `signer` - Signer with associated private key
    async fn add_zone_signing_key(&self, signer: SigSigner) -> DnsSecResult<()> {
        let mut inner = self.inner.write().await;

        Self::inner_add_zone_signing_key(&mut inner, signer, self.origin(), self.class)
    }

    /// Sign the zone for DNSSEC
    async fn secure_zone(&self) -> DnsSecResult<()> {
        let mut inner = self.inner.write().await;

        inner.secure_zone_mut(self.origin(), self.class, self.nx_proof_kind.as_ref())
    }
}

/// Gets the next search name, and returns the RecordType that it originated from
fn maybe_next_name(
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
