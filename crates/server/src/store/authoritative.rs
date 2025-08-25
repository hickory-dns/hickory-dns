//! Authoritative zone data

use std::{
    collections::BTreeMap,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use async_trait::async_trait;
#[cfg(feature = "__dnssec")]
use time::OffsetDateTime;
#[cfg(all(feature = "__dnssec", feature = "testing"))]
use tokio::sync::RwLockWriteGuard;
use tokio::sync::{RwLock, RwLockReadGuard};
use tracing::debug;
#[cfg(feature = "__dnssec")]
use tracing::warn;

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
    authority::{DnssecAuthority, Nsec3QueryInfo},
    dnssec::NxProofKind,
    proto::{
        dnssec::{
            DnsSecResult, SigSigner,
            rdata::DNSSECRData,
            rdata::{DNSKEY, KEY},
        },
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

    #[cfg(feature = "__dnssec")]
    nx_proof_kind: Option<NxProofKind>,

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

            #[cfg(feature = "__dnssec")]
            nx_proof_kind,

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

    /// Temporary method to get mutable access to the backend storage.
    ///
    /// This will be removed once migration is complete.
    pub async fn backend_mut(&self) -> impl DerefMut<Target = B> + '_ {
        self.backend.write().await
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

    async fn update(
        &self,
        _update: &Request,
    ) -> (UpdateResult<bool>, Option<Box<dyn ResponseSigner>>) {
        (Err(ResponseCode::NotImp), None)
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
        let request_info = match request.request_info() {
            Ok(info) => info,
            Err(e) => return Some((Err(LookupError::from(e)), None)),
        };

        if request_info.query.query_type() == RecordType::AXFR {
            // TODO: support more advanced AXFR options
            if !matches!(self.axfr_policy, AxfrPolicy::AllowAll) {
                return Some((Err(LookupError::from(ResponseCode::Refused)), None));
            }
        }

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
            None,
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
