#[cfg(feature = "__dnssec")]
use std::collections::{BTreeSet, HashMap, hash_map::Entry};
use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

use cfg_if::cfg_if;
#[cfg(feature = "__dnssec")]
use time::OffsetDateTime;
#[cfg(feature = "__dnssec")]
use tracing::debug;
use tracing::{error, warn};

#[cfg(feature = "__dnssec")]
use crate::{
    authority::{LookupError, Nsec3QueryInfo},
    dnssec::NxProofKind,
    proto::{
        ProtoError,
        dnssec::{
            DnsSecResult, Nsec3HashAlgorithm, SigSigner, TBS,
            rdata::{DNSSECRData, NSEC, NSEC3, NSEC3PARAM, RRSIG},
        },
    },
};

use super::maybe_next_name;
use crate::{
    authority::LookupOptions,
    proto::rr::{
        DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType, RrKey, rdata::SOA,
    },
};

#[derive(Default)]
pub(super) struct InnerInMemory {
    pub(super) records: BTreeMap<RrKey, Arc<RecordSet>>,
    // Private key mapped to the Record of the DNSKey
    //  TODO: these private_keys should be stored securely. Ideally, we have keys only stored per
    //   server instance, but that requires requesting updates from the parent zone, which may or
    //   may not support dynamic updates to register the new key... Hickory DNS will provide support
    //   for this, in some form, perhaps alternate root zones...
    #[cfg(feature = "__dnssec")]
    pub(super) secure_keys: Vec<SigSigner>,
}

impl InnerInMemory {
    #[cfg(feature = "__dnssec")]
    pub(super) fn proof(
        &self,
        info: Nsec3QueryInfo<'_>,
        zone: &LowerName,
    ) -> Result<Vec<Arc<RecordSet>>, LookupError> {
        let Nsec3QueryInfo {
            qname,
            qtype,
            has_wildcard_match,
            ..
        } = info;

        let rr_key = RrKey::new(info.get_hashed_owner_name(qname, zone)?, RecordType::NSEC3);
        let qname_match = self.records.get(&rr_key);

        if has_wildcard_match {
            // - Wildcard answer response.
            let closest_encloser_name = self.closest_encloser_proof(qname, zone, &info)?;
            let Some((closest_encloser_name, _)) = closest_encloser_name else {
                return Ok(vec![]);
            };

            let cover = self.find_cover(&closest_encloser_name, zone, &info)?;
            return Ok(cover.map_or_else(Vec::new, |rr_set| vec![rr_set]));
        }

        match qname_match {
            // - No data response if the QTYPE is not DS.
            // - No data response if the QTYPE is DS and there is an NSEC3 record matching QNAME.
            Some(rr_set) => return Ok(vec![rr_set.clone()]),
            None => {}
        }

        // - Name error response.
        // - No data response if QTYPE is DS and there is not an NSEC3 record matching QNAME.
        // - Wildcard no data response.
        let mut records = Vec::new();
        let (next_closer_name, closest_encloser_match) =
            self.closest_encloser_proof(qname, zone, &info)?.unzip();
        if let Some(cover) = closest_encloser_match {
            records.push(cover);
        }

        let Some(next_closer_name) = next_closer_name else {
            return Ok(records);
        };

        if let Some(cover) = self.find_cover(&next_closer_name, zone, &info)? {
            records.push(cover);
        }

        let wildcard_match = {
            let wildcard = qname.clone().into_wildcard();
            self.records.keys().any(|rr_key| rr_key.name == wildcard)
        };

        if wildcard_match {
            let wildcard_at_closest_encloser = next_closer_name.into_wildcard();
            let rr_key = RrKey::new(
                info.get_hashed_owner_name(&wildcard_at_closest_encloser, zone)?,
                RecordType::NSEC3,
            );

            if let Some(record) = self.records.get(&rr_key) {
                records.push(record.clone());
            }
        } else if qtype != RecordType::DS {
            let wildcard_at_closest_encloser = next_closer_name.into_wildcard();
            if let Some(cover) = self.find_cover(&wildcard_at_closest_encloser, zone, &info)? {
                records.push(cover);
            }
        }

        records.sort_by(|a, b| a.name().cmp(b.name()));
        records.dedup_by(|a, b| a.name() == b.name());
        Ok(records)
    }

    #[cfg(feature = "__dnssec")]
    pub(super) fn closest_nsec(&self, name: &LowerName) -> Option<Arc<RecordSet>> {
        for rr_set in self.records.values().rev() {
            if rr_set.record_type() != RecordType::NSEC {
                continue;
            }

            if *name < rr_set.name().into() {
                continue;
            }

            // there should only be one record
            let Some(record) = rr_set.records(false).next() else {
                continue;
            };

            let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = record.data() else {
                continue;
            };

            let next_domain_name = nsec.next_domain_name();
            // the search name is less than the next NSEC record
            if *name < next_domain_name.into() ||
                // this is the last record, and wraps to the beginning of the zone
                next_domain_name < rr_set.name()
            {
                return Some(rr_set.clone());
            }
        }

        None
    }

    fn inner_soa(&self, origin: &LowerName) -> Option<&SOA> {
        // TODO: can't there be an RrKeyRef?
        let rr_key = RrKey::new(origin.clone(), RecordType::SOA);

        self.records
            .get(&rr_key)
            .and_then(|rrset| rrset.records_without_rrsigs().next())
            .map(Record::data)
            .and_then(RData::as_soa)
    }

    /// Returns the minimum ttl (as used in the SOA record)
    pub(super) fn minimum_ttl(&self, origin: &LowerName) -> u32 {
        match self.inner_soa(origin) {
            Some(soa) => soa.minimum(),
            None => {
                error!("could not lookup SOA for authority: {origin}");
                0
            }
        }
    }

    /// get the current serial number for the zone.
    pub(super) fn serial(&self, origin: &LowerName) -> u32 {
        match self.inner_soa(origin) {
            Some(soa) => soa.serial(),
            None => {
                error!("could not lookup SOA for authority: {origin}");
                0
            }
        }
    }

    pub(super) fn inner_lookup(
        &self,
        name: &LowerName,
        record_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Option<Arc<RecordSet>> {
        // this range covers all the records for any of the RecordTypes at a given label.
        let start_range_key = RrKey::new(name.clone(), RecordType::Unknown(u16::MIN));
        let end_range_key = RrKey::new(name.clone(), RecordType::Unknown(u16::MAX));

        fn aname_covers_type(key_type: RecordType, query_type: RecordType) -> bool {
            (query_type == RecordType::A || query_type == RecordType::AAAA)
                && key_type == RecordType::ANAME
        }

        let lookup = self
            .records
            .range(&start_range_key..&end_range_key)
            // remember CNAME can be the only record at a particular label
            .find(|(key, _)| {
                key.record_type == record_type
                    || key.record_type == RecordType::CNAME
                    || aname_covers_type(key.record_type, record_type)
            })
            .map(|(_key, rr_set)| rr_set);

        // TODO: maybe unwrap this recursion.
        match lookup {
            None => self.inner_lookup_wildcard(name, record_type, lookup_options),
            l => l.cloned(),
        }
    }

    fn inner_lookup_wildcard(
        &self,
        name: &LowerName,
        record_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Option<Arc<RecordSet>> {
        // if this is a wildcard or a root, both should break continued lookups
        if name.is_wildcard() || name.is_root() {
            return None;
        }

        let mut wildcard = name.clone().into_wildcard();
        loop {
            let Some(rrset) = self.inner_lookup(&wildcard, record_type, lookup_options) else {
                let parent = wildcard.base_name();
                if parent.is_root() {
                    return None;
                }

                wildcard = parent.into_wildcard();
                continue;
            };

            // we need to change the name to the query name in the result set since this was a wildcard
            let mut new_answer =
                RecordSet::with_ttl(Name::from(name), rrset.record_type(), rrset.ttl());

            #[allow(clippy::needless_late_init)]
            let records;
            #[allow(clippy::needless_late_init)]
            let _rrsigs: Vec<&Record>;
            cfg_if! {
                if #[cfg(feature = "__dnssec")] {
                    let (records_tmp, rrsigs_tmp) = rrset
                        .records(lookup_options.dnssec_ok())
                        .partition(|r| r.record_type() != RecordType::RRSIG);
                    records = records_tmp;
                    _rrsigs = rrsigs_tmp;
                } else {
                    let (records_tmp, rrsigs_tmp) = (rrset.records_without_rrsigs(), Vec::with_capacity(0));
                    records = records_tmp;
                    _rrsigs = rrsigs_tmp;
                }
            };

            for record in records {
                new_answer.add_rdata(record.data().clone());
            }

            #[cfg(feature = "__dnssec")]
            for rrsig in _rrsigs {
                new_answer.insert_rrsig(rrsig.clone())
            }

            return Some(Arc::new(new_answer));
        }
    }

    /// Search for additional records to include in the response
    ///
    /// # Arguments
    ///
    /// * original_name - the original name that was being looked up
    /// * original_query_type - original type in the request query
    /// * next_name - the name from the CNAME, ANAME, MX, etc. record that is being searched
    /// * search_type - the root search type, ANAME, CNAME, MX, i.e. the beginning of the chain
    /// * lookup_options - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///   algorithms, etc.)
    pub(super) fn additional_search(
        &self,
        original_name: &LowerName,
        original_query_type: RecordType,
        next_name: LowerName,
        _search_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Option<Vec<Arc<RecordSet>>> {
        let mut additionals: Vec<Arc<RecordSet>> = vec![];

        // if it's a CNAME or other forwarding record, we'll be adding additional records based on the query_type
        let mut query_types_arr = [original_query_type; 2];
        let query_types: &[RecordType] = match original_query_type {
            RecordType::ANAME | RecordType::NS | RecordType::MX | RecordType::SRV => {
                query_types_arr = [RecordType::A, RecordType::AAAA];
                &query_types_arr[..]
            }
            _ => &query_types_arr[..1],
        };

        for query_type in query_types {
            // loop and collect any additional records to send

            // Track the names we've looked up for this query type.
            let mut names = HashSet::new();

            // If we're just going to repeat the same query then bail out.
            if query_type == &original_query_type {
                names.insert(original_name.clone());
            }

            let mut next_name = Some(next_name.clone());
            while let Some(search) = next_name.take() {
                // If we've already looked up this name then bail out.
                if names.contains(&search) {
                    break;
                }

                let additional = self.inner_lookup(&search, *query_type, lookup_options);
                names.insert(search);

                if let Some(additional) = additional {
                    // assuming no crazy long chains...
                    if !additionals.contains(&additional) {
                        additionals.push(additional.clone());
                    }

                    next_name =
                        maybe_next_name(&additional, *query_type).map(|(name, _search_type)| name);
                }
            }
        }

        if !additionals.is_empty() {
            Some(additionals)
        } else {
            None
        }
    }

    #[cfg(any(feature = "__dnssec", feature = "sqlite"))]
    pub(super) fn increment_soa_serial(&mut self, origin: &LowerName, dns_class: DNSClass) -> u32 {
        // we'll remove the SOA and then replace it
        let rr_key = RrKey::new(origin.clone(), RecordType::SOA);
        let record = self
            .records
            .remove(&rr_key)
            // TODO: there should be an unwrap on rrset, but it's behind Arc
            .and_then(|rrset| rrset.records_without_rrsigs().next().cloned());

        let mut record = if let Some(record) = record {
            record
        } else {
            error!("could not lookup SOA for authority: {}", origin);
            return 0;
        };

        let serial = if let RData::SOA(soa_rdata) = record.data_mut() {
            soa_rdata.increment_serial();
            soa_rdata.serial()
        } else {
            panic!("This was not an SOA record"); // valid panic, never should happen
        };

        self.upsert(record, serial, dns_class);
        serial
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
    pub(super) fn upsert(&mut self, record: Record, serial: u32, dns_class: DNSClass) -> bool {
        if dns_class != record.dns_class() {
            warn!(
                "mismatched dns_class on record insert, zone: {} record: {}",
                dns_class,
                record.dns_class()
            );
            return false;
        }

        #[cfg(feature = "__dnssec")]
        fn is_nsec(upsert_type: RecordType, occupied_type: RecordType) -> bool {
            // NSEC is always allowed
            upsert_type == RecordType::NSEC
                || upsert_type == RecordType::NSEC3
                || occupied_type == RecordType::NSEC
                || occupied_type == RecordType::NSEC3
        }

        #[cfg(not(feature = "__dnssec"))]
        fn is_nsec(_upsert_type: RecordType, _occupied_type: RecordType) -> bool {
            // TODO: we should make the DNSSEC RecordTypes always visible
            false
        }

        /// returns true if an only if the label can not co-occupy space with the checked type
        #[allow(clippy::nonminimal_bool)]
        fn label_does_not_allow_multiple(
            upsert_type: RecordType,
            occupied_type: RecordType,
            check_type: RecordType,
        ) -> bool {
            // it's a CNAME/ANAME but there's a record that's not a CNAME/ANAME at this location
            (upsert_type == check_type && occupied_type != check_type) ||
                // it's a different record, but there is already a CNAME/ANAME here
                (upsert_type != check_type && occupied_type == check_type)
        }

        // check that CNAME and ANAME is either not already present, or no other records are if it's a CNAME
        let start_range_key = RrKey::new(record.name().into(), RecordType::Unknown(u16::MIN));
        let end_range_key = RrKey::new(record.name().into(), RecordType::Unknown(u16::MAX));

        let multiple_records_at_label_disallowed = self
            .records
            .range(&start_range_key..&end_range_key)
            // remember CNAME can be the only record at a particular label
            .any(|(key, _)| {
                !is_nsec(record.record_type(), key.record_type)
                    && label_does_not_allow_multiple(
                        record.record_type(),
                        key.record_type,
                        RecordType::CNAME,
                    )
            });

        if multiple_records_at_label_disallowed {
            // consider making this an error?
            return false;
        }

        let rr_key = RrKey::new(record.name().into(), record.record_type());
        let records: &mut Arc<RecordSet> = self.records.entry(rr_key).or_insert_with(|| {
            Arc::new(RecordSet::new(
                record.name().clone(),
                record.record_type(),
                serial,
            ))
        });

        // because this is and Arc, we need to clone and then replace the entry
        let mut records_clone = RecordSet::clone(&*records);
        if records_clone.insert(record, serial) {
            *records = Arc::new(records_clone);
            true
        } else {
            false
        }
    }

    /// (Re)generates the nsec records, increments the serial number and signs the zone
    #[cfg(feature = "__dnssec")]
    pub(super) fn secure_zone_mut(
        &mut self,
        origin: &LowerName,
        dns_class: DNSClass,
        nx_proof_kind: Option<&NxProofKind>,
    ) -> DnsSecResult<()> {
        // TODO: only call nsec_zone after adds/deletes
        // needs to be called before incrementing the soa serial, to make sure IXFR works properly
        match nx_proof_kind {
            Some(NxProofKind::Nsec) => self.nsec_zone(origin, dns_class),
            Some(NxProofKind::Nsec3 {
                algorithm,
                salt,
                iterations,
                opt_out,
            }) => self.nsec3_zone(origin, dns_class, *algorithm, salt, *iterations, *opt_out)?,
            None => (),
        }

        // need to resign any records at the current serial number and bump the number.
        // first bump the serial number on the SOA, so that it is resigned with the new serial.
        self.increment_soa_serial(origin, dns_class);

        // TODO: should we auto sign here? or maybe up a level...
        self.sign_zone(origin, dns_class)
    }

    #[cfg(feature = "__dnssec")]
    fn nsec_zone(&mut self, origin: &LowerName, dns_class: DNSClass) {
        // only create nsec records for secure zones

        use std::mem;
        if self.secure_keys.is_empty() {
            return;
        }
        debug!("generating nsec records: {}", origin);

        // first remove all existing nsec records
        let delete_keys: Vec<RrKey> = self
            .records
            .keys()
            .filter(|k| k.record_type == RecordType::NSEC)
            .cloned()
            .collect();

        for key in delete_keys {
            self.records.remove(&key);
        }

        // now go through and generate the nsec records
        let ttl = self.minimum_ttl(origin);
        let serial = self.serial(origin);
        let mut records: Vec<Record> = vec![];

        {
            let mut nsec_info: Option<(&Name, BTreeSet<RecordType>)> = None;
            for key in self.records.keys() {
                match &mut nsec_info {
                    None => nsec_info = Some((&key.name, BTreeSet::from([key.record_type]))),
                    Some((name, vec)) if LowerName::new(name) == key.name => {
                        vec.insert(key.record_type);
                    }
                    Some((name, vec)) => {
                        // names aren't equal, create the NSEC record
                        let rdata = NSEC::new_cover_self(key.name.clone().into(), mem::take(vec));
                        let record = Record::from_rdata(name.clone(), ttl, rdata);
                        records.push(record.into_record_of_rdata());

                        // new record...
                        nsec_info = Some((&key.name, BTreeSet::from([key.record_type])))
                    }
                }
            }

            // the last record
            if let Some((name, vec)) = nsec_info {
                // names aren't equal, create the NSEC record
                let rdata = NSEC::new_cover_self(origin.clone().into(), vec);
                let record = Record::from_rdata(name.clone(), ttl, rdata);
                records.push(record.into_record_of_rdata());
            }
        }

        // insert all the nsec records
        for record in records {
            let upserted = self.upsert(record, serial, dns_class);
            debug_assert!(upserted);
        }
    }

    #[cfg(feature = "__dnssec")]
    fn nsec3_zone(
        &mut self,
        origin: &LowerName,
        dns_class: DNSClass,
        hash_alg: Nsec3HashAlgorithm,
        salt: &[u8],
        iterations: u16,
        opt_out: bool,
    ) -> DnsSecResult<()> {
        // only create nsec records for secure zones
        if self.secure_keys.is_empty() {
            return Ok(());
        }
        debug!("generating nsec3 records: {origin}");

        // first remove all existing nsec records
        let delete_keys = self
            .records
            .keys()
            .filter(|k| k.record_type == RecordType::NSEC3)
            .cloned()
            .collect::<Vec<_>>();

        for key in delete_keys {
            self.records.remove(&key);
        }

        // now go through and generate the nsec3 records
        let ttl = self.minimum_ttl(origin);
        let serial = self.serial(origin);

        // Store the record types of each domain name so we can generate NSEC3 records for each
        // domain name.
        let mut record_types = HashMap::new();
        record_types.insert(origin.clone(), ([RecordType::NSEC3PARAM].into(), true));

        let mut delegation_points = HashSet::<LowerName>::new();

        for key in self.records.keys() {
            if !origin.zone_of(&key.name) {
                // Non-authoritative record outside of zone
                continue;
            }
            if delegation_points
                .iter()
                .any(|name| name.zone_of(&key.name) && name != &key.name)
            {
                // Non-authoritative record below zone cut
                continue;
            }
            if key.record_type == RecordType::NS && &key.name != origin {
                delegation_points.insert(key.name.clone());
            }

            // Store the type of the current record under its domain name
            match record_types.entry(key.name.clone()) {
                Entry::Occupied(mut entry) => {
                    let (rtypes, exists): &mut (HashSet<RecordType>, bool) = entry.get_mut();
                    rtypes.insert(key.record_type);
                    *exists = true;
                }
                Entry::Vacant(entry) => {
                    entry.insert((HashSet::from([key.record_type]), true));
                }
            }
        }

        if opt_out {
            // Delete owner names that have unsigned delegations.
            let ns_only = HashSet::from([RecordType::NS]);
            record_types.retain(|_name, (types, _exists)| types != &ns_only);
        }

        // For every domain name between the current name and the origin, add it to `record_types`
        // without any record types. This covers all the empty non-terminals that must have an NSEC3
        // record as well.
        for name in record_types.keys().cloned().collect::<Vec<_>>() {
            let mut parent = name.base_name();
            while parent.num_labels() > origin.num_labels() {
                record_types
                    .entry(parent.clone())
                    .or_insert_with(|| (HashSet::new(), false));
                parent = parent.base_name();
            }
        }

        // Compute the hash of all the names.
        let mut record_types = record_types
            .into_iter()
            .map(|(name, (type_bit_maps, exists))| {
                let hashed_name = hash_alg.hash(salt, &name, iterations)?;
                Ok((hashed_name, (type_bit_maps, exists)))
            })
            .collect::<Result<Vec<_>, ProtoError>>()?;
        // Sort by hash.
        record_types.sort_by(|(a, _), (b, _)| a.as_ref().cmp(b.as_ref()));

        let mut records = vec![];

        // Generate an NSEC3 record for every name
        for (i, (hashed_name, (type_bit_maps, exists))) in record_types.iter().enumerate() {
            // Get the next hashed name following the hash order.
            let next_index = (i + 1) % record_types.len();
            let next_hashed_name = record_types[next_index].0.as_ref().to_vec();

            let rdata = NSEC3::new(
                hash_alg,
                opt_out,
                iterations,
                salt.to_vec(),
                next_hashed_name,
                type_bit_maps
                    .iter()
                    .copied()
                    .chain(exists.then_some(RecordType::RRSIG)),
            );

            let name =
                origin.prepend_label(data_encoding::BASE32_DNSSEC.encode(hashed_name.as_ref()))?;

            let record = Record::from_rdata(name, ttl, rdata);
            records.push(record.into_record_of_rdata());
        }

        // Include the NSEC3PARAM record.
        let rdata = NSEC3PARAM::new(hash_alg, opt_out, iterations, salt.to_vec());
        let record = Record::from_rdata(origin.into(), ttl, rdata);
        records.push(record.into_record_of_rdata());

        // insert all the NSEC3 records.
        for record in records {
            let upserted = self.upsert(record, serial, dns_class);
            debug_assert!(upserted);
        }

        Ok(())
    }

    /// Signs an RecordSet, and stores the RRSIGs in the RecordSet
    ///
    /// This will sign the RecordSet with all the registered keys in the zone
    ///
    /// # Arguments
    ///
    /// * `rr_set` - RecordSet to sign
    /// * `secure_keys` - Set of keys to use to sign the RecordSet, see `self.signers()`
    /// * `zone_ttl` - the zone TTL, see `self.minimum_ttl()`
    /// * `zone_class` - DNSClass of the zone, see `self.zone_class()`
    #[cfg(feature = "__dnssec")]
    pub(super) fn sign_rrset(
        rr_set: &mut RecordSet,
        secure_keys: &[SigSigner],
        zone_ttl: u32,
        zone_class: DNSClass,
    ) -> DnsSecResult<()> {
        let inception = OffsetDateTime::now_utc();

        rr_set.clear_rrsigs();

        let rrsig_temp = Record::update0(rr_set.name().clone(), zone_ttl, RecordType::RRSIG);

        for signer in secure_keys {
            debug!(
                "signing rr_set: {}, {} with: {}",
                rr_set.name(),
                rr_set.record_type(),
                signer.key().algorithm(),
            );

            let expiration = inception + signer.sig_duration();
            let tbs = TBS::from_rrset(rr_set, zone_class, inception, expiration, signer);

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
            rrsig.set_data(RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::new(
                // type_covered: RecordType,
                rr_set.record_type(),
                // algorithm: Algorithm,
                signer.key().algorithm(),
                // num_labels: u8,
                rr_set.name().num_labels(),
                // original_ttl: u32,
                rr_set.ttl(),
                // sig_expiration: u32,
                expiration.unix_timestamp() as u32,
                // sig_inception: u32,
                inception.unix_timestamp() as u32,
                // key_tag: u16,
                signer.calculate_key_tag()?,
                // signer_name: Name,
                signer.signer_name().clone(),
                // sig: Vec<u8>
                signature,
            ))));

            rr_set.insert_rrsig(rrsig);
        }

        Ok(())
    }

    /// Signs all records in the zone.
    #[cfg(feature = "__dnssec")]
    fn sign_zone(&mut self, origin: &LowerName, dns_class: DNSClass) -> DnsSecResult<()> {
        debug!("signing zone: {}", origin);

        let minimum_ttl = self.minimum_ttl(origin);
        let secure_keys = &self.secure_keys;
        let records = &mut self.records;

        // TODO: should this be an error?
        if secure_keys.is_empty() {
            warn!(
                "attempt to sign_zone {} for dnssec, but no keys available!",
                origin
            )
        }

        // sign all record_sets, as of 0.12.1 this includes DNSKEY
        for rr_set_orig in records.values_mut() {
            // because the rrset is an Arc, it must be cloned before mutated
            let rr_set = Arc::make_mut(rr_set_orig);
            Self::sign_rrset(rr_set, secure_keys, minimum_ttl, dns_class)?;
        }

        Ok(())
    }

    /// Find a record that covers the given name. That is, an NSEC3 record such that the hashed owner
    /// name of the given name falls between the record's owner name and its next hashed owner
    /// name.
    #[cfg(feature = "__dnssec")]
    fn find_cover(
        &self,
        name: &LowerName,
        zone: &Name,
        info: &Nsec3QueryInfo<'_>,
    ) -> Result<Option<Arc<RecordSet>>, ProtoError> {
        let owner_name = info.get_hashed_owner_name(name, zone)?;
        let records = self
            .records
            .values()
            .filter(|rr_set| rr_set.record_type() == RecordType::NSEC3);

        // Find the record with the largest owner name such that its owner name is before the
        // hashed QNAME. If this record exist, it already covers QNAME. Otherwise, the QNAME
        // preceeds all the existing NSEC3 records' owner names, meaning that it is covered by
        // the NSEC3 record with the largest owner name.
        Ok(records
            .clone()
            .filter(|rr_set| rr_set.record_type() == RecordType::NSEC3)
            .filter(|rr_set| rr_set.name() < &*owner_name)
            .max_by_key(|rr_set| rr_set.name())
            .or_else(|| records.max_by_key(|rr_set| rr_set.name()))
            .cloned())
    }

    /// Return the next closer name and the record that matches the closest encloser of a given name.
    #[cfg(feature = "__dnssec")]
    fn closest_encloser_proof(
        &self,
        name: &LowerName,
        zone: &Name,
        info: &Nsec3QueryInfo<'_>,
    ) -> Result<Option<(LowerName, Arc<RecordSet>)>, ProtoError> {
        let mut next_closer_name = name.clone();
        let mut closest_encloser = next_closer_name.base_name();

        while !closest_encloser.is_root() {
            let rr_key = RrKey::new(
                info.get_hashed_owner_name(&closest_encloser, zone)?,
                RecordType::NSEC3,
            );
            if let Some(rrs) = self.records.get(&rr_key) {
                return Ok(Some((next_closer_name, rrs.clone())));
            }

            next_closer_name = next_closer_name.base_name();
            closest_encloser = closest_encloser.base_name();
        }

        Ok(None)
    }
}
