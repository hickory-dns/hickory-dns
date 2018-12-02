// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! All authority related types

#[cfg(feature = "dnssec")]
use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use trust_dns::op::ResponseCode;
use trust_dns::rr::dnssec::{DnsSecResult, Signer, SupportedAlgorithms};
use trust_dns::rr::{DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType, RrKey};

use authority::{
    AnyRecords, AuthLookup, Authority, LookupRecords, MessageRequest, UpdateResult, ZoneType,
};
use store::file::FileConfig;

/// SqliteAuthority is responsible for storing the resource records for a particular zone.
///
/// Authorities default to DNSClass IN. The ZoneType specifies if this should be treated as the
/// start of authority for the zone, is a slave, or a cached zone.
pub struct FileAuthority {
    origin: LowerName,
    class: DNSClass,
    records: BTreeMap<RrKey, Arc<RecordSet>>,
    zone_type: ZoneType,
    allow_axfr: bool,
    // Private key mapped to the Record of the DNSKey
    //  TODO: these private_keys should be stored securely. Ideally, we have keys only stored per
    //   server instance, but that requires requesting updates from the parent zone, which may or
    //   may not support dynamic updates to register the new key... Trust-DNS will provide support
    //   for this, in some form, perhaps alternate root zones...
    secure_keys: Vec<Signer>,
}

impl FileAuthority {
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
        allow_axfr: bool,
    ) -> Self {
        Self {
            origin: LowerName::new(&origin),
            class: DNSClass::IN,
            records: records
                .into_iter()
                .map(|(key, rrset)| (key, Arc::new(rrset)))
                .collect(),
            zone_type,
            allow_axfr,
            secure_keys: Vec::new(),
        }
    }

    /// Read the Authority for the origin from the specified configuration
    pub fn try_from_config(
        origin: Name,
        zone_type: ZoneType,
        allow_axfr: bool,
        root_dir: Option<&Path>,
        config: &FileConfig,
    ) -> Result<Self, String> {
        use std::fs::File;
        use std::io::Read;
        use trust_dns::serialize::txt::{Lexer, Parser};

        let zone_path = root_dir
            .map(PathBuf::from)
            .unwrap_or_else(PathBuf::new)
            .join(&config.zone_file_path);

        info!("loading zone file: {:?}", zone_path);

        let mut file = File::open(&zone_path)
            .map_err(|e| format!("error opening {}: {:?}", zone_path.display(), e))?;

        let mut buf = String::new();

        // TODO: this should really use something to read line by line or some other method to
        //  keep the usage down. and be a custom lexer...
        file.read_to_string(&mut buf)
            .map_err(|e| format!("failed to read {}: {:?}", zone_path.display(), e))?;
        let lexer = Lexer::new(&buf);
        let (origin, records) = Parser::new()
            .parse(lexer, Some(origin))
            .map_err(|e| format!("failed to parse {}: {:?}", zone_path.display(), e))?;

        info!(
            "zone file loaded: {} with {} records",
            origin,
            records.len()
        );

        Ok(FileAuthority::new(origin, records, zone_type, allow_axfr))
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
    pub fn records(&self) -> &BTreeMap<RrKey, Arc<RecordSet>> {
        &self.records
    }

    /// Returns the minimum ttl (as used in the SOA record)
    pub fn minimum_ttl(&self) -> u32 {
        self.soa().iter().next().map_or(0, |soa| {
            if let RData::SOA(ref rdata) = *soa.rdata() {
                rdata.minimum()
            } else {
                0
            }
        })
    }

    /// get the current serial number for the zone.
    pub fn serial(&self) -> u32 {
        self.soa().iter().next().map_or_else(
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

    #[allow(unused)]
    fn increment_soa_serial(&mut self) -> u32 {
        let opt_soa_serial = self.soa().iter().next().map(|soa| {
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
        let records: &mut Arc<RecordSet> = self
            .records
            .entry(rr_key)
            .or_insert_with(|| Arc::new(RecordSet::new(record.name(), record.rr_type(), serial)));

        // because this is and Arc, we need to clone and then replace the entry
        let mut records_clone = RecordSet::clone(&*records);
        if records_clone.insert(record, serial) {
            *records = Arc::new(records_clone);
            true
        } else {
            false
        }
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
        for rr_set_orig in self.records.values_mut() {
            let mut rr_set = RecordSet::clone(&*rr_set_orig);
            // becuase the rrset is an Arc, it must be cloned before mutated

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

            *rr_set_orig = Arc::new(rr_set);
        }

        Ok(())
    }

    /// unwrap all the records
    pub(crate) fn unwrap_records(self) -> BTreeMap<RrKey, Arc<RecordSet>> {
        self.records
    }
}

impl Authority for FileAuthority {
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
    fn update(&mut self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName {
        &self.origin
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
    fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> AuthLookup {
        let rr_key = RrKey::new(name.clone(), rtype);

        // Collect the records from each rr_set
        let result: LookupRecords = match rtype {
            RecordType::AXFR | RecordType::ANY => {
                let result = AnyRecords::new(
                    is_secure,
                    supported_algorithms,
                    self.records.values().cloned().collect(),
                    rtype,
                    name.clone(),
                );
                LookupRecords::AnyRecords(result)
            }
            _ => self
                .records
                .get(&rr_key)
                .map_or(LookupRecords::NxDomain, |rr_set| {
                    LookupRecords::new(is_secure, supported_algorithms, rr_set.clone())
                }),
        };

        // This is annoying. The 1035 spec literally specifies that most DNS authorities would want to store
        //   records in a list except when there are a lot of records. But this makes indexed lookups by name+type
        //   always return empty sets. This is only important in the negative case, where other DNS authorities
        //   generally return NoError and no results when other types exist at the same name. bah.
        if result.is_nx_domain() {
            if self.records.keys().any(|key| key.name() == name) {
                return AuthLookup::NameExists;
            } else {
                return AuthLookup::NxDomain;
            }
        }

        result.into()
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
    ) -> AuthLookup {
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
                LookupRecords::new(is_secure, supported_algorithms, rr_set.clone())
            }).into()
    }

    /// By adding a secure key, this will implicitly enable dnssec for the zone.
    ///
    /// # Arguments
    ///
    /// * `signer` - Signer with associated private key
    #[cfg(feature = "dnssec")]
    fn add_secure_key(&mut self, signer: Signer) -> DnsSecResult<()> {
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

    /// This will fail, the dnssec feature must be enabled
    #[cfg(not(feature = "dnssec"))]
    fn add_secure_key(&mut self, _signer: Signer) -> DnsSecResult<()> {
        Err("DNSSEC is not enabled.".into())
    }

    /// (Re)generates the nsec records, increments the serial number nad signs the zone
    #[cfg(feature = "dnssec")]
    fn secure_zone(&mut self) -> DnsSecResult<()> {
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
    fn secure_zone(&mut self) -> DnsSecResult<()> {
        Err("DNSSEC is not enabled.".into())
    }
}

// TODO: construct a battery of standard authority tests
#[cfg(test)]
mod tests {
    use super::*;
    use authority::ZoneType;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn test_load_zone() {
        let config = FileConfig {
            zone_file_path: "tests/named_test_configs/example.com.zone".to_string(),
        };
        let authority = FileAuthority::try_from_config(
            Name::from_str("example.com.").unwrap(),
            ZoneType::Master,
            false,
            None,
            &config,
        ).expect("failed to load file");

        let lookup = authority.lookup(
            &LowerName::from_str("www.example.com.").unwrap(),
            RecordType::A,
            false,
            SupportedAlgorithms::new(),
        );

        match lookup
            .into_iter()
            .next()
            .expect("A record not found in authity")
            .rdata()
        {
            RData::A(ip) => assert_eq!(Ipv4Addr::new(127, 0, 0, 1), *ip),
            _ => panic!("wrong rdata type returned"),
        }
    }
}
