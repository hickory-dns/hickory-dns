/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::collections::BTreeMap;
use std::cmp::Ordering;

use chrono::offset::utc::UTC;
use openssl::crypto::pkey::Role;

use ::authority::{UpdateResult, ZoneType, RRSet};
use ::op::{Message, UpdateMessage, ResponseCode, Query};
use ::rr::{DNSClass, Name, RData, Record, RecordType};
use ::rr::rdata::{NSEC, SIG};
use ::rr::dnssec::Signer;

/// Accessor key for RRSets in the Authority.
#[derive(Eq, PartialEq, Debug, Hash, Clone)]
pub struct RrKey { name: Name, record_type: RecordType }

impl RrKey {
  /// Creates a new key to access the Authority.
  ///
  /// # Arguments
  ///
  /// * `name` - domain name to lookup.
  /// * `record_type` - the `RecordType` to lookup.
  ///
  /// # Return value
  ///
  /// A new key to access the Authorities.
  pub fn new(name: &Name, record_type: RecordType) -> RrKey {
    RrKey{ name: name.clone(), record_type: record_type }
  }
}

impl PartialOrd for RrKey {
  fn partial_cmp(&self, other: &RrKey) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

impl Ord for RrKey {
  fn cmp(&self, other: &Self) -> Ordering {
    let order = self.name.cmp(&other.name);
    if order == Ordering::Equal {
      self.record_type.cmp(&other.record_type)
    } else {
      order
    }
  }
}

/// Authority is the storage method for all resource records
pub struct Authority {
  origin: Name,
  class: DNSClass,
  records: BTreeMap<RrKey, RRSet>,
  zone_type: ZoneType,
  allow_update: bool,
  // Private key mapped to the Record of the DNSKey
  //  TODO: these private_keys should be stored securely. Ideally, we have keys only stored per
  //   server instance, but that requires requesting updates from the parent zone, which may or
  //   may not support dynamic updates to register the new key... Trust-DNS will provide support
  //   for this, in some form, perhaps alternate root zones...
  secure_keys: Vec<Signer>,
}

/// Authority is responsible for storing the resource records for a particular zone.
///
/// Authorities default to DNSClass IN. The ZoneType specifies if this should be treated as the
/// start of authority for the zone, is a slave, or a cached zone.
impl Authority {
  /// Creates a new Authority.
  ///
  /// # Arguments
  ///
  /// * `origin` - The zone `Name` being created, this should match that of the `RecordType::SOA`
  ///              record.
  /// * `records` - The `HashMap` of the initial set of records in the zone.
  /// * `zone_type` - The type of zone, i.e. is this authoritative?
  /// * `allow_update` - If true, then this zone accepts dynamic updates.
  ///
  /// # Return value
  ///
  /// The new `Authority`.
  pub fn new(origin: Name, records: BTreeMap<RrKey, RRSet>, zone_type: ZoneType, allow_update: bool) -> Authority {
    Authority{ origin: origin, class: DNSClass::IN, records: records, zone_type: zone_type,
      allow_update: allow_update, secure_keys: Vec::new() }
  }

  pub fn add_secure_key(&mut self, signer: Signer) {
    // also add the key to the zone
    let zone_ttl = self.get_minimum_ttl();
    let dnskey = signer.to_dnskey(self.origin.clone(), zone_ttl);

    // TODO: also generate the CDS and CDNSKEY
    let serial = self.get_serial();
    self.upsert(dnskey, serial);
    self.secure_keys.push(signer);
  }

  #[cfg(test)]
  pub fn set_allow_update(&mut self, allow_update: bool) {
    self.allow_update = allow_update;
  }

  #[cfg(test)]
  pub fn get_secure_keys(&self) -> &[Signer] {
    &self.secure_keys
  }

  pub fn get_origin(&self) -> &Name {
    &self.origin
  }

  pub fn get_zone_type(&self) -> ZoneType {
    self.zone_type
  }

  /// Returns the SOA of the authority.
  ///
  /// *Note* This will only return the SOA, if this is fullfilling a request, a standard lookup
  ///  should be used, see `get_soa_secure()`, which will optionally return RRSIGs.
  pub fn get_soa(&self) -> Option<&Record> {
    // SOA should be origin|SOA
    self.lookup(&self.origin, RecordType::SOA, false).first().map(|v| *v)
  }

  /// Returns the SOA record
  ///
  ///
  pub fn get_soa_secure(&self, is_secure: bool) -> Vec<&Record> {
    self.lookup(&self.origin, RecordType::SOA, is_secure)
  }

  pub fn get_minimum_ttl(&self) -> u32 {
    self.get_soa().map_or(0, |soa| if let &RData::SOA(ref rdata) = soa.get_rdata() { rdata.get_minimum() } else { 0 })
  }

  fn get_serial(&self) -> u32 {
    let soa = if let Some(ref soa_record) = self.get_soa() {
      soa_record.clone()
    } else {
      warn!("no soa record found for zone: {}", self.origin);
      return 0;
    };

    if let &RData::SOA(ref soa_rdata) = soa.get_rdata() {
      soa_rdata.get_serial()
    } else {
      panic!("This was not an SOA record");
    }
  }

  fn increment_soa_serial(&mut self) -> u32 {
    let mut soa = if let Some(ref mut soa_record) = self.get_soa() {
      soa_record.clone()
    } else {
      warn!("no soa record found for zone: {}", self.origin);
      return 0;
    };

    let serial = if let &mut RData::SOA(ref mut soa_rdata) = soa.get_rdata_mut() {
      soa_rdata.increment_serial();
      soa_rdata.get_serial()
    } else {
      panic!("This was not an SOA record");
    };

    self.upsert(soa, serial);
    return serial;
  }

  pub fn get_ns(&self, is_secure: bool) -> Vec<&Record> {
    self.lookup(&self.origin, RecordType::NS, is_secure)
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
  fn verify_prerequisites(&self, pre_requisites: &[Record]) -> UpdateResult<()> {
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
      if require.get_ttl() != 0 {
        debug!("ttl must be 0 for: {:?}", require);
        return Err(ResponseCode::FormErr);
      }

      if !self.origin.zone_of(require.get_name()) {
        debug!("{} is not a zone_of {}", require.get_name(), self.origin);
        return Err(ResponseCode::NotZone);
      }

      match require.get_dns_class() {
        DNSClass::ANY =>
          if let &RData::NULL( .. ) = require.get_rdata() {
            match require.get_rr_type() {
              // ANY      ANY      empty    Name is in use
              RecordType::ANY => {
                if self.lookup(require.get_name(), RecordType::ANY, false).is_empty() {
                  return Err(ResponseCode::NXDomain);
                } else {
                  continue;
                }
              },
              // ANY      rrset    empty    RRset exists (value independent)
              rrset @ _ => {
                if self.lookup(require.get_name(), rrset, false).is_empty() {
                  return Err(ResponseCode::NXRRSet);
                } else {
                  continue;
                }
              },
            }
          } else {
            return Err(ResponseCode::FormErr);
          }
        ,
        DNSClass::NONE =>
          if let &RData::NULL( .. ) = require.get_rdata() {
            match require.get_rr_type() {
              // NONE     ANY      empty    Name is not in use
              RecordType::ANY => {
                if !self.lookup(require.get_name(), RecordType::ANY, false).is_empty() {
                  return Err(ResponseCode::YXDomain);
                } else {
                  continue;
                }
              },
              // NONE     rrset    empty    RRset does not exist
              rrset @ _ => {
                if !self.lookup(require.get_name(), rrset, false).is_empty() {
                  return Err(ResponseCode::YXRRSet);
                } else {
                  continue;
                }
              },
            }
          } else {
            return Err(ResponseCode::FormErr);
          }
        ,
        class @ _ if class == self.class =>
          // zone     rrset    rr       RRset exists (value dependent)
          if self.lookup(require.get_name(), require.get_rr_type(), false)
                 .iter()
                 .filter(|rr| *rr == &require)
                 .next()
                 .is_none() {
            return Err(ResponseCode::NXRRSet);
          } else {
            continue;
          }
          ,
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
  fn authorize(&self, update_message: &Message) -> UpdateResult<()> {
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
      warn!("update attempted on non-updatable Authority: {}", self.origin);
      return Err(ResponseCode::Refused)
    }

    // verify sig0, currently the only authorization that is accepted.
    let sig0s: &[Record] = update_message.get_sig0();
    debug!("authorizing with: {:?}", sig0s);
    if !sig0s.is_empty() && sig0s.iter()
            .filter_map(|sig0| if let &RData::SIG(ref sig) = sig0.get_rdata() { Some(sig) } else { None })
            .any(|sig| {
              let name = sig.get_signer_name();
              let keys = self.lookup(name, RecordType::KEY, false);
              debug!("found keys {:?}", keys);
              keys.iter()
                  .filter_map(|rr_set| if let &RData::KEY(ref key) = rr_set.get_rdata() { Some(key) } else { None })
                  .any(|key| {
                    let pkey = key.get_algorithm().public_key_from_vec(key.get_public_key());
                    if let Err(error) = pkey {
                      warn!("public key {:?} of {} could not be used: {}", key, name, error);
                      return false
                    }

                    let pkey = pkey.unwrap();
                    if pkey.can(Role::Verify) {
                      let signer: Signer = Signer::new_verifier(*key.get_algorithm(), pkey, sig.get_signer_name().clone());

                      if signer.verify_message(update_message, sig.get_sig()) {
                        info!("verified sig: {:?} with key: {:?}", sig, key);
                        true
                      } else {
                        debug!("did not verify sig: {:?} with key: {:?}", sig, key);
                        false
                      }
                    } else {
                      warn!("{}: can not be used to verify", name);
                      false
                    }
                  })
            }) {
      return Ok(());
    } else {
      warn!("no sig0 matched registered records: id {}", update_message.get_id());
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
  fn pre_scan(&self, records: &[Record]) -> UpdateResult<()> {
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
      if !self.get_origin().zone_of(rr.get_name()) {
        return Err(ResponseCode::NotZone);
      }

      let class: DNSClass = rr.get_dns_class();
      if class == self.class {
        match rr.get_rr_type() {
          RecordType::ANY | RecordType::AXFR | RecordType::IXFR => return Err(ResponseCode::FormErr),
          _ => (),
        }
      } else {
        match class {
          DNSClass::ANY => {
            if rr.get_ttl() != 0 { return Err(ResponseCode::FormErr) }
            if let &RData::NULL(..) = rr.get_rdata() { () }
            else { return Err(ResponseCode::FormErr) }
            match rr.get_rr_type() {
              RecordType::AXFR | RecordType::IXFR => return Err(ResponseCode::FormErr),
              _ => (),
            }
          },
          DNSClass::NONE => {
            if rr.get_ttl() != 0 { return Err(ResponseCode::FormErr) }
            match rr.get_rr_type() {
              RecordType::ANY | RecordType::AXFR | RecordType::IXFR => return Err(ResponseCode::FormErr),
              _ => (),
            }
          },
          _ => return Err(ResponseCode::FormErr),
        }
      }
    }

    return Ok(());
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
  fn update_records(&mut self, records: &[Record]) -> UpdateResult<bool> {
    let mut updated = false;
    let serial: u32 = self.get_serial();


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
      let rr_key = RrKey::new(rr.get_name(), rr.get_rr_type());

      match rr.get_dns_class() {
        class @ _ if class == self.class => {
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
        },
        DNSClass::ANY => {
          // This is a delete of entire RRSETs, either many or one. In either case, the spec is clear:
          match rr.get_rr_type() {
            t @ RecordType::SOA | t @ RecordType::NS if rr.get_name() == &self.origin => {
              // SOA and NS records are not to be deleted if they are the origin records
              info!("skipping delete of {:?} see RFC 2136 - 3.4.2.3", t);
              continue;
            },
            RecordType::ANY => {
              // RFC 2136 - 3.4.2.3. For any Update RR whose CLASS is ANY and whose TYPE is ANY,
              //   all Zone RRs with the same NAME are deleted, unless the NAME is the
              //   same as ZNAME in which case only those RRs whose TYPE is other than
              //   SOA or NS are deleted.

              // ANY      ANY      empty    Delete all RRsets from a name
              info!("deleting all records at name (not SOA or NS at origin): {:?}", rr.get_name());
              let to_delete = self.records.keys().filter(|k| !((k.record_type == RecordType::SOA ||
                                                                k.record_type == RecordType::NS) &&
                                                               k.name != self.origin))
                                                 .filter(|k| &k.name == rr.get_name())
                                                 .cloned()
                                                 .collect::<Vec<RrKey>>();
              for delete in to_delete {
                self.records.remove(&delete);
                updated = true;
              }
            },
            _ => {
              // RFC 2136 - 3.4.2.3. For any Update RR whose CLASS is ANY and
              //   whose TYPE is not ANY all Zone RRs with the same NAME and TYPE are
              //   deleted, unless the NAME is the same as ZNAME in which case neither
              //   SOA or NS RRs will be deleted.

              // ANY      rrset    empty    Delete an RRset
              if let &RData::NULL( .. ) = rr.get_rdata() {
                let deleted = self.records.remove(&rr_key);
                info!("deleted rrset: {:?}", deleted);
                updated = updated || deleted.is_some();
              } else {
                info!("expected empty rdata: {:?}", rr);
                return Err(ResponseCode::FormErr)
              }
            }
          }
        },
        DNSClass::NONE => {
          info!("deleting specific record: {:?}", rr);
          println!("deleting specific record: {:?}", rr);
          // NONE     rrset    rr       Delete an RR from an RRset
          if let Some(rrset) = self.records.get_mut(&rr_key) {
            let deleted = rrset.remove(rr, serial);
            info!("deleted ({}) specific record: {:?}", deleted, rr);
            println!("deleted ({}) specific record: {:?}", deleted, rr);
            updated = updated || deleted;
          }
        },
        class @ _ => {
          info!("unexpected DNS Class: {:?}", class);
          return Err(ResponseCode::FormErr)
        }
      }
    }

    // update the serial...
    if updated {
      self.secure_zone();
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
    assert_eq!(self.class, record.get_dns_class());

    let rr_key = RrKey::new(record.get_name(), record.get_rr_type());
    let records: &mut RRSet = self.records.entry(rr_key).or_insert(RRSet::new(record.get_name(), record.get_rr_type(), serial));

    records.insert(record, serial)
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
  pub fn update(&mut self, update: &Message) -> UpdateResult<bool> {
    // the spec says to authorize after prereqs, seems better to auth first.
    try!(self.authorize(update));
    try!(self.verify_prerequisites(update.get_pre_requisites()));
    try!(self.pre_scan(update.get_updates()));

    self.update_records(update.get_updates())
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
  pub fn search(&self, query: &Query, is_secure: bool) -> Vec<&Record> {
    let record_type: RecordType = query.get_query_type();

    // if this is an AXFR zone transfer, verify that this is either the slave or master
    //  for AXFR the first and last record must be the SOA
    if RecordType::AXFR == record_type {
      match self.get_zone_type() {
        ZoneType::Master | ZoneType::Slave => (),
        // TODO Forward?
        _ => return vec![], // TODO this sould be an error.
      }
    }

    // it would be better to stream this back, rather than packaging everything up in an array
    //  though for UDP it would still need to be bundled
    let mut query_result: Vec<_> = self.lookup(query.get_name(), record_type, is_secure);

    if RecordType::AXFR == record_type {
      if let Some(soa) = self.get_soa() {
        let mut xfr: Vec<&Record> = query_result;
        // TODO: probably make Records Rc or Arc, to remove the clone
        xfr.insert(0, soa);
        xfr.push(soa);

        query_result = xfr;
      } else {
        return vec![]; // TODO is this an error?
      }
    }

    query_result
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
  pub fn lookup(&self, name: &Name, rtype: RecordType, is_secure: bool) -> Vec<&Record> {
    // on an SOA request always return the SOA, regardless of the name
    let name: &Name = if rtype == RecordType::SOA { &self.origin } else { name };
    let rr_key = RrKey::new(name, rtype);

    // Collect the records from each rr_set
    let result: Vec<&Record> = match rtype {
      RecordType::ANY | RecordType::AXFR => {
        self.records.values().filter(|rr_set| rtype == RecordType::ANY || rr_set.get_record_type() != RecordType::SOA)
                             .filter(|rr_set| rtype == RecordType::AXFR || rr_set.get_name() == name)
                             .fold(Vec::<&Record>::new(), |mut vec, rr_set| {
                               vec.append(&mut rr_set.get_records(is_secure));
                               vec
                             })
      },
      _ => {
        self.records.get(&rr_key).map_or(vec![], |rr_set| rr_set.get_records(is_secure).into_iter().collect())
      }
    };

    result
  }

  /// Return the NSEC records based on the given name
  ///
  /// # Arguments
  ///
  /// * `name` - given this name (i.e. the lookup name), return the NSEC record that is less than
  ///            this
  /// * `is_secure` - if true then it will return RRSIG records as well
  pub fn get_nsec_records(&self, name: &Name, is_secure: bool) -> Vec<&Record> {
    self.records.values().filter(|rr_set| rr_set.get_record_type() == RecordType::NSEC)
                         .skip_while(|rr_set| name < rr_set.get_name())
                         .next()
                         .map_or(vec![], |rr_set| rr_set.get_records(is_secure).into_iter().collect())
  }

  /// (Re)generates the nsec records, increments the serial number nad signs the zone
  pub fn secure_zone(&mut self) {
    // TODO: only call nsec_zone after adds/deletes
    // needs to be called before incrementing the soa serial, to make sur IXFR works properly
    self.nsec_zone();

    // need to resign any records at the current serial number and bump the number.
    // first bump the serial number on the SOA, so that it is resigned with the new serial.
    self.increment_soa_serial();

    // TODO: should we auto sign here? or maybe up a level...
    self.sign_zone();
  }

  /// Creates all nsec records needed for the zone, replaces any existing records.
  fn nsec_zone(&mut self) {
    // only create nsec records for secure zones
    if self.secure_keys.is_empty() { return }
    debug!("generating nsec records: {}", self.origin);

    // first remove all existing nsec records
    let delete_keys: Vec<RrKey> = self.records.keys()
                                              .filter(|k| k.record_type == RecordType::NSEC)
                                              .cloned()
                                              .collect();

    for key in delete_keys {
      self.records.remove(&key);
    }

    // now go through and generate the nsec records
    let ttl = self.get_minimum_ttl();
    let serial = self.get_serial();
    let mut records: Vec<Record> = vec![];

    {
      let mut nsec_info: Option<(&Name, Vec<RecordType>)> = None;
      for key in self.records.keys() {
        match nsec_info {
          None => nsec_info = Some((&key.name, vec![key.record_type])),
          Some((name, ref mut vec)) if name == &key.name => { vec.push(key.record_type) },
          Some((name, vec)) => {
            // names aren't equal, create the NSEC record
            let mut record = Record::with(name.clone(), RecordType::NSEC, ttl);
            let rdata = NSEC::new(key.name.clone(), vec);
            record.rdata(RData::NSEC(rdata));
            records.push(record);

            // new record...
            nsec_info = Some((&key.name, vec![key.record_type]))
          },
        }
      }

      // the last record
      if let Some((name, vec)) = nsec_info {
        // names aren't equal, create the NSEC record
        let mut record = Record::with(name.clone(), RecordType::NSEC, ttl);
        let rdata = NSEC::new(self.get_origin().clone(), vec);
        record.rdata(RData::NSEC(rdata));
        records.push(record);
      }
    }

    // insert all the nsec records
    for record in records {
      self.upsert(record, serial);
    }
  }

  /// Signs any records in the zone that have serial numbers greater than or equal to `serial`
  fn sign_zone(&mut self) {
    debug!("signing zone: {}", self.origin);
    let now = UTC::now().timestamp() as u32;
    let zone_ttl = self.get_minimum_ttl();

    for rr_set in self.records.iter_mut().filter_map(|(_, rr_set)| {
      // do not sign zone DNSKEY's that's the job of the parent zone
      if rr_set.get_record_type() == RecordType::DNSKEY { return None }
      rr_set.get_rrsigs().is_empty();
      Some(rr_set) } ) {

      debug!("signing rr_set: {}", rr_set.get_name());
      rr_set.clear_rrsigs();
      let rrsig_temp = Record::with(rr_set.get_name().clone(), RecordType::RRSIG, zone_ttl);

      for signer in self.secure_keys.iter() {
        let hash = signer.hash_rrset(rr_set.get_name(),
                                     self.class,
                                     rr_set.get_name().num_labels(),
                                     rr_set.get_record_type(),
                                     signer.get_algorithm(),
                                     rr_set.get_ttl(),
                                     signer.get_expiration(),
                                     now,
                                     signer.calculate_key_tag(),
                                     signer.get_signer_name(),
                                     // TODO: this is a nasty clone... the issue is that the vec
                                     //  from get_records is of Vec<&R>, but we really want &[R]
                                     &rr_set.get_records(false).into_iter().cloned().collect::<Vec<Record>>());
        let signature = signer.sign(&hash);
        let mut rrsig = rrsig_temp.clone();
        rrsig.rdata(RData::SIG(SIG::new(
          // type_covered: RecordType,
          rr_set.get_record_type(),
          // algorithm: Algorithm,
          signer.get_algorithm(),
          // num_labels: u8,
          rr_set.get_name().num_labels(),
          // original_ttl: u32,
          rr_set.get_ttl(),
          // sig_expiration: u32,
          signer.get_expiration(),
          // sig_inception: u32,
          now,
          // key_tag: u16,
          signer.calculate_key_tag(),
          // signer_name: Name,
          signer.get_signer_name().clone(),
          // sig: Vec<u8>
          signature,
        )));

        rr_set.insert_rrsig(rrsig);
        debug!("signed rr_set: {}", rr_set.get_name());
      }
    }
  }
}

#[cfg(test)]
pub mod authority_tests {
  use std::collections::BTreeMap;
  use std::net::{Ipv4Addr,Ipv6Addr};

  use ::authority::ZoneType;
  use ::rr::*;
  use ::rr::rdata::{ NULL, SOA, TXT };
  use ::op::*;
  use super::*;

  pub fn create_example() -> Authority {
    let origin: Name = Name::parse("example.com.", None,).unwrap();
    let mut records: Authority = Authority::new(origin.clone(), BTreeMap::new(), ZoneType::Master, false);
    // example.com.		3600	IN	SOA	sns.dns.icann.org. noc.dns.icann.org. 2015082403 7200 3600 1209600 3600
    records.upsert(Record::new().name(origin.clone()).ttl(3600).rr_type(RecordType::SOA).dns_class(DNSClass::IN).rdata(RData::SOA(SOA::new(Name::parse("sns.dns.icann.org.", None).unwrap(), Name::parse("noc.dns.icann.org.", None).unwrap(), 2015082403, 7200, 3600, 1209600, 3600 ))).clone(), 0);

    records.upsert(Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()) ).clone(), 0);
    records.upsert(Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS(Name::parse("b.iana-servers.net.", None).unwrap()) ).clone(), 0);

    // example.com.		60	IN	TXT	"v=spf1 -all"
    //records.upsert(origin.clone(), Record::new().name(origin.clone()).ttl(60).rr_type(RecordType::TXT).dns_class(DNSClass::IN).rdata(RData::TXT{ txt_data: vec!["v=spf1 -all".to_string()] }).clone());
    // example.com.		60	IN	TXT	"$Id: example.com 4415 2015-08-24 20:12:23Z davids $"
    records.upsert(Record::new().name(origin.clone()).ttl(60).rr_type(RecordType::TXT).dns_class(DNSClass::IN).rdata(RData::TXT(TXT::new(vec!["$Id: example.com 4415 2015-08-24 20:12:23Z davids $".to_string()]))).clone(), 0);

    // example.com.		86400	IN	A	93.184.216.34
    records.upsert(Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::A(Ipv4Addr::new(93,184,216,34))).clone(), 0);

    // example.com.		86400	IN	AAAA	2606:2800:220:1:248:1893:25c8:1946
    records.upsert(Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::AAAA).dns_class(DNSClass::IN).rdata(RData::AAAA(Ipv6Addr::new(0x2606,0x2800,0x220,0x1,0x248,0x1893,0x25c8,0x1946))).clone(), 0);

    // TODO support these later...

    // example.com.		3600	IN	RRSIG	NSEC 8 2 3600 20150926015219 20150905040848 54108 example.com. d0AXd6QRITqLeiYbQUlJ5O0Og9tSjk7IlxQr9aJO+r+rc1g0dW9i9OCc XXQxdC1/zyubecjD6kSs3vwxzzEEupivaKHKtNPXdnDZ5UUiaIC1VU9l 9h/ik+AR4rCTY6dYPCI6lafD/TlqQLbpEnb34ywkRpl5G3pasPrwEY7b nrAndEY=
    // example.com.		3600	IN	NSEC	www.example.com. A NS SOA TXT AAAA RRSIG NSEC DNSKEY
    // example.com.		86400	IN	RRSIG	NS 8 2 86400 20150915033148 20150824191224 54108 example.com. O2TCB5/v/b1XGlTQEj0/oGKp7dTueQ7zRmCtADDEDWrzLdWrKcmDGF37 mgKejcAlSYVhWLxyLlet7KqJhLu+oQcDTNf/BT3vNX/Ivx3sKhUUMpfi 8Mn5zhRqM9gbzZVCS/toJIYqOBqvAkS7UpkmpLzl0Zt2h4j0Gp/8GwRb ZU67l6M=
    // example.com.		86400	IN	RRSIG	AAAA 8 2 86400 20150914212400 20150824191224 54108 example.com. AHd2BDNjtg4jPRQwyT4FHtlVTZDZ6IIusYVGCzWfnt5SZOoizyXnJhqX 44MeVTqi1/2cskpKvRkK3bkYnVUcjZiFgSaa9xJHmXrslaTr5mOmXt9s 6k95N1daYKhDKKcr0M4TXLUgdnBr+/pMFiLsyOoDb8GJDT8Llmpk52Ie ysJX8BY=
    // example.com.		86400	IN	RRSIG	A 8 2 86400 20150914083326 20150824191224 54108 example.com. La1p2R7GPMrXEm3kcznSJ70sOspmfSDsgOZ74GlzgaFfMRveA20IDUnZ /HI9M95/tBWbHdHBtm9aCK+4n7EluhNPTAT1+88V6xK7Lc7pcBfBXIHg DAdUoj26VIh7NRml/0QR0dFu4PriA/wLNe+d1Q961qf0JZP80TU4IMBC X/W6Ijk=
    // example.com.		60	IN	RRSIG	TXT 8 2 60 20150914201612 20150824191224 54108 example.com. Be/bPvaVVK/o66QOHJZMFBDCQVhP44jptS9sZe8Vpfmzd72/v+1gwn1z u2+xisePSpAMtDZsFJgqsCjpbLFvmhNdh8ktlq/kuCME5hZs7qY7DZIB VwkSTsJPIq8qhX22clfIbqzaypuIX9ajWr+5i0nGQLNekMB07t4/GCoJ q5QpQoE=
    // example.com.		3600	IN	RRSIG	DNSKEY 8 2 3600 20150914090528 20150824071818 31406 example.com. rZJRBwHhYzCDwkDEXqECHNWezTNj2A683I/yHHqD1j9ytGHGskGEEyJC i5fk70YCm64GqDYKu70kgv7hCFqc4OM3aD88QDe3L4Uv7ZXqouNbjTEO 3BEBI13GetRkK5qLndl30Y/urOBASQFELQUJsvQBR2gJMdQsb6G0mHIW rubY2SxAGa9rQW7yehRQNK4ME37FqINBDuIV9o7kULPhn9Ux1Qx62prd 9nikzamGxFL+9dFDOfnYVw2C/OgGJNIXh5QyKMG4qXmXb6sB/V3P+FE+ +vkt3RToE2xPN5bf1vVIlEJof6LtojrowwnZpiphTXFJF/BJrgiotGt3 Gsd8Cw==
    // example.com.		3600	IN	DNSKEY	256 3 8 AwEAAcZMEndf6/+kG6Dp7re/grJ9f5CP5bQplBGokyxbM4oPNeBfWMIC +xY+ICgTyJarVB4aPYNMV7znsHM4XwU8hfpZ3ZcmT+69KyGqs+tt2pc/ si30dnUpPo/AMnN7Kul2SgqT9g1bb5O0D/CH2txo6YXr/BbuNHLqAh/x mof1QYkl6GoP
    // example.com.		3600	IN	DNSKEY	256 3 8 AwEAAeZFCLkW/sztmJmpmZo/udvAyqshiLO34zHzzkVPrhuUBA/xb3wk YeCvMO6iBxCD+/Dk7fWEAT1NR21bDKHySVHE5cre+fqnXI+9NCjkMoBE 193j8G5HscIpWpG1qgkelBhmucfUPv+R4AIhpfjc352eh1q/SniYUGR4 fytlDZVXCLhL
    // example.com.		3600	IN	DNSKEY	257 3 8 AwEAAbOFAxl+Lkt0UMglZizKEC1AxUu8zlj65KYatR5wBWMrh18TYzK/ ig6Y1t5YTWCO68bynorpNu9fqNFALX7bVl9/gybA0v0EhF+dgXmoUfRX 7ksMGgBvtfa2/Y9a3klXNLqkTszIQ4PEMVCjtryl19Be9/PkFeC9ITjg MRQsQhmB39eyMYnal+f3bUxKk4fq7cuEU0dbRpue4H/N6jPucXWOwiMA kTJhghqgy+o9FfIp+tR/emKao94/wpVXDcPf5B18j7xz2SvTTxiuqCzC MtsxnikZHcoh1j4g+Y1B8zIMIvrEM+pZGhh/Yuf4RwCBgaYCi9hpiMWV vS4WBzx0/lU=
    // example.com.		3600	IN	RRSIG	SOA 8 2 3600 20150926132522 20150905040848 54108 example.com. q8psdDPaJVo9KPVgMNR2N1by3LMEci+3HyTmN/Xv3DgDFG5MqNlX9Dfj dUBIMbvYmkUUPQ9fIWYA+ldmDHiRBiHIcvvk/LYD8mODWL6RoF+GEsW0 zm43RNBnbE41wtNrch5WU/q1ko2svB98ooqePWWuFzmdyPpidtLCgSCz FCiCiVQ=

    // www
    let www_name: Name = Name::parse("www.example.com.", None).unwrap();

    // www.example.com.	86400	IN	TXT	"v=spf1 -all"
    records.upsert(Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::TXT).dns_class(DNSClass::IN).rdata(RData::TXT(TXT::new(vec!["v=spf1 -all".to_string()]))).clone(), 0);

    // www.example.com.	86400	IN	A	93.184.216.34
    records.upsert(Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::A(Ipv4Addr::new(93,184,216,34))).clone(), 0);

    // www.example.com.	86400	IN	AAAA	2606:2800:220:1:248:1893:25c8:1946
    records.upsert(Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::AAAA).dns_class(DNSClass::IN).rdata(RData::AAAA(Ipv6Addr::new(0x2606,0x2800,0x220,0x1,0x248,0x1893,0x25c8,0x1946))).clone(), 0);

    // www.example.com.	3600	IN	RRSIG	NSEC 8 3 3600 20150925215757 20150905040848 54108 example.com. ZKIVt1IN3O1FWZPSfrQAH7nHt7RUFDjcbh7NxnEqd/uTGCnZ6SrAEgrY E9GMmBwvRjoucphGtjkYOpPJPe5MlnTHoYCjxL4qmG3LsD2KD0bfPufa ibtlQZRrPglxZ92hBKK3ZiPnPRe7I9yni2UQSQA7XDi7CQySYyo490It AxdXjAo=
    // www.example.com.	3600	IN	NSEC	example.com. A TXT AAAA RRSIG NSEC
    // www.example.com.	86400	IN	RRSIG	TXT 8 3 86400 20150914142952 20150824191224 54108 example.com. LvODnPb7NLDZfHPBOrr/qLnOKA670vVYKQSk5Qkz3MPNKDVAFJqsP2Y6 UYcypSJZfcSjfIk2mU9dUiansU2ZL80OZJUsUobqJt5De748ovITYDJ7 afbohQzPg+4E1GIWMkJZ/VQD3B2pmr7J5rPn+vejxSQSoI93AIQaTpCU L5O/Bac=
    // www.example.com.	86400	IN	RRSIG	AAAA 8 3 86400 20150914082216 20150824191224 54108 example.com. kje4FKE+7d/j4OzWQelcKkePq6DxCRY/5btAiUcZNf+zVNlHK+o57h1r Y76ZviWChQB8Np2TjA1DrXGi/kHr2KKE60H5822mFZ2b9O+sgW4q6o3G kO2E1CQxbYe+nI1Z8lVfjdCNm81zfvYqDjo2/tGqagehxG1V9MBZO6br 4KKdoa4=
    // www.example.com.	86400	IN	RRSIG	A 8 3 86400 20150915023456 20150824191224 54108 example.com. cWtw0nMvcXcYNnxejB3Le3KBfoPPQZLmbaJ8ybdmzBDefQOm1ZjZZMOP wHEIxzdjRhG9mLt1mpyo1H7OezKTGX+mDtskcECTl/+jB/YSZyvbwRxj e88Lrg4D+D2MiajQn3XSWf+6LQVe1J67gdbKTXezvux0tRxBNHHqWXRk pxCILes=

    return records;
  }

  pub fn create_secure_example() -> Authority {
    use openssl::crypto::pkey::PKey;
    use ::rr::dnssec::{Algorithm, Signer};

    let mut authority: Authority = create_example();
    let mut pkey = PKey::new();
    pkey.gen(512);
    let signer = Signer::new(Algorithm::RSASHA256, pkey, authority.get_origin().clone(), u32::max_value(), 0);

    authority.add_secure_key(signer);
    authority.secure_zone();

    authority
  }

  #[test]
  fn test_search() {
    let example = create_example();
    let origin = example.get_origin().clone();

    let mut query: Query = Query::new();
    query.name(origin.clone());

    let result = example.search(&query, false);
    if !result.is_empty() {
      assert_eq!(result.first().unwrap().get_rr_type(), RecordType::A);
      assert_eq!(result.first().unwrap().get_dns_class(), DNSClass::IN);
      assert_eq!(result.first().unwrap().get_rdata(), &RData::A(Ipv4Addr::new(93,184,216,34)));
    } else {
      panic!("expected a result");
    }
  }

  /// this is a litte more interesting b/c it requires a recursive lookup for the origin
  #[test]
  fn test_search_www() {
    let example = create_example();
    let www_name = Name::parse("www.example.com.", None).unwrap();

    let mut query: Query = Query::new();
    query.name(www_name.clone());

    let result = example.search(&query, false);
    if !result.is_empty() {
      assert_eq!(result.first().unwrap().get_rr_type(), RecordType::A);
      assert_eq!(result.first().unwrap().get_dns_class(), DNSClass::IN);
      assert_eq!(result.first().unwrap().get_rdata(), &RData::A(Ipv4Addr::new(93,184,216,34)));
    } else {
      panic!("expected a result");
    }
  }

  #[test]
  fn test_authority() {
    let authority: Authority = create_example();

    assert!(authority.get_soa().is_some());
    assert_eq!(authority.get_soa().unwrap().get_dns_class(), DNSClass::IN);

    assert!(!authority.lookup(authority.get_origin(), RecordType::NS, false).is_empty());

    let mut lookup: Vec<_> = authority.get_ns(false);
    lookup.sort();

    assert_eq!(**lookup.first().unwrap(), Record::new().name(authority.get_origin().clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()) ).clone());
    assert_eq!(**lookup.last().unwrap(), Record::new().name(authority.get_origin().clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS(Name::parse("b.iana-servers.net.", None).unwrap()) ).clone());

    assert!(!authority.lookup(authority.get_origin(), RecordType::TXT, false).is_empty());

    let mut lookup: Vec<_> = authority.lookup(authority.get_origin(), RecordType::TXT, false);
    lookup.sort();

    assert_eq!(**lookup.first().unwrap(), Record::new().name(authority.get_origin().clone()).ttl(60).rr_type(RecordType::TXT).dns_class(DNSClass::IN).rdata(RData::TXT(TXT::new(vec!["$Id: example.com 4415 2015-08-24 20:12:23Z davids $".to_string()]))).clone());

    assert_eq!(**authority.lookup(authority.get_origin(), RecordType::A, false).first().unwrap(), Record::new().name(authority.get_origin().clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::A(Ipv4Addr::new(93,184,216,34))).clone());
  }

  #[test]
  fn test_authorize() {
    let authority: Authority = create_example();

    let mut message = Message::new();
    message.id(10).message_type(MessageType::Query).op_code(OpCode::Update);

    assert_eq!(authority.authorize(&message), Err(ResponseCode::Refused));

    // TODO: this will nee to be more complex as additional policies are added
    // authority.set_allow_update(true);
    // assert!(authority.authorize(&message).is_ok());
  }

  #[test]
  fn test_prerequisites() {
    let not_zone = Name::new().label("not").label("a").label("domain").label("com");
    let not_in_zone = Name::new().label("not").label("example").label("com");

    let mut authority: Authority = create_example();
    authority.set_allow_update(true);

    // first check the initial negatives, ttl = 0, and the zone is the same
    assert_eq!(authority.verify_prerequisites(&[Record::new().name(not_in_zone.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::NULL(NULL::new())).clone()]), Err(ResponseCode::FormErr));
    assert_eq!(authority.verify_prerequisites(&[Record::new().name(not_zone.clone()).ttl(0).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::NULL(NULL::new())).clone()]), Err(ResponseCode::NotZone));

    // *   ANY      ANY      empty    Name is in use
    assert!(authority.verify_prerequisites(&[Record::new().name(authority.get_origin().clone()).ttl(0).dns_class(DNSClass::ANY).rr_type(RecordType::ANY).rdata(RData::NULL(NULL::new())).clone()]).is_ok());
    assert_eq!(authority.verify_prerequisites(&[Record::new().name(not_in_zone.clone()).ttl(0).dns_class(DNSClass::ANY).rr_type(RecordType::ANY).rdata(RData::NULL(NULL::new())).clone()]), Err(ResponseCode::NXDomain));

    // *   ANY      rrset    empty    RRset exists (value independent)
    assert!(authority.verify_prerequisites(&[Record::new().name(authority.get_origin().clone()).ttl(0).dns_class(DNSClass::ANY).rr_type(RecordType::A).rdata(RData::NULL(NULL::new())).clone()]).is_ok());
    assert_eq!(authority.verify_prerequisites(&[Record::new().name(not_in_zone.clone()).ttl(0).dns_class(DNSClass::ANY).rr_type(RecordType::A).rdata(RData::NULL(NULL::new())).clone()]), Err(ResponseCode::NXRRSet));

    // *   NONE     ANY      empty    Name is not in use
    assert!(authority.verify_prerequisites(&[Record::new().name(not_in_zone.clone()).ttl(0).dns_class(DNSClass::NONE).rr_type(RecordType::ANY).rdata(RData::NULL(NULL::new())).clone()]).is_ok());
    assert_eq!(authority.verify_prerequisites(&[Record::new().name(authority.get_origin().clone()).ttl(0).dns_class(DNSClass::NONE).rr_type(RecordType::ANY).rdata(RData::NULL(NULL::new())).clone()]), Err(ResponseCode::YXDomain));

    // *   NONE     rrset    empty    RRset does not exist
    assert!(authority.verify_prerequisites(&[Record::new().name(not_in_zone.clone()).ttl(0).dns_class(DNSClass::NONE).rr_type(RecordType::A).rdata(RData::NULL(NULL::new())).clone()]).is_ok());
    assert_eq!(authority.verify_prerequisites(&[Record::new().name(authority.get_origin().clone()).ttl(0).dns_class(DNSClass::NONE).rr_type(RecordType::A).rdata(RData::NULL(NULL::new())).clone()]), Err(ResponseCode::YXRRSet));

    // *   zone     rrset    rr       RRset exists (value dependent)
    assert!(authority.verify_prerequisites(&[Record::new().name(authority.get_origin().clone()).ttl(0).dns_class(DNSClass::IN).rr_type(RecordType::A).rdata(RData::A(Ipv4Addr::new(93,184,216,34))).clone()]).is_ok());
    // wrong class
    assert_eq!(authority.verify_prerequisites(&[Record::new().name(authority.get_origin().clone()).ttl(0).dns_class(DNSClass::CH).rr_type(RecordType::A).rdata(RData::A(Ipv4Addr::new(93,184,216,34))).clone()]), Err(ResponseCode::FormErr));
    // wrong Name
    assert_eq!(authority.verify_prerequisites(&[Record::new().name(not_in_zone.clone()).ttl(0).dns_class(DNSClass::IN).rr_type(RecordType::A).rdata(RData::A(Ipv4Addr::new(93,184,216,24))).clone()]), Err(ResponseCode::NXRRSet));
    // wrong IP
    assert_eq!(authority.verify_prerequisites(&[Record::new().name(authority.get_origin().clone()).ttl(0).dns_class(DNSClass::IN).rr_type(RecordType::A).rdata(RData::A(Ipv4Addr::new(93,184,216,24))).clone()]), Err(ResponseCode::NXRRSet));
  }

  #[test]
  fn test_pre_scan() {
    let up_name = Name::new().label("www").label("example").label("com");
    let not_zone = Name::new().label("not").label("zone").label("com");

    let authority: Authority = create_example();

    assert_eq!(authority.pre_scan(&[Record::new().name(not_zone.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::A(Ipv4Addr::new(93,184,216,24))).clone()]), Err(ResponseCode::NotZone));

    assert_eq!(authority.pre_scan(&[Record::new().name(up_name.clone()).ttl(86400).rr_type(RecordType::ANY).dns_class(DNSClass::IN).rdata(RData::NULL(NULL::new()) ).clone()]), Err(ResponseCode::FormErr));
    assert_eq!(authority.pre_scan(&[Record::new().name(up_name.clone()).ttl(86400).rr_type(RecordType::AXFR).dns_class(DNSClass::IN).rdata(RData::NULL(NULL::new()) ).clone()]), Err(ResponseCode::FormErr));
    assert_eq!(authority.pre_scan(&[Record::new().name(up_name.clone()).ttl(86400).rr_type(RecordType::IXFR).dns_class(DNSClass::IN).rdata(RData::NULL(NULL::new()) ).clone()]), Err(ResponseCode::FormErr));
    assert!(authority.pre_scan(&[Record::new().name(up_name.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::A(Ipv4Addr::new(93,184,216,24))).clone()]).is_ok());
    assert!(authority.pre_scan(&[Record::new().name(up_name.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::NULL(NULL::new())).clone()]).is_ok());

    assert_eq!(authority.pre_scan(&[Record::new().name(up_name.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::ANY).rdata(RData::A(Ipv4Addr::new(93,184,216,24))).clone()]), Err(ResponseCode::FormErr));
    assert_eq!(authority.pre_scan(&[Record::new().name(up_name.clone()).ttl(0).rr_type(RecordType::A).dns_class(DNSClass::ANY).rdata(RData::A(Ipv4Addr::new(93,184,216,24))).clone()]), Err(ResponseCode::FormErr));
    assert_eq!(authority.pre_scan(&[Record::new().name(up_name.clone()).ttl(0).rr_type(RecordType::AXFR).dns_class(DNSClass::ANY).rdata(RData::NULL(NULL::new())).clone()]), Err(ResponseCode::FormErr));
    assert_eq!(authority.pre_scan(&[Record::new().name(up_name.clone()).ttl(0).rr_type(RecordType::IXFR).dns_class(DNSClass::ANY).rdata(RData::NULL(NULL::new())).clone()]), Err(ResponseCode::FormErr));
    assert!(authority.pre_scan(&[Record::new().name(up_name.clone()).ttl(0).rr_type(RecordType::ANY).dns_class(DNSClass::ANY).rdata(RData::NULL(NULL::new())).clone()]).is_ok());
    assert!(authority.pre_scan(&[Record::new().name(up_name.clone()).ttl(0).rr_type(RecordType::A).dns_class(DNSClass::ANY).rdata(RData::NULL(NULL::new())).clone()]).is_ok());

    assert_eq!(authority.pre_scan(&[Record::new().name(up_name.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::NONE).rdata(RData::NULL(NULL::new())).clone()]), Err(ResponseCode::FormErr));
    assert_eq!(authority.pre_scan(&[Record::new().name(up_name.clone()).ttl(0).rr_type(RecordType::ANY).dns_class(DNSClass::NONE).rdata(RData::NULL(NULL::new())).clone()]), Err(ResponseCode::FormErr));
    assert_eq!(authority.pre_scan(&[Record::new().name(up_name.clone()).ttl(0).rr_type(RecordType::AXFR).dns_class(DNSClass::NONE).rdata(RData::NULL(NULL::new())).clone()]), Err(ResponseCode::FormErr));
    assert_eq!(authority.pre_scan(&[Record::new().name(up_name.clone()).ttl(0).rr_type(RecordType::IXFR).dns_class(DNSClass::NONE).rdata(RData::NULL(NULL::new())).clone()]), Err(ResponseCode::FormErr));
    assert!(authority.pre_scan(&[Record::new().name(up_name.clone()).ttl(0).rr_type(RecordType::A).dns_class(DNSClass::NONE).rdata(RData::NULL(NULL::new())).clone()]).is_ok());
    assert!(authority.pre_scan(&[Record::new().name(up_name.clone()).ttl(0).rr_type(RecordType::A).dns_class(DNSClass::NONE).rdata(RData::A(Ipv4Addr::new(93,184,216,24))).clone()]).is_ok());

    assert_eq!(authority.pre_scan(&[Record::new().name(up_name.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::CH).rdata(RData::NULL(NULL::new())).clone()]), Err(ResponseCode::FormErr));
  }

  #[test]
  fn test_update() {
    let new_name = Name::new().label("new").label("example").label("com");
    let www_name = Name::new().label("www").label("example").label("com");
    let mut authority: Authority = create_example();
    let serial = authority.get_serial();

    authority.set_allow_update(true);

    let mut original_vec: Vec<Record> = vec![
      Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::TXT).dns_class(DNSClass::IN).rdata(RData::TXT(TXT::new(vec!["v=spf1 -all".to_string()]))).clone(),
      Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::A(Ipv4Addr::new(93,184,216,34))).clone(),
      Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::AAAA).dns_class(DNSClass::IN).rdata(RData::AAAA(Ipv6Addr::new(0x2606,0x2800,0x220,0x1,0x248,0x1893,0x25c8,0x1946))).clone(),
    ];

    original_vec.sort();

    {
      // assert that the correct set of records is there.
      let mut www_rrset: Vec<&Record> = authority.lookup(&www_name, RecordType::ANY, false);
      www_rrset.sort();

      assert_eq!(www_rrset, original_vec.iter().collect::<Vec<&Record>>());

      // assert new record doesn't exist
      assert!(authority.lookup(&new_name, RecordType::ANY, false).is_empty());
    }

    //
    //  zone     rrset    rr       Add to an RRset
    let add_record = &[Record::new().name(new_name.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::A(Ipv4Addr::new(93,184,216,24))).clone()];
    assert!(authority.update_records(add_record).expect("update failed"));
    assert_eq!(authority.lookup(&new_name, RecordType::ANY, false), add_record.iter().collect::<Vec<&Record>>());
    assert_eq!(serial + 1, authority.get_serial());

    let add_www_record = &[Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::A(Ipv4Addr::new(10,0,0,1))).clone()];
    assert!(authority.update_records(add_www_record).expect("update failed"));
    assert_eq!(serial + 2, authority.get_serial());

    {
      let mut www_rrset = authority.lookup(&www_name, RecordType::ANY, false);
      www_rrset.sort();

      let mut plus_10 = original_vec.clone();
      plus_10.push(add_www_record[0].clone());
      plus_10.sort();
      assert_eq!(www_rrset, plus_10.iter().collect::<Vec<&Record>>());
    }

    //
    //  NONE     rrset    rr       Delete an RR from an RRset
    let del_record = &[Record::new().name(new_name.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::NONE).rdata(RData::A(Ipv4Addr::new(93,184,216,24))).clone()];
    assert!(authority.update_records(del_record).expect("update failed"));
    assert_eq!(serial + 3, authority.get_serial());
    {
      println!("after delete of specific record: {:?}", authority.lookup(&new_name, RecordType::ANY, false));
      assert!(authority.lookup(&new_name, RecordType::ANY, false).is_empty());
    }

    // remove one from www
    let del_record = &[Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::NONE).rdata(RData::A(Ipv4Addr::new(10,0,0,1))).clone()];
    assert!(authority.update_records(del_record).expect("update failed"));
    assert_eq!(serial + 4, authority.get_serial());
    {
      let mut www_rrset = authority.lookup(&www_name, RecordType::ANY, false);
      www_rrset.sort();

      assert_eq!(www_rrset, original_vec.iter().collect::<Vec<&Record>>());
    }

    //
    //  ANY      rrset    empty    Delete an RRset
    let del_record = &[Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::ANY).rdata(RData::NULL(NULL::new())).clone()];
    assert!(authority.update_records(del_record).expect("update failed"));
    assert_eq!(serial + 5, authority.get_serial());
    let mut removed_a_vec: Vec<_> = vec![
      Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::TXT).dns_class(DNSClass::IN).rdata(RData::TXT(TXT::new(vec!["v=spf1 -all".to_string()]))).clone(),
      Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::AAAA).dns_class(DNSClass::IN).rdata(RData::AAAA(Ipv6Addr::new(0x2606,0x2800,0x220,0x1,0x248,0x1893,0x25c8,0x1946))).clone(),
    ];
    removed_a_vec.sort();

    {
      let mut www_rrset = authority.lookup(&www_name, RecordType::ANY, false);
      www_rrset.sort();

      assert_eq!(www_rrset, removed_a_vec.iter().collect::<Vec<&Record>>());
    }

    //
    //  ANY      ANY      empty    Delete all RRsets from a name
    println!("deleting all records");
    let del_record = &[Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::ANY).dns_class(DNSClass::ANY).rdata(RData::NULL(NULL::new())).clone()];
    assert!(authority.update_records(del_record).expect("update failed"));
    assert!(authority.lookup(&www_name, RecordType::ANY, false).is_empty());
    assert_eq!(serial + 6, authority.get_serial());
  }

  #[test]
  fn test_zone_signing() {
    use ::rr::{RData};

    let authority: Authority = create_secure_example();

    let results = authority.lookup(&authority.get_origin(), RecordType::AXFR, true);

    assert!(results.iter().any(|r| r.get_rr_type() == RecordType::DNSKEY), "must contain a DNSKEY");

    for record in results.iter() {
      if record.get_rr_type() == RecordType::RRSIG { continue }
      if record.get_rr_type() == RecordType::DNSKEY { continue }

      // validate all records have associated RRSIGs after signing
      assert!(results.iter().any(|r| r.get_rr_type() == RecordType::RRSIG &&
                                     r.get_name() == record.get_name() &&
                                     if let &RData::SIG(ref rrsig) = r.get_rdata() {
                                       rrsig.get_type_covered() == record.get_rr_type()
                                     } else {
                                       false
                                     } ), "record type not covered: {:?}", record);
    }
  }

  #[test]
  fn test_get_nsec() {
    let name = Name::new().label("zzz").label("example").label("com");
    let authority: Authority = create_secure_example();

    let results = authority.get_nsec_records(&name, true);

    for record in results.iter() {
      assert!(record.get_name() < &name);
    }
  }
}
