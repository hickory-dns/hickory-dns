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
use std::collections::{HashMap, HashSet};

use ::authority::{UpdateResult, ZoneType};
use ::op::{UpdateMessage, ResponseCode};
use ::rr::*;

/// Authority is the storage method for all resource records
#[derive(Debug)]
pub struct Authority {
  origin: Name,
  records: HashMap<Name, HashSet<Record>>,
  zone_type: ZoneType,
  allow_update: bool,
}

impl Authority {
  pub fn new(origin: Name, records: HashMap<Name, HashSet<Record>>, zone_type: ZoneType, allow_update: bool) -> Authority {
    Authority{ origin: origin, records: records, zone_type: zone_type, allow_update: allow_update}
  }

  fn set_allow_update(&mut self, allow_update: bool) {
    self.allow_update = allow_update;
  }

  pub fn get_origin(&self) -> &Name {
    &self.origin
  }

  pub fn get_zone_type(&self) -> ZoneType {
    self.zone_type
  }

  pub fn get_soa(&self) -> Option<Record> {
    // SOA should be origin|SOA
    self.lookup(&self.origin, RecordType::SOA, DNSClass::IN).and_then(|v|v.first().cloned())
  }

  pub fn get_ns(&self) -> Option<Vec<Record>> {
    self.lookup(&self.origin, RecordType::NS, DNSClass::IN)
  }

 /*
  * RFC 2136                       DNS Update                     April 1997
  *
  * 3.2 - Process Prerequisite Section
  *
  *   Next, the Prerequisite Section is checked to see that all
  *   prerequisites are satisfied by the current state of the zone.  Using
  *   the definitions expressed in Section 1.2, if any RR's NAME is not
  *   within the zone specified in the Zone Section, signal NOTZONE to the
  *   requestor.
  *
  *   3.2.1. For RRs in this section whose CLASS is ANY, test to see that
  *   TTL and RDLENGTH are both zero (0), else signal FORMERR to the
  *   requestor.  If TYPE is ANY, test to see that there is at least one RR
  *   in the zone whose NAME is the same as that of the Prerequisite RR,
  *   else signal NXDOMAIN to the requestor.  If TYPE is not ANY, test to
  *   see that there is at least one RR in the zone whose NAME and TYPE are
  *   the same as that of the Prerequisite RR, else signal NXRRSET to the
  *   requestor.
  *
  *   3.2.2. For RRs in this section whose CLASS is NONE, test to see that
  *   the TTL and RDLENGTH are both zero (0), else signal FORMERR to the
  *   requestor.  If the TYPE is ANY, test to see that there are no RRs in
  *   the zone whose NAME is the same as that of the Prerequisite RR, else
  *   signal YXDOMAIN to the requestor.  If the TYPE is not ANY, test to
  *   see that there are no RRs in the zone whose NAME and TYPE are the
  *   same as that of the Prerequisite RR, else signal YXRRSET to the
  *   requestor.
  *
  *   3.2.3. For RRs in this section whose CLASS is the same as the ZCLASS,
  *   test to see that the TTL is zero (0), else signal FORMERR to the
  *   requestor.  Then, build an RRset for each unique <NAME,TYPE> and
  *   compare each resulting RRset for set equality (same members, no more,
  *   no less) with RRsets in the zone.  If any Prerequisite RRset is not
  *   entirely and exactly matched by a zone RRset, signal NXRRSET to the
  *   requestor.  If any RR in this section has a CLASS other than ZCLASS
  *   or NONE or ANY, signal FORMERR to the requestor.
  *
  *   3.2.4 - Table Of Metavalues Used In Prerequisite Section
  *
  *   CLASS    TYPE     RDATA    Meaning
  *   ------------------------------------------------------------
  *   ANY      ANY      empty    Name is in use
  *   ANY      rrset    empty    RRset exists (value independent)
  *   NONE     ANY      empty    Name is not in use
  *   NONE     rrset    empty    RRset does not exist
  *   zone     rrset    rr       RRset exists (value dependent)
  *
  *   3.2.5 - Pseudocode for Prerequisite Section Processing
  *
  *      for rr in prerequisites
  *           if (rr.ttl != 0)
  *                return (FORMERR)
  *           if (zone_of(rr.name) != ZNAME)
  *                return (NOTZONE);
  *           if (rr.class == ANY)
  *                if (rr.rdlength != 0)
  *                     return (FORMERR)
  *                if (rr.type == ANY)
  *                     if (!zone_name<rr.name>)
  *                          return (NXDOMAIN)
  *                else
  *                     if (!zone_rrset<rr.name, rr.type>)
  *                          return (NXRRSET)
  *           if (rr.class == NONE)
  *                if (rr.rdlength != 0)
  *                     return (FORMERR)
  *                if (rr.type == ANY)
  *                     if (zone_name<rr.name>)
  *                          return (YXDOMAIN)
  *                else
  *                     if (zone_rrset<rr.name, rr.type>)
  *                          return (YXRRSET)
  *           if (rr.class == zclass)
  *                temp<rr.name, rr.type> += rr
  *           else
  *                return (FORMERR)
  *
  *      for rrset in temp
  *           if (zone_rrset<rrset.name, rrset.type> != rrset)
  *                return (NXRRSET)
  */
  fn verify_prerequisites(&self, pre_requisites: &[Record]) -> UpdateResult<()> {
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
          if let &RData::NULL{ .. } = require.get_rdata() {
            match require.get_rr_type() {
              // ANY      ANY      empty    Name is in use
              RecordType::ANY => {
                if let None = self.lookup(require.get_name(), RecordType::ANY, DNSClass::ANY) {
                  return Err(ResponseCode::NXDomain);
                } else {
                  continue;
                }
              },
              // ANY      rrset    empty    RRset exists (value independent)
              rrset @ _ => {
                if let None = self.lookup(require.get_name(), rrset, DNSClass::ANY) {
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
          if let &RData::NULL{ .. } = require.get_rdata() {
            match require.get_rr_type() {
              // NONE     ANY      empty    Name is not in use
              RecordType::ANY => {
                if let Some(..) = self.lookup(require.get_name(), RecordType::ANY, DNSClass::ANY) {
                  return Err(ResponseCode::YXDomain);
                } else {
                  continue;
                }
              },
              // NONE     rrset    empty    RRset does not exist
              rrset @ _ => {
                if let Some(..) = self.lookup(require.get_name(), rrset, DNSClass::ANY) {
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
        class @ _ if class == try!(self.get_soa().ok_or(ResponseCode::ServFail)).get_dns_class() =>
          // zone     rrset    rr       RRset exists (value dependent)
          if let Some(rrset) = self.lookup(require.get_name(), require.get_rr_type(), class) {
            if rrset.iter().filter(|rr| *rr == require).next().is_none() {
              return Err(ResponseCode::NXRRSet);
            } else {
              continue;
            }
          } else {
            return Err(ResponseCode::NXRRSet);
          }
          ,
        _ => return Err(ResponseCode::FormErr),
      }
    }

    // if we didn't bail everything checked out...
    Ok(())
  }

  /*
   * RFC 2136                       DNS Update                     April 1997
   *
   * 3.3 - Check Requestor's Permissions
   *
   *   3.3.1. Next, the requestor's permission to update the RRs named in
   *   the Update Section may be tested in an implementation dependent
   *   fashion or using mechanisms specified in a subsequent Secure DNS
   *   Update protocol.  If the requestor does not have permission to
   *   perform these updates, the server may write a warning message in its
   *   operations log, and may either signal REFUSED to the requestor, or
   *   ignore the permission problem and proceed with the update.
   *
   *   3.3.2. While the exact processing is implementation defined, if these
   *   verification activities are to be performed, this is the point in the
   *   server's processing where such performance should take place, since
   *   if a REFUSED condition is encountered after an update has been
   *   partially applied, it will be necessary to undo the partial update
   *   and restore the zone to its original state before answering the
   *   requestor.
   *
   *   3.3.3 - Pseudocode for Permission Checking
   *
   *      if (security policy exists)
   *           if (this update is not permitted)
   *                if (local option)
   *                     log a message about permission problem
   *                if (local option)
   *                     return (REFUSED)
   */
  fn authorize(&self) -> UpdateResult<()> {
    if !self.allow_update {
      warn!("update attempted on non-updatable Authority: {}", self.origin);
      Err(ResponseCode::Refused)
    } else {
      Ok(())
    }
  }

  /*
   * RFC 2136                       DNS Update                     April 1997
   *
   *   3.4 - Process Update Section
   *
   *   Next, the Update Section is processed as follows.
   *
   *   3.4.1 - Prescan
   *
   *   The Update Section is parsed into RRs and each RR's CLASS is checked
   *   to see if it is ANY, NONE, or the same as the Zone Class, else signal
   *   a FORMERR to the requestor.  Using the definitions in Section 1.2,
   *   each RR's NAME must be in the zone specified by the Zone Section,
   *   else signal NOTZONE to the requestor.
   *
   *   3.4.1.2. For RRs whose CLASS is not ANY, check the TYPE and if it is
   *   ANY, AXFR, MAILA, MAILB, or any other QUERY metatype, or any
   *   unrecognized type, then signal FORMERR to the requestor.  For RRs
   *   whose CLASS is ANY or NONE, check the TTL to see that it is zero (0),
   *   else signal a FORMERR to the requestor.  For any RR whose CLASS is
   *   ANY, check the RDLENGTH to make sure that it is zero (0) (that is,
   *   the RDATA field is empty), and that the TYPE is not AXFR, MAILA,
   *   MAILB, or any other QUERY metatype besides ANY, or any unrecognized
   *   type, else signal FORMERR to the requestor.
   *
   *   3.4.1.3 - Pseudocode For Update Section Prescan
   *
   *      [rr] for rr in updates
   *           if (zone_of(rr.name) != ZNAME)
   *                return (NOTZONE);
   *           if (rr.class == zclass)
   *                if (rr.type & ANY|AXFR|MAILA|MAILB)
   *                     return (FORMERR)
   *           elsif (rr.class == ANY)
   *                if (rr.ttl != 0 || rr.rdlength != 0
   *                    || rr.type & AXFR|MAILA|MAILB)
   *                     return (FORMERR)
   *           elsif (rr.class == NONE)
   *                if (rr.ttl != 0 || rr.type & ANY|AXFR|MAILA|MAILB)
   *                     return (FORMERR)
   *           else
   *                return (FORMERR)
   */
  fn pre_scan(&self, record: &Record) -> UpdateResult<()> {
    Err(ResponseCode::NotImp)
  }
  /*
   * RFC 2136                       DNS Update                     April 1997
   *
   *   3.4 - Process Update Section
   *
   *   Next, the Update Section is processed as follows.
   *
   *   3.4.2 - Update
   *
   *   The Update Section is parsed into RRs and these RRs are processed in
   *   order.
   *
   *   3.4.2.1. If any system failure (such as an out of memory condition,
   *   or a hardware error in persistent storage) occurs during the
   *   processing of this section, signal SERVFAIL to the requestor and undo
   *   all updates applied to the zone during this transaction.
   *
   *   3.4.2.2. Any Update RR whose CLASS is the same as ZCLASS is added to
   *   the zone.  In case of duplicate RDATAs (which for SOA RRs is always
   *   the case, and for WKS RRs is the case if the ADDRESS and PROTOCOL
   *   fields both match), the Zone RR is replaced by Update RR.  If the
   *   TYPE is SOA and there is no Zone SOA RR, or the new SOA.SERIAL is
   *   lower (according to [RFC1982]) than or equal to the current Zone SOA
   *   RR's SOA.SERIAL, the Update RR is ignored.  In the case of a CNAME
   *   Update RR and a non-CNAME Zone RRset or vice versa, ignore the CNAME
   *   Update RR, otherwise replace the CNAME Zone RR with the CNAME Update
   *   RR.
   *
   *   3.4.2.3. For any Update RR whose CLASS is ANY and whose TYPE is ANY,
   *   all Zone RRs with the same NAME are deleted, unless the NAME is the
   *   same as ZNAME in which case only those RRs whose TYPE is other than
   *   SOA or NS are deleted.  For any Update RR whose CLASS is ANY and
   *   whose TYPE is not ANY all Zone RRs with the same NAME and TYPE are
   *   deleted, unless the NAME is the same as ZNAME in which case neither
   *   SOA or NS RRs will be deleted.
   *
   *   3.4.2.4. For any Update RR whose class is NONE, any Zone RR whose
   *   NAME, TYPE, RDATA and RDLENGTH are equal to the Update RR is deleted,
   *   unless the NAME is the same as ZNAME and either the TYPE is SOA or
   *   the TYPE is NS and the matching Zone RR is the only NS remaining in
   *   the RRset, in which case this Update RR is ignored.
   *
   *   3.4.2.5. Signal NOERROR to the requestor.
   *
   *   3.4.2.6 - Table Of Metavalues Used In Update Section
   *
   *   CLASS    TYPE     RDATA    Meaning
   *   ---------------------------------------------------------
   *   ANY      ANY      empty    Delete all RRsets from a name
   *   ANY      rrset    empty    Delete an RRset
   *   NONE     rrset    rr       Delete an RR from an RRset
   *   zone     rrset    rr       Add to an RRset
   *
   *   3.4.2.7 - Pseudocode For Update Section Processing
   *
   *      [rr] for rr in updates
   *           if (rr.class == zclass)
   *                if (rr.type == CNAME)
   *                     if (zone_rrset<rr.name, ~CNAME>)
   *                          next [rr]
   *                elsif (zone_rrset<rr.name, CNAME>)
   *                     next [rr]
   *                if (rr.type == SOA)
   *                     if (!zone_rrset<rr.name, SOA> ||
   *                         zone_rr<rr.name, SOA>.serial > rr.soa.serial)
   *                          next [rr]
   *                for zrr in zone_rrset<rr.name, rr.type>
   *                     if (rr.type == CNAME || rr.type == SOA ||
   *                         (rr.type == WKS && rr.proto == zrr.proto &&
   *                          rr.address == zrr.address) ||
   *                         rr.rdata == zrr.rdata)
   *                          zrr = rr
   *                          next [rr]
   *                zone_rrset<rr.name, rr.type> += rr
   *           elsif (rr.class == ANY)
   *                if (rr.type == ANY)
   *                     if (rr.name == zname)
   *                          zone_rrset<rr.name, ~(SOA|NS)> = Nil
   *                     else
   *                          zone_rrset<rr.name, *> = Nil
   *                elsif (rr.name == zname &&
   *                       (rr.type == SOA || rr.type == NS))
   *                     next [rr]
   *                else
   *                     zone_rrset<rr.name, rr.type> = Nil
   *           elsif (rr.class == NONE)
   *                if (rr.type == SOA)
   *                     next [rr]
   *                if (rr.type == NS && zone_rrset<rr.name, NS> == rr)
   *                     next [rr]
   *                zone_rr<rr.name, rr.type, rr.data> = Nil
   *      return (NOERROR)
   */
  pub fn update(&mut self, update: &UpdateMessage) -> UpdateResult<()> {
    // the spec says to authorize after prereqs, seems better to auth first.
    try!(self.authorize());
    try!(self.verify_prerequisites(update.get_pre_requisites()));
    Err(ResponseCode::NotImp)
  }

  /// upserts into the resource vector
  /// Guarantees that SOA, CNAME only has one record, will implicitly update if they already exist
  pub fn upsert(&mut self, name: Name, record: Record) {
    let records: &mut HashSet<Record, _> = self.records.entry(name).or_insert(HashSet::new());

    // RFC 2136                       DNS Update                     April 1997
    //
    // 1.1.5. The following RR types cannot be appended to an RRset.  If the
    //  following comparison rules are met, then an attempt to add the new RR
    //  will result in the replacement of the previous RR:
    //
    // SOA    compare only NAME, CLASS and TYPE -- it is not possible to
    //         have more than one SOA per zone, even if any of the data
    //         fields differ.
    //
    // CNAME  compare only NAME, CLASS, and TYPE -- it is not possible
    //         to have more than one CNAME RR, even if their data fields
    //         differ.
    match record.get_rr_type() {
      RecordType::SOA | RecordType::CNAME => {
        records.clear();
      },
      _ => ()/* nothing to do */,
    }

    records.insert(record);
  }

  fn matches_record_type_and_class(record: &Record, rtype: RecordType, class: DNSClass) -> bool {
    (rtype == RecordType::ANY || record.get_rr_type() == rtype) &&
    (class == DNSClass::ANY || record.get_dns_class() == class)
  }

  pub fn lookup(&self, name: &Name, rtype: RecordType, class: DNSClass) -> Option<Vec<Record>> {
    // TODO this should be an unnecessary clone... need to create a key type, and then use that for
    //  all queries
    let result: Option<Vec<Record>> = self.records.get(name).map(|v|v.iter().filter(|r| Self::matches_record_type_and_class(r, rtype, class)).cloned().collect());
    if let Some(ref v) = result {
      if v.is_empty() {
        return None;
      }
    }

    result
  }
}

#[cfg(test)]
pub mod authority_tests {
  use std::collections::HashMap;
  use std::net::{Ipv4Addr,Ipv6Addr};

  use ::authority::ZoneType;
  use ::rr::*;
  use ::op::*;
  use super::*;

  pub fn create_example() -> Authority {
    let origin: Name = Name::parse("example.com.", None,).unwrap();
    let mut records: Authority = Authority::new(origin.clone(), HashMap::new(), ZoneType::Master, false);
    // example.com.		3600	IN	SOA	sns.dns.icann.org. noc.dns.icann.org. 2015082403 7200 3600 1209600 3600
    records.upsert(origin.clone(), Record::new().name(origin.clone()).ttl(3600).rr_type(RecordType::SOA).dns_class(DNSClass::IN).rdata(RData::SOA{ mname: Name::parse("sns.dns.icann.org.", None).unwrap(), rname: Name::parse("noc.dns.icann.org.", None).unwrap(), serial: 2015082403, refresh: 7200, retry: 3600, expire: 1209600, minimum: 3600 }).clone());

    records.upsert(origin.clone(), Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS{ nsdname: Name::parse("a.iana-servers.net.", None).unwrap() }).clone());
    records.upsert(origin.clone(), Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS{ nsdname: Name::parse("b.iana-servers.net.", None).unwrap() }).clone());

    // test a different class from IN
    records.upsert(origin.clone(), Record::new().name(origin.clone()).ttl(3600).rr_type(RecordType::TXT).dns_class(DNSClass::HS).rdata(RData::TXT{ txt_data: vec!["foo=bar".to_string()] }).clone());
    // example.com.		60	IN	TXT	"v=spf1 -all"
    records.upsert(origin.clone(), Record::new().name(origin.clone()).ttl(60).rr_type(RecordType::TXT).dns_class(DNSClass::IN).rdata(RData::TXT{ txt_data: vec!["v=spf1 -all".to_string()] }).clone());
    // example.com.		60	IN	TXT	"$Id: example.com 4415 2015-08-24 20:12:23Z davids $"
    records.upsert(origin.clone(), Record::new().name(origin.clone()).ttl(60).rr_type(RecordType::TXT).dns_class(DNSClass::HS).rdata(RData::TXT{ txt_data: vec!["$Id: example.com 4415 2015-08-24 20:12:23Z davids $".to_string()] }).clone());

    // example.com.		86400	IN	A	93.184.216.34
    records.upsert(origin.clone(), Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::A{ address: Ipv4Addr::new(93,184,216,34) }).clone());

    // example.com.		86400	IN	AAAA	2606:2800:220:1:248:1893:25c8:1946
    records.upsert(origin.clone(), Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::AAAA).dns_class(DNSClass::IN).rdata(RData::AAAA{ address: Ipv6Addr::new(0x2606,0x2800,0x220,0x1,0x248,0x1893,0x25c8,0x1946) }).clone());

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
    records.upsert(www_name.clone(), Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::TXT).dns_class(DNSClass::IN).rdata(RData::TXT{ txt_data: vec!["v=spf1 -all".to_string()] }).clone());

    // www.example.com.	86400	IN	A	93.184.216.34
    records.upsert(www_name.clone(), Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::A{ address: Ipv4Addr::new(93,184,216,34) }).clone());

    // www.example.com.	86400	IN	AAAA	2606:2800:220:1:248:1893:25c8:1946
    records.upsert(www_name.clone(), Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::AAAA).dns_class(DNSClass::IN).rdata(RData::AAAA{ address: Ipv6Addr::new(0x2606,0x2800,0x220,0x1,0x248,0x1893,0x25c8,0x1946) }).clone());

    // www.example.com.	3600	IN	RRSIG	NSEC 8 3 3600 20150925215757 20150905040848 54108 example.com. ZKIVt1IN3O1FWZPSfrQAH7nHt7RUFDjcbh7NxnEqd/uTGCnZ6SrAEgrY E9GMmBwvRjoucphGtjkYOpPJPe5MlnTHoYCjxL4qmG3LsD2KD0bfPufa ibtlQZRrPglxZ92hBKK3ZiPnPRe7I9yni2UQSQA7XDi7CQySYyo490It AxdXjAo=
    // www.example.com.	3600	IN	NSEC	example.com. A TXT AAAA RRSIG NSEC
    // www.example.com.	86400	IN	RRSIG	TXT 8 3 86400 20150914142952 20150824191224 54108 example.com. LvODnPb7NLDZfHPBOrr/qLnOKA670vVYKQSk5Qkz3MPNKDVAFJqsP2Y6 UYcypSJZfcSjfIk2mU9dUiansU2ZL80OZJUsUobqJt5De748ovITYDJ7 afbohQzPg+4E1GIWMkJZ/VQD3B2pmr7J5rPn+vejxSQSoI93AIQaTpCU L5O/Bac=
    // www.example.com.	86400	IN	RRSIG	AAAA 8 3 86400 20150914082216 20150824191224 54108 example.com. kje4FKE+7d/j4OzWQelcKkePq6DxCRY/5btAiUcZNf+zVNlHK+o57h1r Y76ZviWChQB8Np2TjA1DrXGi/kHr2KKE60H5822mFZ2b9O+sgW4q6o3G kO2E1CQxbYe+nI1Z8lVfjdCNm81zfvYqDjo2/tGqagehxG1V9MBZO6br 4KKdoa4=
    // www.example.com.	86400	IN	RRSIG	A 8 3 86400 20150915023456 20150824191224 54108 example.com. cWtw0nMvcXcYNnxejB3Le3KBfoPPQZLmbaJ8ybdmzBDefQOm1ZjZZMOP wHEIxzdjRhG9mLt1mpyo1H7OezKTGX+mDtskcECTl/+jB/YSZyvbwRxj e88Lrg4D+D2MiajQn3XSWf+6LQVe1J67gdbKTXezvux0tRxBNHHqWXRk pxCILes=

    return records;
  }

  #[test]
  fn test_authority() {
    let authority: Authority = create_example();

    assert!(authority.get_soa().is_some());
    assert_eq!(authority.get_soa().unwrap().get_dns_class(), DNSClass::IN);

    assert!(authority.lookup(authority.get_origin(), RecordType::NS, DNSClass::HS).is_none());
    assert!(authority.lookup(authority.get_origin(), RecordType::NS, DNSClass::IN).is_some());

    let mut lookup: Vec<_> = authority.get_ns().unwrap();
    lookup.sort();

    assert_eq!(*lookup.first().unwrap(), Record::new().name(authority.get_origin().clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS{ nsdname: Name::parse("a.iana-servers.net.", None).unwrap() }).clone());
    assert_eq!(*lookup.last().unwrap(), Record::new().name(authority.get_origin().clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS{ nsdname: Name::parse("b.iana-servers.net.", None).unwrap() }).clone());

    assert!(authority.lookup(authority.get_origin(), RecordType::TXT, DNSClass::HS).is_some());

    let mut lookup: Vec<_> = authority.lookup(authority.get_origin(), RecordType::TXT, DNSClass::HS).unwrap();
    lookup.sort();

    assert_eq!(*lookup.first().unwrap(), Record::new().name(authority.get_origin().clone()).ttl(60).rr_type(RecordType::TXT).dns_class(DNSClass::HS).rdata(RData::TXT{ txt_data: vec!["$Id: example.com 4415 2015-08-24 20:12:23Z davids $".to_string()] }).clone());

    assert_eq!(*authority.lookup(authority.get_origin(), RecordType::A, DNSClass::IN).unwrap().first().unwrap(), Record::new().name(authority.get_origin().clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::A{ address: Ipv4Addr::new(93,184,216,34) }).clone());
  }

  #[test]
  fn test_authorize() {
    let mut authority: Authority = create_example();
    assert!(authority.authorize().is_err());

    // TODO: this will nee to be more complex as additional policies are added
    authority.set_allow_update(true);
    assert!(authority.authorize().is_ok());
  }

  #[test]
  fn test_prerequisites() {
    let not_zone = Name::new().label("not").label("a").label("domain").label("com");
    let not_in_zone = Name::new().label("not").label("example").label("com");

    let mut authority: Authority = create_example();
    authority.set_allow_update(true);

    // first check the initial negatives, ttl = 0, and the zone is the same
    assert_eq!(authority.verify_prerequisites(&[Record::new().name(not_in_zone.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::NULL{ anything: vec![] }).clone()]), Err(ResponseCode::FormErr));
    assert_eq!(authority.verify_prerequisites(&[Record::new().name(not_zone.clone()).ttl(0).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::NULL{ anything: vec![] }).clone()]), Err(ResponseCode::NotZone));

    // *   ANY      ANY      empty    Name is in use
    assert!(authority.verify_prerequisites(&[Record::new().name(authority.get_origin().clone()).ttl(0).dns_class(DNSClass::ANY).rr_type(RecordType::ANY).rdata(RData::NULL{ anything: vec![] }).clone()]).is_ok());
    assert_eq!(authority.verify_prerequisites(&[Record::new().name(not_in_zone.clone()).ttl(0).dns_class(DNSClass::ANY).rr_type(RecordType::ANY).rdata(RData::NULL{ anything: vec![] }).clone()]), Err(ResponseCode::NXDomain));

    // *   ANY      rrset    empty    RRset exists (value independent)
    assert!(authority.verify_prerequisites(&[Record::new().name(authority.get_origin().clone()).ttl(0).dns_class(DNSClass::ANY).rr_type(RecordType::A).rdata(RData::NULL{ anything: vec![] } ).clone()]).is_ok());
    assert_eq!(authority.verify_prerequisites(&[Record::new().name(not_in_zone.clone()).ttl(0).dns_class(DNSClass::ANY).rr_type(RecordType::A).rdata(RData::NULL{ anything: vec![] }).clone()]), Err(ResponseCode::NXRRSet));

    // *   NONE     ANY      empty    Name is not in use
    assert!(authority.verify_prerequisites(&[Record::new().name(not_in_zone.clone()).ttl(0).dns_class(DNSClass::NONE).rr_type(RecordType::ANY).rdata(RData::NULL{ anything: vec![] }).clone()]).is_ok());
    assert_eq!(authority.verify_prerequisites(&[Record::new().name(authority.get_origin().clone()).ttl(0).dns_class(DNSClass::NONE).rr_type(RecordType::ANY).rdata(RData::NULL{ anything: vec![] }).clone()]), Err(ResponseCode::YXDomain));

    // *   NONE     rrset    empty    RRset does not exist
    assert!(authority.verify_prerequisites(&[Record::new().name(not_in_zone.clone()).ttl(0).dns_class(DNSClass::NONE).rr_type(RecordType::A).rdata(RData::NULL{ anything: vec![] }).clone()]).is_ok());
    assert_eq!(authority.verify_prerequisites(&[Record::new().name(authority.get_origin().clone()).ttl(0).dns_class(DNSClass::NONE).rr_type(RecordType::A).rdata(RData::NULL{ anything: vec![] }).clone()]), Err(ResponseCode::YXRRSet));

    // *   zone     rrset    rr       RRset exists (value dependent)
    assert!(authority.verify_prerequisites(&[Record::new().name(authority.get_origin().clone()).ttl(0).dns_class(DNSClass::IN).rr_type(RecordType::A).rdata(RData::A{ address: Ipv4Addr::new(93,184,216,34) }).clone()]).is_ok());
    // wrong class
    assert_eq!(authority.verify_prerequisites(&[Record::new().name(authority.get_origin().clone()).ttl(0).dns_class(DNSClass::CH).rr_type(RecordType::A).rdata(RData::A{ address: Ipv4Addr::new(93,184,216,34) }).clone()]), Err(ResponseCode::FormErr));
    // wrong Name
    assert_eq!(authority.verify_prerequisites(&[Record::new().name(not_in_zone.clone()).ttl(0).dns_class(DNSClass::IN).rr_type(RecordType::A).rdata(RData::A{ address: Ipv4Addr::new(93,184,216,24) }).clone()]), Err(ResponseCode::NXRRSet));
    // wrong IP
    assert_eq!(authority.verify_prerequisites(&[Record::new().name(authority.get_origin().clone()).ttl(0).dns_class(DNSClass::IN).rr_type(RecordType::A).rdata(RData::A{ address: Ipv4Addr::new(93,184,216,24) }).clone()]), Err(ResponseCode::NXRRSet));
  }
}
