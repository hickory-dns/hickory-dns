// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{
    collections::{HashMap, hash_map::Entry},
    fmt,
};

use crate::zone_handler::{AuthLookup, LookupControlFlow, ZoneHandler, ZoneType};

use hickory_proto::op::LowerQuery;
use hickory_proto::rr::{DNSClass, Record, RecordType};
use metrics::{Counter, Unit, counter, describe_counter};

pub(super) struct CatalogMetrics {
    zone_store_metrics: HashMap<(&'static str, ZoneType), ZoneLookupMetrics>,
    request_metrics: DnsClassesRecordTypesMetrics,
    response_metrics: DnsClassesRecordTypesMetrics,
}

impl CatalogMetrics {
    pub(super) fn add_handler(&mut self, handler: &dyn ZoneHandler) {
        match self
            .zone_store_metrics
            .entry((handler.metrics_label(), handler.zone_type()))
        {
            Entry::Occupied(_) => {
                /* already present, for the label and zone type combination => use existing */
            }
            Entry::Vacant(v) => {
                v.insert(ZoneLookupMetrics::new(
                    handler.metrics_label(),
                    handler.zone_type(),
                ));
            }
        }
    }

    pub(super) fn update_zone_lookup(
        &self,
        handler: &dyn ZoneHandler,
        lookup: &LookupControlFlow<AuthLookup>,
    ) {
        // metrics per store are added/removed with the ZoneHandler in the Catalog (requires mut)
        let Some(zone_store_metrics) = self
            .zone_store_metrics
            .get(&(handler.metrics_label(), handler.zone_type()))
        else {
            return;
        };

        let is_success = match lookup {
            LookupControlFlow::Continue(res) => res.is_ok(),
            LookupControlFlow::Break(res) => res.is_ok(),
            LookupControlFlow::Skip => false,
        };

        match is_success {
            true => zone_store_metrics.success.increment(1),
            false => zone_store_metrics.failed.increment(1),
        }
    }

    pub(super) fn update_request_response<'a>(
        &self,
        query: &LowerQuery,
        answers: impl Iterator<Item = &'a Record> + Send + 'a,
    ) {
        self.request_metrics
            .record_type
            .increment(query.query_type());
        self.request_metrics
            .dns_classes
            .increment(query.query_class());

        answers.for_each(|a| {
            self.response_metrics.record_type.increment(a.record_type());
            self.response_metrics.dns_classes.increment(a.dns_class());
        });
    }
}

impl Default for CatalogMetrics {
    fn default() -> Self {
        Self {
            zone_store_metrics: HashMap::new(),
            request_metrics: DnsClassesRecordTypesMetrics::new(Direction::Request),
            response_metrics: DnsClassesRecordTypesMetrics::new(Direction::Response),
        }
    }
}

struct ZoneLookupMetrics {
    success: Counter,
    failed: Counter,
}

impl ZoneLookupMetrics {
    pub(crate) fn new(zone_handler: &'static str, zone_type: ZoneType) -> Self {
        let zone_lookups_name = "hickory_zone_lookups_total";
        let type_key = "type";
        let role_key = "role";
        let zone_handler_key = "zone_handler";
        let success_key = "success";

        // tags are statically derived from the ZoneHandler ZoneType which is a 1:1 relationship
        let new = match zone_type {
            ZoneType::Primary => Self {
                success: counter!(zone_lookups_name, zone_handler_key => zone_handler, type_key => "authoritative", role_key => "primary", success_key => "true"),
                failed: counter!(zone_lookups_name, zone_handler_key => zone_handler, type_key => "authoritative", role_key => "primary", success_key => "false"),
            },
            ZoneType::Secondary => Self {
                success: counter!(zone_lookups_name, zone_handler_key => zone_handler, type_key => "authoritative", role_key => "secondary", success_key => "true"),
                failed: counter!(zone_lookups_name, zone_handler_key => zone_handler, type_key => "authoritative", role_key => "secondary", success_key => "false"),
            },
            ZoneType::External => Self {
                success: counter!(zone_lookups_name, zone_handler_key => zone_handler, type_key => "external", role_key => "forwarded", success_key => "true"),
                failed: counter!(zone_lookups_name, zone_handler_key => zone_handler, type_key => "external", role_key => "forwarded", success_key => "false"),
            },
        };

        describe_counter!(zone_lookups_name, Unit::Count, "Number of zone lookups.");
        new
    }
}

struct DnsClassesRecordTypesMetrics {
    dns_classes: DNSClassMetrics,
    record_type: RecordTypeMetrics,
}

impl DnsClassesRecordTypesMetrics {
    fn new(direction: Direction) -> Self {
        Self {
            dns_classes: DNSClassMetrics::new(direction),
            record_type: RecordTypeMetrics::new(direction),
        }
    }
}

struct DNSClassMetrics {
    r#in: Counter,
    ch: Counter,
    hs: Counter,
    none: Counter,
    any: Counter,
    unknown: Counter,
}

impl DNSClassMetrics {
    fn new(direction: Direction) -> Self {
        let dns_class_name = format!("hickory_{direction}_dns_classes_total");
        let key = "class";
        Self {
            r#in: {
                let new = counter!(dns_class_name.clone(), key => "in");
                let description = match direction {
                    Direction::Request => "Number of requests by DNS class.",
                    Direction::Response => {
                        "Total number of resource records in responses by DNS class."
                    }
                };
                describe_counter!(dns_class_name.clone(), Unit::Count, description);
                new
            },
            ch: counter!(dns_class_name.clone(), key => "ch"),
            hs: counter!(dns_class_name.clone(), key => "hs"),
            none: counter!(dns_class_name.clone(), key => "none"),
            any: counter!(dns_class_name.clone(), key => "any"),
            unknown: counter!(dns_class_name, key => "unknown"),
        }
    }

    fn increment(&self, dns_class: DNSClass) {
        match dns_class {
            DNSClass::IN => self.r#in.increment(1),
            DNSClass::CH => self.ch.increment(1),
            DNSClass::HS => self.hs.increment(1),
            DNSClass::NONE => self.none.increment(1),
            DNSClass::ANY => self.any.increment(1),
            DNSClass::Unknown(_) => self.unknown.increment(1),
            DNSClass::OPT(_) => { /* skip OPT class type */ }
        }
    }
}

#[derive(Clone)]
struct RecordTypeMetrics {
    a: Counter,
    aname: Counter,
    any: Counter,
    aaaa: Counter,
    axfr: Counter,
    caa: Counter,
    cds: Counter,
    cdnskey: Counter,
    cert: Counter,
    mx: Counter,
    csync: Counter,
    dnskey: Counter,
    cname: Counter,
    ds: Counter,
    hinfo: Counter,
    https: Counter,
    ixfr: Counter,
    key: Counter,
    smimea: Counter,
    srv: Counter,
    sshfp: Counter,
    tlsa: Counter,
    tsig: Counter,
    txt: Counter,
    unknown: Counter,
    zero: Counter,
    svcb: Counter,
    soa: Counter,
    sig: Counter,
    rrsig: Counter,
    ptr: Counter,
    opt: Counter,
    openpgpkey: Counter,
    null: Counter,
    nsec3param: Counter,
    nsec3: Counter,
    nsec: Counter,
    ns: Counter,
    naptr: Counter,
}

impl RecordTypeMetrics {
    fn new(direction: Direction) -> Self {
        let record_type_name = format!("hickory_{direction}_record_types_total");
        let key = "type";

        Self {
            a: {
                let new = counter!(record_type_name.clone(), key => "a");
                let description = match direction {
                    Direction::Request => "Number of requests by query type.",
                    Direction::Response => {
                        "Total number of resource records in responses by record type."
                    }
                };
                describe_counter!(record_type_name.clone(), Unit::Count, description);
                new
            },
            aaaa: counter!(record_type_name.clone(), key => "aaaa"),
            aname: counter!(record_type_name.clone(), key => "aname"),
            any: counter!(record_type_name.clone(), key => "any"),
            axfr: counter!(record_type_name.clone(), key => "axfr"),
            caa: counter!(record_type_name.clone(), key => "caa"),
            cds: counter!(record_type_name.clone(), key => "cds"),
            cdnskey: counter!(record_type_name.clone(), key => "cdnskey"),
            cert: counter!(record_type_name.clone(), key => "cert"),
            cname: counter!(record_type_name.clone(), key => "cname"),
            csync: counter!(record_type_name.clone(), key => "csync"),
            dnskey: counter!(record_type_name.clone(), key => "dnskey"),
            ds: counter!(record_type_name.clone(), key => "ds"),
            hinfo: counter!(record_type_name.clone(), key => "hinfo"),
            https: counter!(record_type_name.clone(), key => "https"),
            ixfr: counter!(record_type_name.clone(), key => "ixfr"),
            key: counter!(record_type_name.clone(), key => "key"),
            mx: counter!(record_type_name.clone(), key => "mx"),
            naptr: counter!(record_type_name.clone(), key => "naptr"),
            ns: counter!(record_type_name.clone(), key => "ns"),
            nsec: counter!(record_type_name.clone(), key => "nsec"),
            nsec3: counter!(record_type_name.clone(), key => "nsec3"),
            nsec3param: counter!(record_type_name.clone(), key => "nsec3param"),
            null: counter!(record_type_name.clone(), key => "null"),
            openpgpkey: counter!(record_type_name.clone(), key => "openpgpkey"),
            opt: counter!(record_type_name.clone(), key => "opt"),
            ptr: counter!(record_type_name.clone(), key => "ptr"),
            rrsig: counter!(record_type_name.clone(), key => "rrsig"),
            sig: counter!(record_type_name.clone(), key => "sig"),
            smimea: counter!(record_type_name.clone(), key => "smimea"),
            soa: counter!(record_type_name.clone(), key => "soa"),
            srv: counter!(record_type_name.clone(), key => "srv"),
            sshfp: counter!(record_type_name.clone(), key => "sshfp"),
            svcb: counter!(record_type_name.clone(), key => "svcb"),
            tlsa: counter!(record_type_name.clone(), key => "tlsa"),
            tsig: counter!(record_type_name.clone(), key => "tsig"),
            txt: counter!(record_type_name.clone(), key => "txt"),
            unknown: counter!(record_type_name.clone(), key => "unknown"),
            zero: counter!(record_type_name, key => "zero"),
        }
    }

    fn increment(&self, record_type: RecordType) {
        match record_type {
            RecordType::A => self.a.increment(1),
            RecordType::AAAA => self.aaaa.increment(1),
            RecordType::ANAME => self.aname.increment(1),
            RecordType::ANY => self.any.increment(1),
            RecordType::AXFR => self.axfr.increment(1),
            RecordType::CAA => self.caa.increment(1),
            RecordType::CDS => self.cds.increment(1),
            RecordType::CDNSKEY => self.cdnskey.increment(1),
            RecordType::CERT => self.cert.increment(1),
            RecordType::CNAME => self.cname.increment(1),
            RecordType::CSYNC => self.csync.increment(1),
            RecordType::DNSKEY => self.dnskey.increment(1),
            RecordType::DS => self.ds.increment(1),
            RecordType::HINFO => self.hinfo.increment(1),
            RecordType::HTTPS => self.https.increment(1),
            RecordType::IXFR => self.ixfr.increment(1),
            RecordType::KEY => self.key.increment(1),
            RecordType::MX => self.mx.increment(1),
            RecordType::NAPTR => self.naptr.increment(1),
            RecordType::NS => self.ns.increment(1),
            RecordType::NSEC => self.nsec.increment(1),
            RecordType::NSEC3 => self.nsec3.increment(1),
            RecordType::NSEC3PARAM => self.nsec3param.increment(1),
            RecordType::NULL => self.null.increment(1),
            RecordType::OPENPGPKEY => self.openpgpkey.increment(1),
            RecordType::OPT => self.opt.increment(1),
            RecordType::PTR => self.ptr.increment(1),
            RecordType::RRSIG => self.rrsig.increment(1),
            RecordType::SIG => self.sig.increment(1),
            RecordType::SMIMEA => self.smimea.increment(1),
            RecordType::SOA => self.soa.increment(1),
            RecordType::SRV => self.srv.increment(1),
            RecordType::SSHFP => self.sshfp.increment(1),
            RecordType::SVCB => self.svcb.increment(1),
            RecordType::TLSA => self.tlsa.increment(1),
            RecordType::TSIG => self.tsig.increment(1),
            RecordType::TXT => self.txt.increment(1),
            RecordType::ZERO => self.zero.increment(1),
            RecordType::Unknown(_) | _ => self.unknown.increment(1),
        }
    }
}

/// Indicates whether metrics handles are for requests or responses.
#[derive(Clone, Copy)]
pub(crate) enum Direction {
    Request,
    Response,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Request => "request",
            Self::Response => "response",
        })
    }
}
