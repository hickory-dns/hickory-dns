// Copyright 2015-2026 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Metrics related to server operation

use std::{
    collections::{HashMap, hash_map::Entry},
    fmt,
};

use hickory_net::xfer::Protocol as NetProtocol;
use hickory_proto::op::{Header, LowerQuery, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, Record, RecordType};
use metrics::{Counter, Gauge, Unit, counter, describe_counter, describe_gauge, gauge};

use crate::server::{ReportingResponseHandler, ResponseHandler, ResponseInfo};
use crate::zone_handler::{AuthLookup, LookupControlFlow, ZoneHandler, ZoneType};

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

#[derive(Clone)]
pub(super) struct ResponseHandlerMetrics {
    pub(super) proto: ProtocolMetrics,
    pub(super) operation: OpCodeMetrics,
    pub(super) request_flags: FlagMetrics,
    pub(super) response_code: ResponseCodeMetrics,
    pub(super) response_flags: FlagMetrics,
}

impl ResponseHandlerMetrics {
    pub(super) fn update(
        &self,
        response_handler: &ReportingResponseHandler<impl ResponseHandler>,
        response_info: &ResponseInfo,
    ) {
        self.proto.increment(&response_handler.protocol);
        self.operation
            .increment(&response_handler.request_header.op_code());
        self.request_flags
            .increment(&response_handler.request_header);

        self.response_code.increment(&response_info.response_code());
        self.response_flags.increment(response_info);
    }
}

impl Default for ResponseHandlerMetrics {
    fn default() -> Self {
        Self {
            proto: ProtocolMetrics::default(),
            operation: OpCodeMetrics::default(),
            request_flags: FlagMetrics::new(Direction::Request),
            response_code: ResponseCodeMetrics::default(),
            response_flags: FlagMetrics::new(Direction::Response),
        }
    }
}

#[derive(Clone)]
pub(super) struct ProtocolMetrics {
    udp: Counter,
    tcp: Counter,
    #[cfg(feature = "__tls")]
    tls: Counter,
    #[cfg(feature = "__https")]
    https: Counter,
    #[cfg(feature = "__quic")]
    quic: Counter,
    #[cfg(feature = "__h3")]
    h3: Counter,
}

impl ProtocolMetrics {
    pub(super) fn increment(&self, proto: &NetProtocol) {
        match proto {
            NetProtocol::Udp => self.udp.increment(1),
            NetProtocol::Tcp => self.tcp.increment(1),
            #[cfg(feature = "__tls")]
            NetProtocol::Tls => self.tls.increment(1),
            #[cfg(feature = "__https")]
            NetProtocol::Https => self.https.increment(1),
            #[cfg(feature = "__quic")]
            NetProtocol::Quic => self.quic.increment(1),
            #[cfg(feature = "__h3")]
            NetProtocol::H3 => self.h3.increment(1),
            _ => {}
        }
    }
}

impl Default for ProtocolMetrics {
    fn default() -> Self {
        let request_protocols_name = "hickory_request_protocols_total";
        let key = "protocol";
        Self {
            udp: {
                let new = counter!(request_protocols_name, key => "udp");
                describe_counter!(
                    request_protocols_name,
                    Unit::Count,
                    "Number of requests by transport protocol."
                );
                new
            },
            tcp: counter!(request_protocols_name, key => "tcp"),
            #[cfg(feature = "__tls")]
            tls: counter!(request_protocols_name, key => "tls"),
            #[cfg(feature = "__https")]
            https: counter!(request_protocols_name, key => "https"),
            #[cfg(feature = "__quic")]
            quic: counter!(request_protocols_name, key => "quic"),
            #[cfg(feature = "__h3")]
            h3: counter!(request_protocols_name, key => "http3"),
        }
    }
}

#[derive(Clone)]
pub(super) struct OpCodeMetrics {
    query: Counter,
    status: Counter,
    notify: Counter,
    update: Counter,
    unknown: Counter,
}

impl OpCodeMetrics {
    pub(super) fn increment(&self, op_code: &OpCode) {
        match op_code {
            OpCode::Query => self.query.increment(1),
            OpCode::Status => self.status.increment(1),
            OpCode::Notify => self.notify.increment(1),
            OpCode::Update => self.update.increment(1),
            OpCode::Unknown(_) => self.unknown.increment(1),
        }
    }
}

impl Default for OpCodeMetrics {
    fn default() -> Self {
        let request_operations_name = "hickory_request_operations_total";
        let key = "operation";
        Self {
            query: {
                let new = counter!(request_operations_name, key => "query");
                describe_counter!(
                    request_operations_name,
                    Unit::Count,
                    "Number of requests by opcode."
                );
                new
            },
            status: counter!(request_operations_name, key => "status"),
            notify: counter!(request_operations_name, key => "notify"),
            update: counter!(request_operations_name, key => "update"),
            unknown: counter!(request_operations_name, key => "unknown"),
        }
    }
}

#[derive(Clone)]
pub(super) struct FlagMetrics {
    authoritative: Counter,
    authentic_data: Counter,
    checking_disabled: Counter,
    recursion_available: Counter,
    recursion_desired: Counter,
    truncation: Counter,
}

impl FlagMetrics {
    fn new(direction: Direction) -> Self {
        let flags_name = format!("hickory_{direction}_flags_total");
        let key = "flag";
        Self {
            authoritative: {
                let new = counter!(flags_name.clone(), key => "aa");
                describe_counter!(
                    flags_name.clone(),
                    Unit::Count,
                    format!("Number of {direction}s by header flags.")
                );
                new
            },
            authentic_data: counter!(flags_name.clone(), key => "ad"),
            checking_disabled: counter!(flags_name.clone(), key => "cd"),
            recursion_available: counter!(flags_name.clone(), key => "ra"),
            recursion_desired: counter!(flags_name.clone(), key => "rd"),
            truncation: counter!(flags_name, key => "tc"),
        }
    }
}

impl FlagMetrics {
    pub(super) fn increment(&self, header: &Header) {
        if header.authoritative() {
            self.authoritative.increment(1);
        }
        if header.authentic_data() {
            self.authentic_data.increment(1);
        }
        if header.checking_disabled() {
            self.checking_disabled.increment(1);
        }
        if header.recursion_available() {
            self.recursion_available.increment(1);
        }
        if header.recursion_desired() {
            self.recursion_desired.increment(1);
        }
        if header.truncated() {
            self.truncation.increment(1);
        }
    }
}

#[derive(Clone)]
pub(super) struct ResponseCodeMetrics {
    no_error: Counter,
    form_error: Counter,
    serv_fail: Counter,
    nx_domain: Counter,
    not_imp: Counter,
    refused: Counter,
    yx_domain: Counter,
    yx_rrset: Counter,
    nx_rrset: Counter,
    not_auth: Counter,
    not_zone: Counter,
    bad_vers: Counter,
    bad_sig: Counter,
    bad_key: Counter,
    bad_time: Counter,
    bad_mode: Counter,
    bad_name: Counter,
    bad_alg: Counter,
    bad_trunc: Counter,
    bad_cookie: Counter,
    unknown: Counter,
}

impl ResponseCodeMetrics {
    pub(super) fn increment(&self, response_code: &ResponseCode) {
        match response_code {
            ResponseCode::NoError => self.no_error.increment(1),
            ResponseCode::FormErr => self.form_error.increment(1),
            ResponseCode::ServFail => self.serv_fail.increment(1),
            ResponseCode::NXDomain => self.nx_domain.increment(1),
            ResponseCode::NotImp => self.not_imp.increment(1),
            ResponseCode::Refused => self.refused.increment(1),
            ResponseCode::YXDomain => self.yx_domain.increment(1),
            ResponseCode::YXRRSet => self.yx_rrset.increment(1),
            ResponseCode::NXRRSet => self.nx_rrset.increment(1),
            ResponseCode::NotAuth => self.not_auth.increment(1),
            ResponseCode::NotZone => self.not_zone.increment(1),
            ResponseCode::BADVERS => self.bad_vers.increment(1),
            ResponseCode::BADSIG => self.bad_sig.increment(1),
            ResponseCode::BADKEY => self.bad_key.increment(1),
            ResponseCode::BADTIME => self.bad_time.increment(1),
            ResponseCode::BADMODE => self.bad_mode.increment(1),
            ResponseCode::BADNAME => self.bad_name.increment(1),
            ResponseCode::BADALG => self.bad_alg.increment(1),
            ResponseCode::BADTRUNC => self.bad_trunc.increment(1),
            ResponseCode::BADCOOKIE => self.bad_cookie.increment(1),
            ResponseCode::Unknown(_) => self.unknown.increment(1),
        }
    }
}

impl Default for ResponseCodeMetrics {
    fn default() -> Self {
        let response_codes_name = "hickory_response_codes_total";
        let key = "code";
        Self {
            no_error: {
                let new = counter!(response_codes_name, key => "no_error");
                describe_counter!(
                    response_codes_name,
                    Unit::Count,
                    "Number of responses by response code."
                );
                new
            },
            form_error: counter!(response_codes_name, key => "form_error"),
            serv_fail: counter!(response_codes_name, key => "serv_fail"),
            nx_domain: counter!(response_codes_name, key => "nx_domain"),
            not_imp: counter!(response_codes_name, key => "not_imp"),
            refused: counter!(response_codes_name, key => "refused"),
            yx_domain: counter!(response_codes_name, key => "yx_domain"),
            yx_rrset: counter!(response_codes_name, key => "yx_rrset"),
            nx_rrset: counter!(response_codes_name, key => "nx_rrset"),
            not_auth: counter!(response_codes_name, key => "not_auth"),
            not_zone: counter!(response_codes_name, key => "not_zone"),
            bad_vers: counter!(response_codes_name, key => "bad_vers"),
            bad_sig: counter!(response_codes_name, key => "bad_sig"),
            bad_key: counter!(response_codes_name, key => "bad_key"),
            bad_time: counter!(response_codes_name, key => "bad_time"),
            bad_mode: counter!(response_codes_name, key => "bad_mode"),
            bad_name: counter!(response_codes_name, key => "bad_name"),
            bad_alg: counter!(response_codes_name, key => "bad_alg"),
            bad_trunc: counter!(response_codes_name, key => "bad_trunc"),
            bad_cookie: counter!(response_codes_name, key => "bad_cookie"),
            unknown: counter!(response_codes_name, key => "unknown"),
        }
    }
}

pub(super) struct PersistentStoreMetrics {
    pub(super) zone_records: Gauge,
    #[cfg(all(feature = "sqlite", feature = "__dnssec"))]
    pub(super) zone_records_added: Counter,
    #[cfg(all(feature = "sqlite", feature = "__dnssec"))]
    pub(super) zone_records_deleted: Counter,
    #[cfg(all(feature = "sqlite", feature = "__dnssec"))]
    pub(super) zone_records_updated: Counter,
}

impl PersistentStoreMetrics {
    pub(super) fn new(store: &'static str) -> Self {
        let store_key = "store";

        let zone_records_name = "hickory_zone_records_total";
        let zone_records = gauge!(zone_records_name, store_key => store);
        describe_gauge!(
            zone_records_name,
            Unit::Count,
            "Number of resource records in zone stores."
        );

        #[cfg(all(feature = "sqlite", feature = "__dnssec"))]
        let (zone_records_added, zone_records_deleted, zone_records_updated) = {
            let zone_records_modified_name = "hickory_zone_records_modified_total";

            let operation_key = "operation";

            let records_added =
                counter!(zone_records_modified_name, store_key => store, operation_key => "added");
            let records_deleted = counter!(zone_records_modified_name, store_key => store, operation_key => "deleted");
            let records_updated = counter!(zone_records_modified_name, store_key => store, operation_key => "updated");

            describe_counter!(
                zone_records_modified_name,
                Unit::Count,
                "Number of modifications to resource records in zone stores."
            );

            (records_added, records_deleted, records_updated)
        };

        Self {
            zone_records,
            #[cfg(all(feature = "sqlite", feature = "__dnssec"))]
            zone_records_added,
            #[cfg(all(feature = "sqlite", feature = "__dnssec"))]
            zone_records_deleted,
            #[cfg(all(feature = "sqlite", feature = "__dnssec"))]
            zone_records_updated,
        }
    }

    #[cfg(all(feature = "sqlite", feature = "__dnssec"))]
    pub(super) fn added(&self) {
        self.zone_records_added.increment(1);
        self.zone_records.increment(1);
    }

    #[cfg(all(feature = "sqlite", feature = "__dnssec"))]
    pub(super) fn deleted(&self) {
        self.zone_records_deleted.increment(1);
        self.zone_records.decrement(1)
    }

    #[cfg(all(feature = "sqlite", feature = "__dnssec"))]
    pub(super) fn updated(&self) {
        self.zone_records_updated.increment(1);
    }
}

/// Indicates whether metrics handles are for requests or responses.
#[derive(Clone, Copy)]
enum Direction {
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

#[cfg(feature = "blocklist")]
pub(crate) mod blocklist {
    use metrics::{Counter, Gauge, Unit, counter, describe_counter, describe_gauge, gauge};

    pub(crate) struct BlocklistMetrics {
        pub(crate) entries: Gauge,
        pub(crate) blocked_queries: Counter,
        pub(crate) logged_queries: Counter,
        pub(crate) total_hits: Counter,
        pub(crate) total_queries: Counter,
    }

    impl BlocklistMetrics {
        pub(crate) fn new() -> Self {
            describe_gauge!(
                "hickory_blocklist_list_entries",
                Unit::Count,
                "The total number of entries in all configured blocklists",
            );
            describe_counter!(
                "hickory_blocklist_blocked_queries_total",
                Unit::Count,
                "The total number of requests that were blocked by the blocklist zone handler",
            );
            describe_counter!(
                "hickory_blocklist_logged_queries_total",
                Unit::Count,
                "The total number of requests that were logged by the blocklist zone handler",
            );
            describe_counter!(
                "hickory_blocklist_list_hits_total",
                Unit::Count,
                "The total number of requests that matched a blocklist entry",
            );
            describe_counter!(
                "hickory_blocklist_queries_total",
                Unit::Count,
                "The total number of requests the blocklist zone handler has processed",
            );

            Self {
                entries: gauge!("hickory_blocklist_list_entries"),
                blocked_queries: counter!("hickory_blocklist_blocked_queries_total"),
                logged_queries: counter!("hickory_blocklist_logged_queries_total"),
                total_hits: counter!("hickory_blocklist_list_hits_total"),
                total_queries: counter!("hickory_blocklist_queries_total"),
            }
        }
    }
}
