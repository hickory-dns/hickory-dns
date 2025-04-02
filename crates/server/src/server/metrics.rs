use hickory_proto::op::{Header, OpCode, ResponseCode};
use hickory_proto::xfer::Protocol;
use metrics::{Counter, Unit, counter, describe_counter};

#[derive(Clone)]
pub(super) struct ResponseHandlerMetrics {
    pub(super) proto: ProtocolMetrics,
    pub(super) operation: OpCodeMetrics,
    pub(super) request_flags: FlagMetrics,
    pub(super) response_code: ResponseCodeMetrics,
    pub(super) response_flags: FlagMetrics,
}

impl Default for ResponseHandlerMetrics {
    fn default() -> Self {
        Self {
            proto: ProtocolMetrics::default(),
            operation: OpCodeMetrics::default(),
            request_flags: FlagMetrics::new("request"),
            response_code: ResponseCodeMetrics::default(),
            response_flags: FlagMetrics::new("response"),
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
    fn new(direction: &'static str) -> Self {
        let flags_name = format!("hickory_{}_flags_total", direction);
        let key = "flag";
        Self {
            authoritative: {
                let new = counter!(flags_name.clone(), key => "aa");
                describe_counter!(
                    flags_name.clone(),
                    Unit::Count,
                    "number of dns request flags"
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
                    "number of dns requests operations"
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

impl ProtocolMetrics {
    pub(super) fn increment(&self, proto: &Protocol) {
        match proto {
            Protocol::Udp => self.udp.increment(1),
            Protocol::Tcp => self.tcp.increment(1),
            #[cfg(feature = "__tls")]
            Protocol::Tls => self.tls.increment(1),
            #[cfg(feature = "__https")]
            Protocol::Https => self.https.increment(1),
            #[cfg(feature = "__quic")]
            Protocol::Quic => self.quic.increment(1),
            #[cfg(feature = "__h3")]
            Protocol::H3 => self.h3.increment(1),
            _ => {}
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
                    "number of dns request operations"
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

impl Default for ResponseCodeMetrics {
    fn default() -> Self {
        let response_codes_name = "hickory_response_codes_total";
        let key = "code";
        Self {
            no_error: {
                let new = counter!(response_codes_name, "code" => "no_error");
                describe_counter!(
                    response_codes_name,
                    Unit::Count,
                    "number of dns response codes"
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
