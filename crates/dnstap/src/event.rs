// Copyright 2015-2026 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your option. This
// file may not be copied, modified, or distributed except according to those
// terms.

//! DNS events queued for DNSTAP encoding.

use std::net::SocketAddr;

use crate::DnsTransport;

/// DNSTAP message type variants.
///
/// Determines which protobuf message type is used for query/response events.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DnstapMessageType {
    /// AUTH_QUERY / AUTH_RESPONSE.
    Auth,
    /// CLIENT_QUERY / CLIENT_RESPONSE.
    Client,
    /// RESOLVER_QUERY / RESOLVER_RESPONSE.
    Resolver,
    /// FORWARDER_QUERY / FORWARDER_RESPONSE, for upstream servers asked to
    /// recurse.
    Forwarder,
    /// UPDATE_QUERY / UPDATE_RESPONSE, used when the message opcode is UPDATE.
    Update,
}

/// A raw DNS event queued for encoding and transmission.
///
/// Emitters build these lightweight structs on the request path; the
/// background sender task encodes them into protobuf frames off the hot path.
///
/// The message type is classified by the emitter; each event yields exactly
/// one frame.
#[derive(Debug)]
pub(crate) struct DnstapEvent {
    pub(crate) message_type: DnstapMessageType,
    pub(crate) src_addr: Option<SocketAddr>,
    pub(crate) server_addr: Option<SocketAddr>,
    pub(crate) transport: Option<DnsTransport>,
    pub(crate) query_time: (u64, u32),
    pub(crate) query_zone: Option<Vec<u8>>,
    pub(crate) payload: EventPayload,
}

/// The DNS message bytes an event carries. Responses also carry the time
/// they were emitted, recorded before queueing so the timestamp does not
/// drift with sender backlog.
#[derive(Debug)]
pub(crate) enum EventPayload {
    Query {
        bytes: Vec<u8>,
    },
    Response {
        bytes: Vec<u8>,
        response_time: (u64, u32),
    },
}

impl EventPayload {
    /// The DNS message bytes, query or response.
    pub(crate) fn bytes(&self) -> &[u8] {
        match self {
            Self::Query { bytes } | Self::Response { bytes, .. } => bytes,
        }
    }

    /// The response emit time; `None` for queries.
    pub(crate) fn response_time(&self) -> Option<(u64, u32)> {
        match self {
            Self::Query { .. } => None,
            Self::Response { response_time, .. } => Some(*response_time),
        }
    }
}

impl DnstapEvent {
    /// Whether the event carries a query rather than a response.
    pub(crate) fn is_query(&self) -> bool {
        matches!(self.payload, EventPayload::Query { .. })
    }

    pub(crate) fn payload_len(&self) -> usize {
        // Accounted bytes for the queue budget: the DNS payload plus the
        // query zone, the per-event heap this event holds while queued.
        self.payload.bytes().len() + self.query_zone.as_ref().map_or(0, Vec::len)
    }
}
