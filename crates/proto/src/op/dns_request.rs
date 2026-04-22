// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `DnsRequest` wraps a `Message` and associates a set of `DnsRequestOptions` for specifying different transfer options.

use core::ops::{Deref, DerefMut};
#[cfg(feature = "std")]
use core::time::Duration;

#[cfg(feature = "std")]
use super::DEFAULT_RETRY_FLOOR;
use super::{Message, Query, edns::DEFAULT_MAX_PAYLOAD_LEN};

/// A set of options for expressing options to how requests should be treated
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DnsRequestOptions {
    // TODO: add EDNS options here?
    /// When true, will add EDNS options to the request.
    pub use_edns: bool,
    /// EDNS UDP payload size.
    ///
    /// Sets the requestor's UDP payload size in the EDNS(0) OPT pseudo-RR in outgoing requests.
    /// This tells other servers when they need to truncate their responses. Smaller payload sizes
    /// require more queries with large responses to be retried over TCP, while larger payload sizes
    /// lead to large responses being fragmented or dropped if they exceed the MTU of a network.
    ///
    /// See <https://www.dnsflagday.net/2020/> and
    /// [RFC 9715](https://www.rfc-editor.org/rfc/rfc9715.html) for discussion.
    pub edns_payload_len: u16,
    /// When true, sets the DO bit in the EDNS options
    pub edns_set_dnssec_ok: bool,
    /// Specifies maximum request depth for DNSSEC validation.
    pub max_request_depth: usize,
    /// set recursion desired (or not) for any requests
    pub recursion_desired: bool,
    /// Randomize case of query name, and check that the response matches, for spoofing resistance.
    #[cfg(feature = "std")]
    pub case_randomization: bool,
    /// Retry interval for unreliable transport protocols (plain UDP). Any value lower than the
    /// retry_interval_floor value set by a protocol implementer will effectively
    /// be ignored, but higher values will result in less frequent retries.
    #[cfg(feature = "std")]
    pub retry_interval: Duration,
}

impl Default for DnsRequestOptions {
    fn default() -> Self {
        Self {
            max_request_depth: 26,
            use_edns: true,
            edns_payload_len: DEFAULT_MAX_PAYLOAD_LEN,
            edns_set_dnssec_ok: false,
            recursion_desired: true,
            #[cfg(feature = "std")]
            case_randomization: false,
            // We use the default value for the retry interval floor here as a good starting point.
            #[cfg(feature = "std")]
            retry_interval: DEFAULT_RETRY_FLOOR,
        }
    }
}

/// A DNS request object
///
/// This wraps a DNS Message for requests. It also has request options associated for controlling certain features of the DNS protocol handlers.
#[derive(Clone, PartialEq, Eq)]
pub struct DnsRequest {
    message: Message,
    options: DnsRequestOptions,
    /// If case randomization was replied to the request, this holds the original query.
    original_query: Option<Query>,
}

impl DnsRequest {
    /// Build a new `DnsRequest` from a `Query` and `DnsRequestOptions`.
    #[cfg(feature = "std")]
    pub fn from_query(mut query: Query, options: DnsRequestOptions) -> Self {
        let mut message = Message::query();
        let mut original_query = None;

        if options.case_randomization {
            original_query = Some(query.clone());
            query.name.randomize_label_case();
        }

        message.queries.push(query);
        message.metadata.recursion_desired = options.recursion_desired;

        if options.use_edns {
            message
                .edns
                .get_or_insert_default()
                .set_max_payload(options.edns_payload_len)
                .set_dnssec_ok(options.edns_set_dnssec_ok);
        }

        Self::new(message, options).with_original_query(original_query)
    }

    /// Returns a new DnsRequest object
    pub fn new(message: Message, options: DnsRequestOptions) -> Self {
        Self {
            message,
            options,
            original_query: None,
        }
    }

    /// Add the original query
    pub fn with_original_query(mut self, original_query: Option<Query>) -> Self {
        self.original_query = original_query;
        self
    }

    /// Get the set of request options associated with this request
    pub fn options(&self) -> &DnsRequestOptions {
        &self.options
    }

    /// Get a mutable reference to the request options associated with this request
    pub fn options_mut(&mut self) -> &mut DnsRequestOptions {
        &mut self.options
    }

    /// Unwraps the raw message
    pub fn into_parts(self) -> (Message, DnsRequestOptions) {
        (self.message, self.options)
    }

    /// Get the request's original query
    pub fn original_query(&self) -> Option<&Query> {
        self.original_query.as_ref()
    }
}

impl Deref for DnsRequest {
    type Target = Message;
    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

impl DerefMut for DnsRequest {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.message
    }
}

impl From<Message> for DnsRequest {
    fn from(message: Message) -> Self {
        Self::new(message, DnsRequestOptions::default())
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::rr::{Name, RecordType};

    #[test]
    fn from_query_default_includes_edns() {
        let query = Query::new(Name::from_ascii("example.com.").unwrap(), RecordType::A);
        let request = DnsRequest::from_query(query, DnsRequestOptions::default());
        assert!(request.edns.is_some());
        assert_eq!(request.max_payload(), DEFAULT_MAX_PAYLOAD_LEN);
    }

    #[test]
    fn from_query_edns_disabled_no_opt() {
        let query = Query::new(Name::from_ascii("example.com.").unwrap(), RecordType::A);
        let request = DnsRequest::from_query(
            query,
            DnsRequestOptions {
                use_edns: false,
                ..DnsRequestOptions::default()
            },
        );

        assert!(request.edns.is_none());
        assert_eq!(request.max_payload(), 512);
    }
}
