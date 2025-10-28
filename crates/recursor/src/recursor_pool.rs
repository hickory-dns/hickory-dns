// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use futures_util::StreamExt;
use hickory_resolver::NameServerPool;
use tracing::info;

use crate::proto::{
    DnsHandle, ProtoError,
    op::{DnsRequestOptions, DnsResponse, Query},
};
use crate::resolver::{ConnectionProvider, Name};

#[derive(Clone)]
pub(crate) struct RecursorPool<P: ConnectionProvider> {
    zone: Name,
    ns: NameServerPool<P>,
}

impl<P: ConnectionProvider> RecursorPool<P> {
    pub(crate) fn from(zone: Name, ns: NameServerPool<P>) -> Self {
        Self { zone, ns }
    }

    pub(crate) fn zone(&self) -> &Name {
        &self.zone
    }

    pub(crate) async fn lookup(
        &self,
        query: Query,
        security_aware: bool,
    ) -> Result<DnsResponse, ProtoError> {
        let ns = self.ns.clone();

        let query_cpy = query.clone();
        let case_randomization = self.ns.context().options.case_randomization;

        info!("querying {} for {}", self.zone, query_cpy);

        let mut options = DnsRequestOptions::default();
        options.use_edns = security_aware;
        options.edns_set_dnssec_ok = security_aware;
        options.case_randomization = case_randomization;

        // Set RD=0 in queries made by the recursive resolver. See the last figure in
        // section 2.2 of RFC 1035, for example. Failure to do so may allow for loops
        // between recursive resolvers following referrals to each other.
        options.recursion_desired = false;

        let (Some(result), _) = ns.lookup(query_cpy, options).into_future().await else {
            return Err(ProtoError::from("no response"));
        };

        result
    }
}
