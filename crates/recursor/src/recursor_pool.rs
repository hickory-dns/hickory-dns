// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use hickory_resolver::NameServerPool;

use crate::proto::{
    ProtoError,
    op::{DnsResponse, Query},
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
        unreachable!("no longer used.");
    }
}
