// Copyright (C) 2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Trait for client connections
use std::future::Future;
use std::sync::Arc;

use trust_dns_proto::{error::ProtoError, xfer::DnsRequestSender};

use crate::op::{MessageFinalizer, MessageVerifier};
#[cfg(feature = "dnssec")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
use crate::rr::dnssec::tsig::TSigner;
use crate::rr::dnssec::Signer as Sig0Signer;

use crate::proto::error::ProtoResult;
use crate::proto::op::Message;
use crate::proto::rr::Record;

/// List of currently supported signers
pub enum Signer {
    /// A Sig0 based signer
    Sig0(Sig0Signer),
    /// A TSIG based signer
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    TSIG(TSigner),
}

impl From<Sig0Signer> for Signer {
    fn from(s: Sig0Signer) -> Self {
        Signer::Sig0(s)
    }
}

#[cfg(feature = "dnssec")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
impl From<TSigner> for Signer {
    fn from(s: TSigner) -> Self {
        Signer::TSIG(s)
    }
}

impl MessageFinalizer for Signer {
    fn finalize_message(
        &self,
        message: &Message,
        time: u32,
    ) -> ProtoResult<(Vec<Record>, Option<MessageVerifier>)> {
        match self {
            Signer::Sig0(s0) => s0.finalize_message(message, time),
            #[cfg(feature = "dnssec")]
            #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
            Signer::TSIG(tsig) => tsig.finalize_message(message, time),
        }
    }
}

/// Trait for client connections
pub trait ClientConnection: 'static + Sized + Send + Sync + Unpin {
    /// The associated DNS RequestSender type.
    type Sender: DnsRequestSender;
    /// A future that resolves to the RequestSender
    type SenderFuture: Future<Output = Result<Self::Sender, ProtoError>> + 'static + Send + Unpin;

    /// Construct a new stream for use in the Client
    fn new_stream(&self, signer: Option<Arc<Signer>>) -> Self::SenderFuture;
}
