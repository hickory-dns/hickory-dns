// Copyright (C) 2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Trait for client connections
use std::future::Future;
use std::sync::Arc;

use hickory_proto::{error::ProtoError, op::MessageFinalizer, xfer::DnsRequestSender};

/// Trait for client connections
pub trait ClientConnection: 'static + Sized + Send + Sync + Unpin {
    /// The associated DNS RequestSender type.
    type Sender: DnsRequestSender;
    /// A future that resolves to the RequestSender
    type SenderFuture: Future<Output = Result<Self::Sender, ProtoError>> + 'static + Send + Unpin;

    /// Construct a new stream for use in the Client
    fn new_stream(&self, signer: Option<Arc<dyn MessageFinalizer>>) -> Self::SenderFuture;
}
