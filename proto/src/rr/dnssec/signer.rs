// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use error::*;
use op::Message;
use rr::Name;
use rr::dnssec::Algorithm;
use rr::rdata::SIG;

/// FIXME: get docs from Signer in Client
pub trait MessageSigner {
    /// FIXME: get docs from Signer in Client
    fn algorithm(&self) -> Algorithm;
    /// FIXME: get docs from Signer in Client
    fn calculate_key_tag(&self) -> ProtoResult<u16>;
    /// FIXME: get docs from Signer in Client
    fn signer_name(&self) -> &Name;
    /// FIXME: get docs from Signer in Client
    fn sign_message(&self, message: &Message, pre_sig0: &SIG) -> ProtoResult<Vec<u8>>;
}