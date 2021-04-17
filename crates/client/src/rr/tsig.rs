// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! tsigner is a structure for computing tsig messasignuthentication code for dns transactions
use crate::proto::error::{ProtoError, ProtoResult};
use crate::proto::rr::rdata::tsig::{
    make_tsig_record, message_tbs, signed_message_to_buff, Algorithm, TSIG,
};
use std::ops::Range;

use crate::op::{Message, MessageFinalizer};
use crate::rr::{Name, RData, Record};

/// Struct to pass to a client for it to authenticate requests using TSIG.
#[derive(Clone)]
pub struct TSigner {
    key: Vec<u8>, // TODO this might want to be some sort of auto-zeroing on drop buffer, as it's cryptographic matterial
    algorithm: Algorithm,
    signer_name: Name,
    fudge: u16,
}

impl TSigner {
    /// Create a new Tsigner from its parts
    ///
    /// # Arguments
    ///
    /// * `key` - cryptographic key used to authenticate exchanges
    /// * `algorithm` - algorithm used to authenticate exchanges
    /// * `signer_name` - name of the key. Must match the name known to the server
    /// * `fudge` - maximum difference between client and server time, in seconds, see [fudge] for details
    pub fn new(
        key: Vec<u8>,
        algorithm: Algorithm,
        signer_name: Name,
        fudge: u16,
    ) -> ProtoResult<Self> {
        if algorithm.supported() {
            Ok(TSigner {
                key,
                algorithm,
                signer_name,
                fudge,
            })
        } else {
            Err(ProtoError::from("unsupported mac algorithm"))
        }
    }

    /// Return the key used for message authentication
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Return the algorithm used for message authentication
    pub fn algorithm(&self) -> &Algorithm {
        &self.algorithm
    }

    /// Name of the key used by this signer
    pub fn signer_name(&self) -> &Name {
        &self.signer_name
    }

    /// Maximum time difference between client time when issuing a message, and server time when
    /// receiving it, in second. If time is out, the server will consider the request invalid.
    /// Longer values means more room for replay by an attacker. A few minutes are usually a good
    /// value.
    pub fn fudge(&self) -> u16 {
        self.fudge
    }

    /// Compute authentication tag for a buffer
    pub fn sign(&self, tbs: &[u8]) -> ProtoResult<Vec<u8>> {
        self.algorithm.mac_data(&self.key, tbs)
    }

    /// Compute authentication tag for a message
    pub fn sign_message(&self, message: &Message, pre_tsig: &TSIG) -> ProtoResult<Vec<u8>> {
        message_tbs(None, message, pre_tsig, &self.signer_name).and_then(|tbs| self.sign(&tbs))
    }

    /// Verify the message is correctly signed
    /// Current time should be contained in returned range for the signature to still be valid
    pub fn verify_message(
        &self,
        previous_hash: Option<&[u8]>,
        message: Message,
    ) -> ProtoResult<Range<u64>> {
        let (vec, record) = signed_message_to_buff(previous_hash, message)?;
        let signature = self.sign(&vec)?;
        let tsig = if let RData::TSIG(tsig) = record.rdata() {
            tsig
        } else {
            unreachable!("tsig::signed_message_to_buff always returns a TSIG record")
        };

        // https://tools.ietf.org/html/rfc8945#section-5.2
        // 1.  Check key
        if record.name() != &self.signer_name || tsig.algorithm() != &self.algorithm {
            return Err(ProtoError::from("tsig validation error: wrong key"));
        }
        // 2.  Check MAC
        if signature.strip_prefix(tsig.mac()).is_none() {
            // tsig might be shorter if truncated, so we check if it is a prefix of the
            // actual signature
            return Err(ProtoError::from("tsig validation error: invalid signature"));
        }
        // 3.  Check time values
        // we don't actually have time here so we will let upper level decide
        // this is technically in violation of the RFC, in case both time and
        // truncation policy are bad, time should be reported and this code will report
        // truncation issue instead
        // 4.  Check truncation policy
        if tsig.mac().len() < std::cmp::max(10, signature.len() / 2) {
            return Err(ProtoError::from(
                "tsig validation error: truncated signature ",
            ));
        }
        Ok(Range {
            start: tsig.time() - tsig.fudge() as u64,
            end: tsig.time() + tsig.fudge() as u64,
        })
    }
}

impl MessageFinalizer for TSigner {
    fn finalize_message(&self, message: &Message, current_time: u32) -> ProtoResult<Vec<Record>> {
        log::debug!("signing message: {:?}", message);

        let pre_tsig = TSIG::new(
            self.algorithm.clone(),
            current_time as u64,
            self.fudge,
            Vec::new(),
            message.id(),
            0,
            Vec::new(),
        );
        let signature: Vec<u8> = self.sign_message(message, &pre_tsig)?;
        let tsig = make_tsig_record(self.signer_name.clone(), pre_tsig.set_mac(signature));
        Ok(vec![tsig])
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use crate::op::{Message, Query};
    use crate::rr::Name;

    use super::*;
    fn assert_send_and_sync<T: Send + Sync>() {}

    #[test]
    fn test_send_and_sync() {
        assert_send_and_sync::<TSigner>();
    }

    #[test]
    fn test_sign_and_verify_message_tsig() {
        let time_begin = 1609459200u64;
        let fudge = 300u64;
        let origin: Name = Name::parse("example.com.", None).unwrap();
        let key_name: Name = Name::from_ascii("key_name").unwrap();
        let mut question: Message = Message::new();
        let mut query: Query = Query::new();
        query.set_name(origin);
        question.add_query(query);

        let sig_key = b"some_key".to_vec();
        let signer = TSigner::new(sig_key, Algorithm::HmacSha512, key_name, fudge as u16).unwrap();

        assert!(question.signature().is_empty());
        question
            .finalize(&signer, time_begin as u32)
            .expect("should have signed");
        assert!(!question.signature().is_empty());

        let validity_range = signer.verify_message(None, question).unwrap();
        assert!(validity_range.contains(&(time_begin + fudge / 2))); // slightly outdated, but still to be acceptable
        assert!(validity_range.contains(&(time_begin - fudge / 2))); // sooner than our time, but still acceptable
        assert!(!validity_range.contains(&(time_begin + fudge * 2))); // too late to be accepted
        assert!(!validity_range.contains(&(time_begin - fudge * 2))); // too soon to be accepted
    }

    // make rejection tests shorter by centralizing common setup code
    fn get_message_and_signer() -> (Message, TSigner) {
        let time_begin = 1609459200u64;
        let fudge = 300u64;
        let origin: Name = Name::parse("example.com.", None).unwrap();
        let key_name: Name = Name::from_ascii("key_name").unwrap();
        let mut question: Message = Message::new();
        let mut query: Query = Query::new();
        query.set_name(origin);
        question.add_query(query);

        let sig_key = b"some_key".to_vec();
        let signer = TSigner::new(sig_key, Algorithm::HmacSha512, key_name, fudge as u16).unwrap();

        assert!(question.signature().is_empty());
        question
            .finalize(&signer, time_begin as u32)
            .expect("should have signed");
        assert!(!question.signature().is_empty());

        // this should be ok, it has not been tampered with
        assert!(signer.verify_message(None, question.clone()).is_ok());

        (question, signer)
    }

    #[test]
    fn test_sign_and_verify_message_tsig_reject_keyname() {
        let (mut question, signer) = get_message_and_signer();

        let other_name: Name = Name::from_ascii("other_name").unwrap();
        let mut signature = question.take_signature().remove(0);
        signature.set_name(other_name);
        question.add_tsig(signature);

        assert!(signer.verify_message(None, question).is_err());
    }

    #[test]
    fn test_sign_and_verify_message_tsig_reject_invalid_mac() {
        let (mut question, signer) = get_message_and_signer();

        let mut query: Query = Query::new();
        let origin: Name = Name::parse("example.net.", None).unwrap();
        query.set_name(origin);
        question.add_query(query);

        assert!(signer.verify_message(None, question).is_err());
    }

    #[test]
    fn test_sign_and_verify_message_tsig_truncation() {
        let (mut question, signer) = get_message_and_signer();

        {
            let mut signature = question.take_signature().remove(0);
            if let RData::TSIG(ref mut tsig) = signature.rdata_mut() {
                let mut mac = tsig.mac().to_vec();
                mac.push(0); // make one longer than sha512
                std::mem::swap(tsig, &mut tsig.clone().set_mac(mac));
            } else {
                panic!("should have been a TSIG");
            }
            question.add_tsig(signature);
        }

        // we are longer, there is a problem
        assert!(signer.verify_message(None, question.clone()).is_err());
        {
            let mut signature = question.take_signature().remove(0);
            if let RData::TSIG(ref mut tsig) = signature.rdata_mut() {
                // sha512 is 512 bits, half of that is 256 bits, /8 for byte
                let mac = tsig.mac()[..256 / 8].to_vec();
                std::mem::swap(tsig, &mut tsig.clone().set_mac(mac));
            } else {
                panic!("should have been a TSIG");
            }
            question.add_tsig(signature);
        }

        // we are at half, it's allowed
        assert!(signer.verify_message(None, question.clone()).is_ok());

        {
            let mut signature = question.take_signature().remove(0);
            if let RData::TSIG(ref mut tsig) = signature.rdata_mut() {
                // less than half of sha512
                let mac = tsig.mac()[..240 / 8].to_vec();
                std::mem::swap(tsig, &mut tsig.clone().set_mac(mac));
            } else {
                panic!("should have been a TSIG");
            }
            question.add_tsig(signature);
        }

        assert!(signer.verify_message(None, question).is_err());
    }
}
