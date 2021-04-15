// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(missing_docs)] // reduce verbosity while working on it
//! signer is a structure for performing many of the signing processes of the DNSSec specification
use chrono::Duration;

use crate::proto::error::ProtoResult;
use crate::proto::rr::rdata::tsig::{message_tbs, Algorithm, TSIG};

use crate::op::{Message, MessageFinalizer};
use crate::rr::{DNSClass, Name, RData, Record, RecordType};

#[derive(Clone)]
pub struct TSigner {
    key: Vec<u8>,
    algorithm: Algorithm,
    signer_name: Name,
    fudge: Duration,
}

impl TSigner {
    pub fn new(key: Vec<u8>, algorithm: Algorithm, signer_name: Name, fudge: Duration) -> Self {
        TSigner {
            key,
            algorithm,
            signer_name,
            fudge,
        }
    }

    // TODO add getters

    pub fn authenticate(&self, tbs: &[u8]) -> ProtoResult<Vec<u8>> {
        self.algorithm.mac_data(&self.key, tbs)
    }

    pub fn authenticate_message(&self, message: &Message, pre_tsig: &TSIG) -> ProtoResult<Vec<u8>> {
        message_tbs(message, pre_tsig, &self.signer_name).and_then(|tbs| self.authenticate(&tbs))
    }
}

impl MessageFinalizer for TSigner {
    fn finalize_message(&self, message: &Message, current_time: u32) -> ProtoResult<Vec<Record>> {
        log::debug!("signing message: {:?}", message);

        // this is based on RFCs 2535, 2931 and 3007

        // 'For all SIG(0) RRs, the owner name, class, TTL, and original TTL, are
        //  meaningless.' - 2931
        let mut tsig = Record::new();
        tsig.set_ttl(0);
        tsig.set_dns_class(DNSClass::ANY);
        tsig.set_record_type(RecordType::TSIG);
        tsig.set_name(self.signer_name.clone());

        let pre_tsig = TSIG::new(
            self.algorithm.clone(),
            current_time as u64,
            self.fudge.num_seconds() as u16,
            Vec::new(),
            message.id(),
            0,
            Vec::new(),
        );
        let signature: Vec<u8> = self.authenticate_message(message, &pre_tsig)?;
        tsig.set_rdata(RData::TSIG(pre_tsig.set_mac(signature)));
        Ok(vec![tsig])
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    /*
        use openssl::bn::BigNum;
        use openssl::pkey::Private;
        use openssl::rsa::Rsa;

        use crate::op::{Message, Query};
        use crate::rr::rdata::key::KeyUsage;
        use crate::rr::rdata::{DNSSECRData, SIG};
        use crate::rr::{DNSClass, Name, Record, RecordType};

        use super::*;
        fn assert_send_and_sync<T: Send + Sync>() {}

        #[test]
        fn test_send_and_sync() {
            assert_send_and_sync::<Signer>();
        }

        fn pre_sig0(signer: &Signer, inception_time: u32, expiration_time: u32) -> SIG {
            SIG::new(
                // type covered in SIG(0) is 0 which is what makes this SIG0 vs a standard SIG
                RecordType::ZERO,
                signer.algorithm(),
                0,
                // see above, original_ttl is meaningless, The TTL fields SHOULD be zero
                0,
                // recommended time is +5 minutes from now, to prevent timing attacks, 2 is probably good
                expiration_time,
                // current time, this should be UTC
                // unsigned numbers of seconds since the start of 1 January 1970, GMT
                inception_time,
                signer.calculate_key_tag().unwrap(),
                // can probably get rid of this clone if the ownership is correct
                signer.signer_name().clone(),
                Vec::new(),
            )
        }

        #[test]
        fn test_sign_and_verify_message_sig0() {
            let origin: Name = Name::parse("example.com.", None).unwrap();
            let mut question: Message = Message::new();
            let mut query: Query = Query::new();
            query.set_name(origin);
            question.add_query(query);

            let rsa = Rsa::generate(2048).unwrap();
            let key = KeyPair::from_rsa(rsa).unwrap();
            let sig0key = key.to_sig0key(Algorithm::RSASHA256).unwrap();
            let signer = Signer::sig0(sig0key.clone(), key, Name::root());

            let pre_sig0 = pre_sig0(&signer, 0, 300);
            let sig = signer.sign_message(&question, &pre_sig0).unwrap();
            println!("sig: {:?}", sig);

            assert!(!sig.is_empty());

            assert!(sig0key.verify_message(&question, &sig, &pre_sig0).is_ok());

            // now test that the sig0 record works correctly.
            assert!(question.sig0().is_empty());
            question.finalize(&signer, 0).expect("should have signed");
            assert!(!question.sig0().is_empty());

            let sig = signer.sign_message(&question, &pre_sig0);
            println!("sig after sign: {:?}", sig);

            if let RData::DNSSEC(DNSSECRData::SIG(ref sig)) = *question.sig0()[0].rdata() {
                assert!(sig0key.verify_message(&question, sig.sig(), &sig).is_ok());
            }
        }

        #[test]
        #[allow(deprecated)]
        fn test_sign_and_verify_rrset() {
            let rsa = Rsa::generate(2048).unwrap();
            let key = KeyPair::from_rsa(rsa).unwrap();
            let sig0key = key
                .to_sig0key_with_usage(Algorithm::RSASHA256, KeyUsage::Zone)
                .unwrap();
            let signer = Signer::sig0(sig0key, key, Name::root());

            let origin: Name = Name::parse("example.com.", None).unwrap();
            let rrsig = Record::new()
                .set_name(origin.clone())
                .set_ttl(86400)
                .set_rr_type(RecordType::NS)
                .set_dns_class(DNSClass::IN)
                .set_rdata(RData::DNSSEC(DNSSECRData::SIG(SIG::new(
                    RecordType::NS,
                    Algorithm::RSASHA256,
                    origin.num_labels(),
                    86400,
                    5,
                    0,
                    signer.calculate_key_tag().unwrap(),
                    origin.clone(),
                    vec![],
                ))))
                .clone();
            let rrset = vec![
                Record::new()
                    .set_name(origin.clone())
                    .set_ttl(86400)
                    .set_rr_type(RecordType::NS)
                    .set_dns_class(DNSClass::IN)
                    .set_rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()))
                    .clone(),
                Record::new()
                    .set_name(origin)
                    .set_ttl(86400)
                    .set_rr_type(RecordType::NS)
                    .set_dns_class(DNSClass::IN)
                    .set_rdata(RData::NS(Name::parse("b.iana-servers.net.", None).unwrap()))
                    .clone(),
            ];

            let tbs = tbs::rrset_tbs_with_rrsig(&rrsig, &rrset).unwrap();
            let sig = signer.sign(&tbs).unwrap();

            let pub_key = signer.key().to_public_bytes().unwrap();
            let pub_key = PublicKeyEnum::from_public_bytes(&pub_key, Algorithm::RSASHA256).unwrap();

            assert!(pub_key
                .verify(Algorithm::RSASHA256, tbs.as_ref(), &sig)
                .is_ok());
        }

        fn get_rsa_from_vec(params: &[u32]) -> Result<Rsa<Private>, openssl::error::ErrorStack> {
            Rsa::from_private_components(
                BigNum::from_u32(params[0]).unwrap(), // modulus: n
                BigNum::from_u32(params[1]).unwrap(), // public exponent: e,
                BigNum::from_u32(params[2]).unwrap(), // private exponent: de,
                BigNum::from_u32(params[3]).unwrap(), // prime1: p,
                BigNum::from_u32(params[4]).unwrap(), // prime2: q,
                BigNum::from_u32(params[5]).unwrap(), // exponent1: dp,
                BigNum::from_u32(params[6]).unwrap(), // exponent2: dq,
                BigNum::from_u32(params[7]).unwrap(), // coefficient: qi
            )
        }

        #[test]
        #[allow(deprecated)]
        #[allow(clippy::unreadable_literal)]
        fn test_calculate_key_tag() {
            let test_vectors = vec![
                (vec![33, 3, 21, 11, 3, 1, 1, 1], 9739),
                (
                    vec![
                        0xc2fedb69, 0x10001, 0x6ebb9209, 0xf743, 0xc9e3, 0xd07f, 0x6275, 0x1095,
                    ],
                    42354,
                ),
            ];

            for &(ref input_data, exp_result) in test_vectors.iter() {
                let rsa = get_rsa_from_vec(input_data).unwrap();
                let rsa_pem = rsa.private_key_to_pem().unwrap();
                println!("pkey:\n{}", String::from_utf8(rsa_pem).unwrap());

                let key = KeyPair::from_rsa(rsa).unwrap();
                let sig0key = key
                    .to_sig0key_with_usage(Algorithm::RSASHA256, KeyUsage::Zone)
                    .unwrap();
                let signer = Signer::sig0(sig0key, key, Name::root());
                let key_tag = signer.calculate_key_tag().unwrap();

                assert_eq!(key_tag, exp_result);
            }
        }

        #[test]
        #[allow(deprecated)]
        fn test_calculate_key_tag_pem() {
            let x = "-----BEGIN RSA PRIVATE KEY-----
    MC0CAQACBQC+L6pNAgMBAAECBQCYj0ZNAgMA9CsCAwDHZwICeEUCAnE/AgMA3u0=
    -----END RSA PRIVATE KEY-----
    ";

            let rsa = Rsa::private_key_from_pem(x.as_bytes()).unwrap();
            let rsa_pem = rsa.private_key_to_pem().unwrap();
            println!("pkey:\n{}", String::from_utf8(rsa_pem).unwrap());

            let key = KeyPair::from_rsa(rsa).unwrap();
            let sig0key = key
                .to_sig0key_with_usage(Algorithm::RSASHA256, KeyUsage::Zone)
                .unwrap();
            let signer = Signer::sig0(sig0key, key, Name::root());
            let key_tag = signer.calculate_key_tag().unwrap();

            assert_eq!(key_tag, 28551);
        }

        // TODO: these tests technically came from TBS in trust_dns_proto
        #[cfg(feature = "openssl")]
        #[allow(clippy::module_inception)]
        #[cfg(test)]
        mod tests {
            use openssl::rsa::Rsa;

            use crate::rr::dnssec::tbs::*;
            use crate::rr::dnssec::*;
            use crate::rr::rdata::{DNSSECRData, SIG};
            use crate::rr::*;

            #[test]
            fn test_rrset_tbs() {
                let rsa = Rsa::generate(2048).unwrap();
                let key = KeyPair::from_rsa(rsa).unwrap();
                let sig0key = key.to_sig0key(Algorithm::RSASHA256).unwrap();
                let signer = Signer::sig0(sig0key, key, Name::root());

                let origin: Name = Name::parse("example.com.", None).unwrap();
                let rrsig = Record::new()
                    .set_name(origin.clone())
                    .set_ttl(86400)
                    .set_rr_type(RecordType::NS)
                    .set_dns_class(DNSClass::IN)
                    .set_rdata(RData::DNSSEC(DNSSECRData::SIG(SIG::new(
                        RecordType::NS,
                        Algorithm::RSASHA256,
                        origin.num_labels(),
                        86400,
                        5,
                        0,
                        signer.calculate_key_tag().unwrap(),
                        origin.clone(),
                        vec![],
                    ))))
                    .clone();
                let rrset = vec![
                    Record::new()
                        .set_name(origin.clone())
                        .set_ttl(86400)
                        .set_rr_type(RecordType::NS)
                        .set_dns_class(DNSClass::IN)
                        .set_rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()))
                        .clone(),
                    Record::new()
                        .set_name(origin.clone())
                        .set_ttl(86400)
                        .set_rr_type(RecordType::NS)
                        .set_dns_class(DNSClass::IN)
                        .set_rdata(RData::NS(Name::parse("b.iana-servers.net.", None).unwrap()))
                        .clone(),
                ];

                let tbs = rrset_tbs_with_rrsig(&rrsig, &rrset).unwrap();
                assert!(!tbs.as_ref().is_empty());

                let rrset = vec![
                    Record::new()
                        .set_name(origin.clone())
                        .set_ttl(86400)
                        .set_rr_type(RecordType::CNAME)
                        .set_dns_class(DNSClass::IN)
                        .set_rdata(RData::CNAME(
                            Name::parse("a.iana-servers.net.", None).unwrap(),
                        ))
                        .clone(), // different type
                    Record::new()
                        .set_name(Name::parse("www.example.com.", None).unwrap())
                        .set_ttl(86400)
                        .set_rr_type(RecordType::NS)
                        .set_dns_class(DNSClass::IN)
                        .set_rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()))
                        .clone(), // different name
                    Record::new()
                        .set_name(origin.clone())
                        .set_ttl(86400)
                        .set_rr_type(RecordType::NS)
                        .set_dns_class(DNSClass::CH)
                        .set_rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()))
                        .clone(), // different class
                    Record::new()
                        .set_name(origin.clone())
                        .set_ttl(86400)
                        .set_rr_type(RecordType::NS)
                        .set_dns_class(DNSClass::IN)
                        .set_rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()))
                        .clone(),
                    Record::new()
                        .set_name(origin)
                        .set_ttl(86400)
                        .set_rr_type(RecordType::NS)
                        .set_dns_class(DNSClass::IN)
                        .set_rdata(RData::NS(Name::parse("b.iana-servers.net.", None).unwrap()))
                        .clone(),
                ];

                let filtered_tbs = rrset_tbs_with_rrsig(&rrsig, &rrset).unwrap();
                assert!(!filtered_tbs.as_ref().is_empty());
                assert_eq!(tbs.as_ref(), filtered_tbs.as_ref());
            }
        }
        */
}
