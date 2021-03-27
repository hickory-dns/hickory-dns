// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[cfg(feature = "openssl")]
pub mod tls {
    use openssl::asn1::*;
    use openssl::bn::*;
    use openssl::hash::MessageDigest;
    use openssl::nid;
    use openssl::pkcs12::*;
    use openssl::pkey::*;
    use openssl::rsa::*;
    use openssl::x509::extension::*;
    use openssl::x509::*;

    /// Generates a root certificate
    pub fn root_ca() -> (PKey, X509Name, X509) {
        let subject_name = "root.example.com";
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut x509_name = X509NameBuilder::new().unwrap();
        x509_name
            .append_entry_by_nid(nid::COMMONNAME, subject_name)
            .unwrap();
        let x509_name = x509_name.build();

        let mut serial: BigNum = BigNum::new().unwrap();
        serial.pseudo_rand(32, MSB_MAYBE_ZERO, false).unwrap();
        let serial = serial.to_asn1_integer().unwrap();

        let mut x509_build = X509::builder().unwrap();
        x509_build
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        x509_build
            .set_not_after(&Asn1Time::days_from_now(256).unwrap())
            .unwrap();
        x509_build.set_issuer_name(&x509_name).unwrap();
        x509_build.set_subject_name(&x509_name).unwrap();
        x509_build.set_pubkey(&pkey).unwrap();
        x509_build.set_serial_number(&serial).unwrap();

        let basic_constraints = BasicConstraints::new().critical().ca().build().unwrap();
        x509_build.append_extension(basic_constraints).unwrap();

        let subject_alternative_name = SubjectAlternativeName::new()
            .dns("root.example.com")
            .build(&x509_build.x509v3_context(None, None))
            .unwrap();
        x509_build
            .append_extension(subject_alternative_name)
            .unwrap();

        x509_build.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert = x509_build.build();

        (pkey, x509_name, cert)
    }

    /// Generates a certificate, see root_ca() for getting a root cert
    pub fn cert(
        subject_name: &str,
        ca_pkey: &PKey,
        ca_name: &X509Name,
        _: &X509,
    ) -> (PKey, X509, Pkcs12) {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut x509_name = X509NameBuilder::new().unwrap();
        x509_name
            .append_entry_by_nid(nid::COMMONNAME, subject_name)
            .unwrap();
        let x509_name = x509_name.build();

        let mut serial: BigNum = BigNum::new().unwrap();
        serial.pseudo_rand(32, MSB_MAYBE_ZERO, false).unwrap();
        let serial = serial.to_asn1_integer().unwrap();

        let mut x509_build = X509::builder().unwrap();
        x509_build
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        x509_build
            .set_not_after(&Asn1Time::days_from_now(256).unwrap())
            .unwrap();
        x509_build.set_issuer_name(&ca_name).unwrap();
        x509_build.set_subject_name(&x509_name).unwrap();
        x509_build.set_pubkey(&pkey).unwrap();
        x509_build.set_serial_number(&serial).unwrap();

        let ext_key_usage = ExtendedKeyUsage::new().server_auth().build().unwrap();
        x509_build.append_extension(ext_key_usage).unwrap();

        let subject_key_identifier = SubjectKeyIdentifier::new()
            .build(&x509_build.x509v3_context(None, None))
            .unwrap();
        x509_build.append_extension(subject_key_identifier).unwrap();

        let authority_key_identifier = AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&x509_build.x509v3_context(None, None))
            .unwrap();
        x509_build
            .append_extension(authority_key_identifier)
            .unwrap();

        // CA:FALSE
        let basic_constraints = BasicConstraints::new().critical().build().unwrap();
        x509_build.append_extension(basic_constraints).unwrap();

        x509_build.sign(&ca_pkey, MessageDigest::sha256()).unwrap();
        let cert = x509_build.build();

        let pkcs12_builder = Pkcs12::builder();
        let pkcs12 = pkcs12_builder
            .build("mypass", subject_name, &pkey, &cert)
            .unwrap();

        (pkey, cert, pkcs12)
    }
}
