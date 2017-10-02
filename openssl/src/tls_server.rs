use openssl::asn1::*;
use openssl::bn::*;
use openssl::{hash, nid};
use openssl::pkcs12::*;
use openssl::pkey::PKey;
use openssl::x509::*;
use openssl::x509::extension::*;

use std::fs::File;
use std::io::Read;
use std::path::Path;

use trust_dns::error::DnsSecResult;

pub use openssl::pkcs12::ParsedPkcs12;

pub fn read_cert(path: &Path, password: Option<&str>)
                 -> Result<ParsedPkcs12, String> {
    let mut file = try!(File::open(&path)
        .map_err(|e| format!("error opening pkcs12 cert file: {:?}: {}", path, e)));

    let mut key_bytes = vec![];
    try!(file.read_to_end(&mut key_bytes)
        .map_err(|e| format!("could not read pkcs12 key from: {:?}: {}", path, e)));
    let pkcs12 = try!(Pkcs12::from_der(&key_bytes)
        .map_err(|e| format!("badly formated pkcs12 key from: {:?}: {}", path, e)));
    pkcs12
        .parse(password.unwrap_or(""))
        .map_err(|e| format!("failed to open pkcs12 from: {:?}: {}", path, e))
}

/// generates a certificate
pub fn generate_cert(subject_name: &str, pkey: PKey, password: Option<&str>)
                     -> DnsSecResult<(X509, Pkcs12)> {
    let mut x509_name = try!(X509NameBuilder::new());
    try!(x509_name.append_entry_by_nid(nid::COMMONNAME, subject_name));
    let x509_name = x509_name.build();

    let mut serial: BigNum = try!(BigNum::new());
    try!(serial.pseudo_rand(32, MSB_MAYBE_ZERO, false));
    let serial = try!(serial.to_asn1_integer());

    let mut x509_build = try!(X509::builder());
    try!(Asn1Time::days_from_now(0).and_then(|t| x509_build.set_not_before(&t)));
    try!(Asn1Time::days_from_now(256).and_then(|t| x509_build.set_not_after(&t)));
    try!(x509_build.set_issuer_name(&x509_name));
    try!(x509_build.set_subject_name(&x509_name));
    try!(x509_build.set_pubkey(&pkey));
    try!(x509_build.set_serial_number(&serial));

    let ext_key_usage = try!(ExtendedKeyUsage::new()
        .server_auth()
        .client_auth()
        .build());
    try!(x509_build.append_extension(ext_key_usage));

    let subject_key_identifier = try!(SubjectKeyIdentifier::new()
        .build(&x509_build.x509v3_context(None, None)));
    try!(x509_build.append_extension(subject_key_identifier));

    let authority_key_identifier = try!(AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&x509_build.x509v3_context(None, None)));
    try!(x509_build.append_extension(authority_key_identifier));

    let subject_alternative_name = try!(SubjectAlternativeName::new()
        .dns(subject_name)
        .build(&x509_build.x509v3_context(None, None)));
    try!(x509_build.append_extension(subject_alternative_name));

    let basic_constraints = try!(BasicConstraints::new().critical().ca().build());
    try!(x509_build.append_extension(basic_constraints));

    try!(x509_build.sign(&pkey, hash::MessageDigest::sha256()));
    let cert = x509_build.build();

    let pkcs12_builder = Pkcs12::builder();
    let pkcs12 = try!(pkcs12_builder.build(password.unwrap_or(""), subject_name, &pkey, &cert));

    Ok((cert, pkcs12))
}
