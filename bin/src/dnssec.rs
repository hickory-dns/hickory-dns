// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Configuration types for all security options in hickory-dns

use std::path::{Path, PathBuf};

use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::pem::PemObject;
use serde::Deserialize;
use time::Duration;
use tracing::info;

use hickory_proto::rr::domain::Name;
use hickory_proto::{
    ProtoError,
    dnssec::{Algorithm, SigSigner, SigningKey, rdata::DNSKEY, rdata::KEY, rdata::key::KeyUsage},
    rr::domain::IntoName,
};
use hickory_server::authority::DnssecAuthority;

/// Key pair configuration for DNSSEC keys for signing a zone
#[derive(Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    /// file path to the key
    pub key_path: PathBuf,
    /// the type of key stored
    pub algorithm: Algorithm,
    /// the name to use when signing records, e.g. ns.example.com
    pub signer_name: Option<String>,
    pub purpose: KeyPurpose,
}

impl KeyConfig {
    /// the signer name for the key, this defaults to the $ORIGIN aka zone name.
    pub fn signer_name(&self) -> Result<Option<Name>, ProtoError> {
        self.signer_name
            .as_ref()
            .map(|name| Name::parse(name, None))
            .transpose()
    }

    /// set of DNSSEC algorithms to use to sign the zone. enable_dnssec must be true.
    /// these will be looked up by $file.{key_name}.pem, for backward compatibility
    /// with previous versions of Hickory DNS, if enable_dnssec is enabled but
    /// supported_algorithms is not specified, it will default to "RSASHA256" and
    /// look for the $file.pem for the key. To control key length, or other options
    /// keys of the specified formats can be generated in PEM format. Instructions
    /// for custom keys can be found elsewhere.
    ///
    /// the currently supported set of supported_algorithms are
    /// ["RSASHA256", "RSASHA512", "ECDSAP256SHA256", "ECDSAP384SHA384", "ED25519"]
    ///
    /// keys are listed in pairs of key_name and algorithm, the search path is the
    /// same directory has the zone $file:
    ///  keys = [ "my_rsa_2048|RSASHA256", "/path/to/my_ed25519|ED25519" ]
    pub fn try_into_signer(&self, signer_name: impl IntoName) -> Result<SigSigner, String> {
        let name = match self.signer_name() {
            Ok(Some(name)) => name,
            Ok(None) => signer_name
                .into_name()
                .map_err(|e| format!("error loading signer name: {e}"))?,
            Err(e) => return Err(format!("error loading signer name: {e}")),
        };

        // read the key in
        let key = key_from_file(&self.key_path, self.algorithm)?;

        // add the key to the zone
        // TODO: allow the duration of signatures to be customized
        let pub_key = key
            .to_public_key()
            .map_err(|e| format!("error getting public key: {e}"))?;

        let signer = SigSigner::dnssec(
            DNSKEY::from_key(&pub_key),
            key,
            name,
            Duration::weeks(52)
                .try_into()
                .map_err(|e| format!("error converting time to std::Duration: {e}"))?,
        );

        signer
            .test_key()
            .map_err(|e| format!("key failed test: {e}"))?;
        Ok(signer)
    }

    pub async fn load(
        &self,
        authority: &mut impl DnssecAuthority<Lookup = impl Send + Sync + Sized + 'static>,
        zone_name: Name,
    ) -> Result<(), String> {
        info!(
            "adding key to zone: {:?}, purpose: {:?}",
            self.key_path, self.purpose,
        );

        match self.purpose {
            KeyPurpose::ZoneSigning => {
                let zone_signer = self
                    .try_into_signer(zone_name)
                    .map_err(|e| format!("failed to load key: {:?} msg: {}", self.key_path, e))?;
                authority
                    .add_zone_signing_key(zone_signer)
                    .await
                    .map_err(|err| format!("failed to add zone signing key to authority: {err}"))?;
            }

            KeyPurpose::ZoneUpdateAuth => {
                let update_auth_signer = self
                    .try_into_signer(zone_name.clone())
                    .map_err(|e| format!("failed to load key: {:?} msg: {}", self.key_path, e))?;
                let public_key = update_auth_signer
                    .key()
                    .to_public_key()
                    .map_err(|err| format!("failed to get public key: {err}"))?;
                let key = KEY::new_sig0key_with_usage(&public_key, KeyUsage::Host);
                authority
                    .add_update_auth_key(zone_name, key)
                    .await
                    .map_err(|err| format!("failed to update auth key to authority: {err}"))?;
            }
        }

        Ok(())
    }
}

/// What a key will be used for
#[derive(Clone, Copy, Deserialize, PartialEq, Eq, Debug)]
pub enum KeyPurpose {
    /// This key is used to sign a zone
    ///
    /// The public key for this must be trusted by a resolver to work. The key must have a private
    /// portion associated with it. It will be registered as a DNSKEY in the zone.
    ZoneSigning,

    /// This key is used for dynamic updates in the zone
    ///
    /// This is at least a public_key, and can be used for SIG0 dynamic updates
    ///
    /// it will be registered as a KEY record in the zone
    ZoneUpdateAuth,
}

pub fn key_from_file(path: &Path, algorithm: Algorithm) -> Result<Box<dyn SigningKey>, String> {
    use std::fs::File;
    use std::io::Read;

    use tracing::info;

    use hickory_proto::dnssec::crypto::signing_key_from_der;

    info!("reading key: {path:?}");
    let mut file =
        File::open(path).map_err(|e| format!("error opening private key file: {path:?}: {e}"))?;

    let mut buf = Vec::with_capacity(256);
    file.read_to_end(&mut buf)
        .map_err(|e| format!("could not read key from: {path:?}: {e}"))?;

    let key = match trim_ascii_start(&buf).starts_with(b"-----BEGIN ") {
        true => PrivateKeyDer::from_pem_slice(&buf)
            .map_err(|e| format!("could not read pem from {}: {e}", path.display()))?,
        false => PrivateKeyDer::try_from(&*buf)
            .map_err(|e| format!("could not read der from {}: {e}", path.display()))?,
    };

    signing_key_from_der(&key, algorithm).map_err(|e| format!("could not decode key: {e}"))
}

// Copied from std, MSRV 1.80
fn trim_ascii_start(mut bytes: &[u8]) -> &[u8] {
    // Note: A pattern matching based approach (instead of indexing) allows
    // making the function const.
    while let [first, rest @ ..] = bytes {
        match first.is_ascii_whitespace() {
            true => bytes = rest,
            false => return bytes,
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs8_pem_key() {
        // OpenSSL 3 generates PKCS#8-encoded RSA keys by default
        // `openssl genrsa 2048`
        key_from_file(
            Path::new("tests/test-data/rsa-2048-pkcs8.pem"),
            Algorithm::RSASHA256,
        )
        .expect("failed to read key");
    }

    #[test]
    fn pkcs1_pem_key() {
        // OpenSSL 1 used to generate PKCS#1-encoded RSA keys by default
        // OpenSSL 3 does not anymore, but you can still generate them with ssh-keygen
        // `ssh-keygen -t rsa -b 2048 -o -a 100 -f test-data/rsa-2048-pkcs1.pem -m PEM`
        key_from_file(
            Path::new("tests/test-data/rsa-2048-pkcs1.pem"),
            Algorithm::RSASHA256,
        )
        .expect("failed to read key");
    }
}
