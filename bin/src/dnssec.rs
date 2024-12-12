// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Configuration types for all security options in hickory-dns

use std::path::{Path, PathBuf};

#[cfg(feature = "dns-over-rustls")]
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
#[cfg(all(feature = "dnssec-ring", not(feature = "dns-over-rustls")))]
use rustls_pki_types::PrivateKeyDer;
use serde::Deserialize;
#[cfg(feature = "dnssec-ring")]
use tracing::info;

use hickory_proto::rr::domain::Name;
use hickory_proto::serialize::txt::ParseResult;
#[cfg(feature = "dnssec-ring")]
use hickory_proto::{
    dnssec::{rdata::key::KeyUsage, rdata::DNSKEY, rdata::KEY, Algorithm, SigSigner, SigningKey},
    rr::domain::IntoName,
};
#[cfg(feature = "dnssec-ring")]
use hickory_server::authority::DnssecAuthority;

/// Key pair configuration for DNSSEC keys for signing a zone
#[derive(Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    /// file path to the key
    pub key_path: String,
    /// the type of key stored, see `Algorithm`
    pub algorithm: String,
    /// the name to use when signing records, e.g. ns.example.com
    pub signer_name: Option<String>,
    pub purpose: KeyPurpose,
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

impl KeyConfig {
    /// Return a new KeyConfig
    ///
    /// # Arguments
    ///
    /// * `key_path` - file path to the key
    /// * `password` - password to use to read the key
    /// * `algorithm` - the type of key stored, see `Algorithm`
    /// * `signer_name` - the name to use when signing records, e.g. ns.example.com
    /// * `is_zone_signing_key` - specify that this key should be used for signing a zone
    /// * `is_zone_update_auth` - specifies that this key can be used for dynamic updates in the zone
    #[cfg(feature = "dnssec-ring")]
    pub fn new(
        key_path: String,
        algorithm: Algorithm,
        signer_name: String,
        purpose: KeyPurpose,
    ) -> Self {
        Self {
            key_path,
            algorithm: algorithm.as_str().to_string(),
            signer_name: Some(signer_name),
            purpose,
        }
    }

    /// path to the key file, either relative to the zone file, or a explicit from the root.
    pub fn key_path(&self) -> &Path {
        Path::new(&self.key_path)
    }

    /// algorithm for for the key, see `Algorithm` for supported algorithms.
    #[cfg(feature = "dnssec-ring")]
    #[allow(deprecated)]
    pub fn algorithm(&self) -> ParseResult<Algorithm> {
        match self.algorithm.as_str() {
            "RSASHA1" => Ok(Algorithm::RSASHA1),
            "RSASHA256" => Ok(Algorithm::RSASHA256),
            "RSASHA1-NSEC3-SHA1" => Ok(Algorithm::RSASHA1NSEC3SHA1),
            "RSASHA512" => Ok(Algorithm::RSASHA512),
            "ECDSAP256SHA256" => Ok(Algorithm::ECDSAP256SHA256),
            "ECDSAP384SHA384" => Ok(Algorithm::ECDSAP384SHA384),
            "ED25519" => Ok(Algorithm::ED25519),
            s => Err(format!("unrecognized string {s}").into()),
        }
    }

    /// the signer name for the key, this defaults to the $ORIGIN aka zone name.
    pub fn signer_name(&self) -> ParseResult<Option<Name>> {
        if let Some(signer_name) = self.signer_name.as_ref() {
            let name = Name::parse(signer_name, None)?;
            return Ok(Some(name));
        }

        Ok(None)
    }

    pub fn purpose(&self) -> KeyPurpose {
        self.purpose
    }

    /// Tries to read the defined key into a Signer
    #[cfg(feature = "dnssec-ring")]
    pub fn try_into_signer<N: IntoName>(&self, signer_name: N) -> Result<SigSigner, String> {
        let signer_name = signer_name
            .into_name()
            .map_err(|e| format!("error loading signer name: {e}"))?;

        let key = self
            .signer(signer_name)
            .map_err(|e| format!("failed to load key: {:?} msg: {e}", self.key_path()))?;

        key.test_key()
            .map_err(|e| format!("key failed test: {e}"))?;
        Ok(key)
    }

    #[cfg(feature = "dnssec-ring")]
    pub async fn load(
        &self,
        authority: &mut impl DnssecAuthority<Lookup = impl Send + Sync + Sized + 'static>,
        zone_name: &Name,
    ) -> Result<(), String> {
        info!(
            "adding key to zone: {:?}, purpose: {:?}",
            self.key_path(),
            self.purpose(),
        );

        match self.purpose() {
            KeyPurpose::ZoneSigning => {
                let zone_signer = self
                    .try_into_signer(zone_name.clone())
                    .map_err(|e| format!("failed to load key: {:?} msg: {}", self.key_path(), e))?;
                authority
                    .add_zone_signing_key(zone_signer)
                    .await
                    .map_err(|err| format!("failed to add zone signing key to authority: {err}"))?;
            }

            KeyPurpose::ZoneUpdateAuth => {
                let update_auth_signer = self
                    .try_into_signer(zone_name.clone())
                    .map_err(|e| format!("failed to load key: {:?} msg: {}", self.key_path(), e))?;
                let public_key = update_auth_signer
                    .key()
                    .to_public_key()
                    .map_err(|err| format!("failed to get public key: {err}"))?;
                let key = KEY::new_sig0key_with_usage(&public_key, KeyUsage::Host);
                authority
                    .add_update_auth_key(zone_name.clone(), key)
                    .await
                    .map_err(|err| format!("failed to update auth key to authority: {err}"))?;
            }
        }

        Ok(())
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
    #[cfg(feature = "dnssec-ring")]
    fn signer(&self, zone_name: Name) -> Result<SigSigner, String> {
        use time::Duration;

        let key_path = self.key_path();
        let algorithm = self
            .algorithm()
            .map_err(|e| format!("bad algorithm: {e}"))?;

        // read the key in
        let key = key_from_file(key_path, algorithm)?;

        let name = self
            .signer_name()
            .map_err(|e| format!("error reading name: {e}"))?
            .unwrap_or(zone_name);

        // add the key to the zone
        // TODO: allow the duration of signatures to be customized
        let pub_key = key
            .to_public_key()
            .map_err(|e| format!("error getting public key: {e}"))?;

        Ok(SigSigner::dnssec(
            DNSKEY::from_key(&pub_key),
            key,
            name,
            Duration::weeks(52)
                .try_into()
                .map_err(|e| format!("error converting time to std::Duration: {e}"))?,
        ))
    }
}

/// Configuration for a TLS certificate
#[derive(Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct TlsCertConfig {
    pub path: PathBuf,
    pub endpoint_name: Option<String>,
    pub private_key: PathBuf,
}

impl TlsCertConfig {
    /// Load a Certificate from the path (with rustls)
    #[cfg(feature = "dns-over-rustls")]
    pub fn load(
        &self,
        zone_dir: &Path,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
        use std::ffi::OsStr;

        use tracing::info;

        use hickory_proto::rustls::tls_server::{read_cert, read_key, read_key_from_der};

        if self.path.extension().and_then(OsStr::to_str) != Some("pem") {
            return Err(format!(
                "unsupported certificate file format (expected `.pem` extension): {}",
                self.path.display()
            ));
        }

        let cert_path = zone_dir.join(&self.path);
        info!(
            "loading TLS PEM certificate chain from: {}",
            cert_path.display()
        );
        let cert_chain = read_cert(&cert_path).map_err(|e| format!("error reading cert: {e}"))?;

        let key_extension = self.private_key.extension();
        let key = if key_extension.is_some_and(|ext| ext == "pem") {
            let key_path = zone_dir.join(&self.private_key);
            info!("loading TLS PKCS8 key from PEM: {}", key_path.display());
            read_key(&key_path)?
        } else if key_extension.is_some_and(|ext| ext == "der" || ext == "key") {
            let key_path = zone_dir.join(&self.private_key);
            info!("loading TLS PKCS8 key from DER: {}", key_path.display());
            read_key_from_der(&key_path)?
        } else {
            return Err(format!(
                "unsupported private key file format (expected `.pem` or `.der` extension): {}",
                self.private_key.display()
            ));
        };

        Ok((cert_chain, key))
    }
}

#[cfg(feature = "dnssec-ring")]
pub fn key_from_file(path: &Path, algorithm: Algorithm) -> Result<Box<dyn SigningKey>, String> {
    use std::fs::File;
    use std::io::Read;

    use rustls_pki_types::PrivatePkcs8KeyDer;
    use tracing::info;

    use hickory_proto::dnssec::ring::signing_key_from_der;

    info!("reading key: {path:?}");
    let mut file =
        File::open(path).map_err(|e| format!("error opening private key file: {path:?}: {e}"))?;

    let mut buf = Vec::with_capacity(256);
    file.read_to_end(&mut buf)
        .map_err(|e| format!("could not read key from: {path:?}: {e}"))?;

    let key = match path.extension().is_some_and(|ext| ext == "pk8") {
        true => PrivateKeyDer::from(PrivatePkcs8KeyDer::from(buf.as_slice())),
        false => return Err("unsupported key format (expected `.pk8` extension)".to_string()),
    };

    signing_key_from_der(&key, algorithm).map_err(|e| format!("could not decode key: {e}"))
}
