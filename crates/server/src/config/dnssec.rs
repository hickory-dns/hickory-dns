// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Configuration types for all security options in trust-dns

use std::path::Path;

#[cfg(all(feature = "dns-over-openssl", not(feature = "dns-over-rustls")))]
use openssl::{pkey::PKey, stack::Stack, x509::X509};
#[cfg(feature = "dns-over-rustls")]
use rustls::{Certificate, PrivateKey};
use serde::Deserialize;

use crate::client::error::ParseResult;
use crate::client::rr::domain::Name;
#[cfg(feature = "dnssec")]
use crate::client::rr::{
    dnssec::{Algorithm, KeyFormat, KeyPair, Private, SigSigner},
    domain::IntoName,
};

/// Key pair configuration for DNSSec keys for signing a zone
#[derive(Deserialize, PartialEq, Eq, Debug)]
pub struct KeyConfig {
    /// file path to the key
    pub key_path: String,
    /// password to use to read the key
    pub password: Option<String>,
    /// the type of key stored, see `Algorithm`
    pub algorithm: String,
    /// the name to use when signing records, e.g. ns.example.com
    pub signer_name: Option<String>,
    /// specify that this key should be used for signing a zone
    pub is_zone_signing_key: Option<bool>,
    /// specifies that this key can be used for dynamic updates in the zone
    pub is_zone_update_auth: Option<bool>,
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
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    pub fn new(
        key_path: String,
        password: Option<String>,
        algorithm: Algorithm,
        signer_name: String,
        is_zone_signing_key: bool,
        is_zone_update_auth: bool,
    ) -> Self {
        Self {
            key_path,
            password,
            algorithm: algorithm.as_str().to_string(),
            signer_name: Some(signer_name),
            is_zone_signing_key: Some(is_zone_signing_key),
            is_zone_update_auth: Some(is_zone_update_auth),
        }
    }

    /// path to the key file, either relative to the zone file, or a explicit from the root.
    pub fn key_path(&self) -> &Path {
        Path::new(&self.key_path)
    }

    /// Converts key into
    #[cfg(any(feature = "dns-over-tls", feature = "dnssec"))]
    #[cfg_attr(docsrs, doc(cfg(any(feature = "dns-over-tls", feature = "dnssec"))))]
    pub fn format(&self) -> ParseResult<KeyFormat> {
        use crate::client::error::ParseErrorKind;

        let extension = self.key_path().extension().ok_or_else(|| {
            ParseErrorKind::Msg(format!(
                "file lacks extension, e.g. '.pk8': {:?}",
                self.key_path()
            ))
        })?;

        match extension.to_str() {
            Some("der") => Ok(KeyFormat::Der),
            Some("key") => Ok(KeyFormat::Pem), // TODO: deprecate this...
            Some("pem") => Ok(KeyFormat::Pem),
            Some("pk8") => Ok(KeyFormat::Pkcs8),
            e => Err(ParseErrorKind::Msg(format!(
                "extension not understood, '{:?}': {:?}",
                e,
                self.key_path()
            ))
            .into()),
        }
    }

    /// Returns the password used to read the key
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// algorithm for for the key, see `Algorithm` for supported algorithms.
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
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
            s => Err(format!("unrecognized string {}", s).into()),
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

    /// specifies that this key should be used to sign the zone
    ///
    /// The public key for this must be trusted by a resolver to work. The key must have a private
    /// portion associated with it. It will be registered as a DNSKEY in the zone.
    pub fn is_zone_signing_key(&self) -> bool {
        self.is_zone_signing_key.unwrap_or(false)
    }

    /// this is at least a public_key, and can be used for SIG0 dynamic updates.
    ///
    /// it will be registered as a KEY record in the zone.
    pub fn is_zone_update_auth(&self) -> bool {
        self.is_zone_update_auth.unwrap_or(false)
    }

    /// Tries to read the defined key into a Signer
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    pub fn try_into_signer<N: IntoName>(&self, signer_name: N) -> Result<SigSigner, String> {
        let signer_name = signer_name
            .into_name()
            .map_err(|e| format!("error loading signer name: {}", e))?;

        let key = load_key(signer_name, self)
            .map_err(|e| format!("failed to load key: {:?} msg: {}", self.key_path(), e))?;

        key.test_key()
            .map_err(|e| format!("key failed test: {}", e))?;
        Ok(key)
    }
}

/// Certificate format of the file being read
#[derive(Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CertType {
    /// Pkcs12 formatted certificates and private key (requires OpenSSL)
    Pkcs12,
    /// PEM formatted Certificate chain
    Pem,
}

impl Default for CertType {
    fn default() -> Self {
        Self::Pkcs12
    }
}

/// Format of the private key file to read
#[derive(Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PrivateKeyType {
    /// PKCS8 formatted key file, allows for a password (requires Rustls)
    Pkcs8,
    /// DER formatted key, raw and unencrypted
    Der,
}

impl Default for PrivateKeyType {
    fn default() -> Self {
        Self::Der
    }
}

/// Configuration for a TLS certificate
#[derive(Deserialize, PartialEq, Eq, Debug)]
pub struct TlsCertConfig {
    path: String,
    endpoint_name: String,
    cert_type: Option<CertType>,
    password: Option<String>,
    private_key: Option<String>,
    private_key_type: Option<PrivateKeyType>,
}

impl TlsCertConfig {
    /// path to the pkcs12 der formatted certificate file
    pub fn get_path(&self) -> &Path {
        Path::new(&self.path)
    }

    /// return the DNS name of the certificate hosted at the TLS endpoint
    pub fn get_endpoint_name(&self) -> &str {
        &self.endpoint_name
    }

    /// Returns the format type of the certificate file
    pub fn get_cert_type(&self) -> CertType {
        self.cert_type.unwrap_or_default()
    }

    /// optional password for open the pkcs12, none assumes no password
    pub fn get_password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// returns the path to the private key, as associated with the certificate
    pub fn get_private_key(&self) -> Option<&Path> {
        self.private_key.as_deref().map(Path::new)
    }

    /// returns the path to the private key
    pub fn get_private_key_type(&self) -> PrivateKeyType {
        self.private_key_type.unwrap_or_default()
    }
}

/// set of DNSSEC algorithms to use to sign the zone. enable_dnssec must be true.
/// these will be lookedup by $file.{key_name}.pem, for backward compatibility
/// with previous versions of Trust-DNS, if enable_dnssec is enabled but
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
#[cfg(feature = "dnssec")]
fn load_key(zone_name: Name, key_config: &KeyConfig) -> Result<SigSigner, String> {
    use tracing::info;

    use std::convert::TryInto;
    use std::fs::File;
    use std::io::Read;

    use time::Duration;

    let key_path = key_config.key_path();
    let algorithm = key_config
        .algorithm()
        .map_err(|e| format!("bad algorithm: {}", e))?;
    let format = key_config
        .format()
        .map_err(|e| format!("bad key format: {}", e))?;

    // read the key in
    let key: KeyPair<Private> = {
        info!("reading key: {:?}", key_path);

        let mut file = File::open(&key_path)
            .map_err(|e| format!("error opening private key file: {:?}: {}", key_path, e))?;

        let mut key_bytes = Vec::with_capacity(256);
        file.read_to_end(&mut key_bytes)
            .map_err(|e| format!("could not read key from: {:?}: {}", key_path, e))?;

        format
            .decode_key(&key_bytes, key_config.password(), algorithm)
            .map_err(|e| format!("could not decode key: {}", e))?
    };

    let name = key_config
        .signer_name()
        .map_err(|e| format!("error reading name: {}", e))?
        .unwrap_or(zone_name);

    // add the key to the zone
    // TODO: allow the duration of signatures to be customized
    let dnskey = key
        .to_dnskey(algorithm)
        .map_err(|e| format!("error converting to dnskey: {}", e))?;
    Ok(SigSigner::dnssec(
        dnskey,
        key,
        name,
        Duration::weeks(52)
            .try_into()
            .map_err(|e| format!("error converting time to std::Duration: {}", e))?,
    ))
}

/// Load a Certificate from the path (with openssl)
#[cfg(all(feature = "dns-over-openssl", not(feature = "dns-over-rustls")))]
pub fn load_cert(
    zone_dir: &Path,
    tls_cert_config: &TlsCertConfig,
) -> Result<((X509, Option<Stack<X509>>), PKey<Private>), String> {
    use tracing::{info, warn};

    use crate::proto::openssl::tls_server::{
        read_cert_pem, read_cert_pkcs12, read_key_from_der, read_key_from_pkcs8,
    };

    let path = zone_dir.to_owned().join(tls_cert_config.get_path());
    let cert_type = tls_cert_config.get_cert_type();
    let password = tls_cert_config.get_password();
    let private_key_path = tls_cert_config
        .get_private_key()
        .map(|p| zone_dir.to_owned().join(p));
    let private_key_type = tls_cert_config.get_private_key_type();

    // if it's pkcs12, we'll be collecting the key and certs from that, otherwise continue processing
    let (cert, cert_chain) = match cert_type {
        CertType::Pem => {
            info!("loading TLS PEM certificate from: {:?}", path);
            read_cert_pem(&path)?
        }
        CertType::Pkcs12 => {
            if private_key_path.is_some() {
                warn!(
                    "ignoring specified key, using the one in the PKCS12 file: {}",
                    path.display()
                );
            }
            info!("loading TLS PKCS12 certificate from: {:?}", path);
            return read_cert_pkcs12(&path, password).map_err(Into::into);
        }
    };

    // it wasn't plcs12, we need to load the key separately
    let key = match (private_key_path, private_key_type) {
        (Some(private_key_path), PrivateKeyType::Pkcs8) => {
            info!("loading TLS PKCS8 key from: {}", private_key_path.display());
            read_key_from_pkcs8(&private_key_path, password)?
        }
        (Some(private_key_path), PrivateKeyType::Der) => {
            info!("loading TLS DER key from: {}", private_key_path.display());
            read_key_from_der(&private_key_path)?
        }
        (None, _) => {
            return Err(format!(
                "No private key associated with specified certificate"
            ));
        }
    };

    Ok(((cert, cert_chain), key))
}

/// Load a Certificate from the path (with rustls)
#[cfg(feature = "dns-over-rustls")]
#[cfg_attr(docsrs, doc(cfg(feature = "dns-over-rustls")))]
pub fn load_cert(
    zone_dir: &Path,
    tls_cert_config: &TlsCertConfig,
) -> Result<(Vec<Certificate>, PrivateKey), String> {
    use tracing::{info, warn};

    use crate::proto::rustls::tls_server::{read_cert, read_key, read_key_from_der};

    let path = zone_dir.to_owned().join(tls_cert_config.get_path());
    let cert_type = tls_cert_config.get_cert_type();
    let password = tls_cert_config.get_password();
    let private_key_path = tls_cert_config
        .get_private_key()
        .map(|p| zone_dir.to_owned().join(p));
    let private_key_type = tls_cert_config.get_private_key_type();

    let cert = match cert_type {
        CertType::Pem => {
            info!("loading TLS PEM certificate chain from: {}", path.display());
            read_cert(&path).map_err(|e| format!("error reading cert: {}", e))?
        }
        CertType::Pkcs12 => {
            return Err(
                "PKCS12 is not supported with Rustls for certificate, use PEM encoding".to_string(),
            );
        }
    };

    let key = match (private_key_path, private_key_type) {
        (Some(private_key_path), PrivateKeyType::Pkcs8) => {
            info!("loading TLS PKCS8 key from: {}", private_key_path.display());
            if password.is_some() {
                warn!("Password for key supplied, but Rustls does not support encrypted PKCS8");
            }

            read_key(&private_key_path)?
        }
        (Some(private_key_path), PrivateKeyType::Der) => {
            info!("loading TLS DER key from: {}", private_key_path.display());
            read_key_from_der(&private_key_path)?
        }
        (None, _) => return Err("No private key associated with specified certificate".to_string()),
    };

    Ok((cert, key))
}
