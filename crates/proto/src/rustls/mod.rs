// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TLS protocol related components for DNS over TLS

use alloc::sync::Arc;
use alloc::vec::Vec;

#[cfg(not(feature = "rustls-platform-verifier"))]
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct,
    client::danger::HandshakeSignatureValid,
    crypto::{self, CryptoProvider, verify_tls12_signature, verify_tls13_signature},
};
#[cfg(feature = "rustls-platform-verifier")]
use rustls_platform_verifier::BuilderVerifierExt;

pub mod tls_client_stream;
pub mod tls_stream;

pub use self::tls_client_stream::{
    TlsClientStream, tls_client_connect, tls_client_connect_with_bind_addr,
};
pub use self::tls_stream::{TlsStream, tls_connect, tls_connect_with_bind_addr, tls_from_stream};

/// Make a new [`ClientConfig`] with the default settings
pub fn client_config() -> Result<ClientConfig, rustls::Error> {
    let builder = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap();

    #[cfg(feature = "rustls-platform-verifier")]
    let builder = builder.with_platform_verifier()?;
    #[cfg(not(feature = "rustls-platform-verifier"))]
    let builder = builder.with_root_certificates({
        #[cfg_attr(not(feature = "webpki-roots"), allow(unused_mut))]
        let mut root_store = RootCertStore::empty();
        #[cfg(feature = "webpki-roots")]
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        root_store
    });

    Ok(builder.with_no_client_auth())
}

/// Instantiate a new [`CryptoProvider`] for use with rustls
#[cfg(all(feature = "tls-aws-lc-rs", not(feature = "tls-ring")))]
pub fn default_provider() -> CryptoProvider {
    crypto::aws_lc_rs::default_provider()
}

/// Instantiate a new [`CryptoProvider`] for use with rustls
#[cfg(feature = "tls-ring")]
pub fn default_provider() -> CryptoProvider {
    crypto::ring::default_provider()
}

/// A rustls ServerCertVerifier that performs **no** certificate verification.
///
/// This should only be used with great care, as skipping certificate verification is insecure
/// and could allow person-in-the-middle attacks.
#[derive(Debug)]
pub struct NoCertificateVerification(CryptoProvider);

impl Default for NoCertificateVerification {
    fn default() -> Self {
        Self(default_provider())
    }
}

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
