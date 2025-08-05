use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertifiedKey, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256, SanType,
    SignatureAlgorithm,
};

use crate::Result;
use crate::container::Container;

/// A public key infrastructure (PKI) for dns-test containers.
///
/// Each PKI is a self-signed root certificate that can be used to issue
/// leaf certificates per-container. For simplicity's sake we don't use an
/// intermediate and directly sign leaf certs with the root.
pub struct Pki {
    root: (Issuer<'static, KeyPair>, Certificate),
}

impl Pki {
    /// Create a new container test PKI using `rcgen`.
    pub fn new() -> Result<Self> {
        // Create an issuer CA cert.
        let mut ca_params = CertificateParams::new(Vec::new())?;
        ca_params
            .distinguished_name
            .push(DnType::OrganizationName, "HickoryDNS");
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Conformance CA");
        ca_params.is_ca = rcgen::IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = KeyPair::generate_for(ALG)?;
        let ca_cert = ca_params.self_signed(&ca_key)?;
        let ca = Issuer::new(ca_params, ca_key);

        Ok(Self {
            root: (ca, ca_cert),
        })
    }

    /// Issue a leaf certificate/keypair for a given container using the PKI root
    pub fn certified_key_for_container(&self, c: &Container) -> Result<CertifiedKey<KeyPair>> {
        let mut container_leaf_params = CertificateParams::new(Vec::new())?;
        container_leaf_params
            .distinguished_name
            .push(DnType::CommonName, format!("{} ({})", c.name(), c.id()));
        container_leaf_params.is_ca = IsCa::NoCa;
        container_leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        container_leaf_params
            .subject_alt_names
            .push(SanType::IpAddress(c.ipv4_addr().into()));

        let signing_key = KeyPair::generate_for(ALG)?;
        let cert = container_leaf_params.signed_by(&signing_key, &self.root.0)?;

        Ok(CertifiedKey { cert, signing_key })
    }

    /// Return the PEM encoding of the PKI's root certificate.
    pub fn root_pem(&self) -> String {
        self.root.1.pem()
    }
}

static ALG: &SignatureAlgorithm = &PKCS_ECDSA_P256_SHA256;
