/// The format of the binary key
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyFormat {
    /// A der encoded key
    Der,
    /// A pem encoded key, the default of OpenSSL
    Pem,
    /// Pkcs8, a pkcs8 formatted private key
    Pkcs8,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;
    use crate::dnssec::{decode_key, Algorithm};
    #[cfg(feature = "dnssec-openssl")]
    use crate::dnssec::{EcSigningKey, RsaSigningKey};
    #[cfg(feature = "dnssec-ring")]
    use crate::dnssec::{EcdsaSigningKey, Ed25519SigningKey};

    #[test]
    #[cfg(feature = "dnssec-openssl")]
    fn test_rsa_encode_decode_der() {
        let algorithm = Algorithm::RSASHA256;
        let key = RsaSigningKey::generate(algorithm).unwrap();
        let der = key.encode_der().unwrap();
        decode_key(&der, None, algorithm, KeyFormat::Der).unwrap();
    }

    #[test]
    #[cfg(feature = "dnssec-openssl")]
    fn test_rsa_encode_decode_pem() {
        let algorithm = Algorithm::RSASHA256;
        let key = RsaSigningKey::generate(algorithm).unwrap();
        let pem = key.encode_pem(None).unwrap();
        decode_key(&pem, None, algorithm, KeyFormat::Pem).unwrap();

        let encrypted = key.encode_pem(Some("test password")).unwrap();
        decode_key(&encrypted, Some("test password"), algorithm, KeyFormat::Pem).unwrap();
    }

    #[test]
    #[cfg(feature = "dnssec-openssl")]
    fn test_ec_encode_decode_der() {
        let algorithm = Algorithm::ECDSAP256SHA256;
        let key = EcSigningKey::generate(algorithm).unwrap();
        let der = key.encode_der().unwrap();
        decode_key(&der, None, algorithm, KeyFormat::Der).unwrap();
    }

    #[test]
    #[cfg(feature = "dnssec-openssl")]
    fn test_ec_encode_decode_pem() {
        let algorithm = Algorithm::ECDSAP256SHA256;
        let key = EcSigningKey::generate(algorithm).unwrap();
        let pem = key.encode_pem(None).unwrap();
        decode_key(&pem, None, algorithm, KeyFormat::Pem).unwrap();

        let encrypted = key.encode_pem(Some("test password")).unwrap();
        decode_key(&encrypted, Some("test password"), algorithm, KeyFormat::Pem).unwrap();
    }

    #[test]
    #[cfg(feature = "dnssec-ring")]
    fn test_ec_encode_decode_pkcs8() {
        let algorithm = Algorithm::ECDSAP256SHA256;
        let pkcs8 = EcdsaSigningKey::generate_pkcs8(algorithm).unwrap();
        decode_key(&pkcs8, None, algorithm, KeyFormat::Pkcs8).unwrap();
    }

    #[test]
    #[cfg(feature = "dnssec-ring")]
    fn test_ed25519_encode_decode_pkcs8() {
        let pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap();
        decode_key(&pkcs8, None, Algorithm::ED25519, KeyFormat::Pkcs8).unwrap();
    }
}
