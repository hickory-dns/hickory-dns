#[cfg(feature = "openssl")]
use openssl::ec::EcKey;
#[cfg(feature = "openssl")]
use openssl::rsa::Rsa;
#[cfg(feature = "openssl")]
use openssl::symm::Cipher;
#[cfg(feature = "ring")]
use ring::signature::{
    EcdsaKeyPair, Ed25519KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING,
};

use crate::error::*;
use crate::rr::dnssec::{Algorithm, KeyPair, Private};

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

impl KeyFormat {
    /// Decode private key
    #[allow(unused, clippy::match_single_binding)]
    pub fn decode_key(
        self,
        bytes: &[u8],
        password: Option<&str>,
        algorithm: Algorithm,
    ) -> DnsSecResult<KeyPair<Private>> {
        //  empty string prevents openssl from triggering a read from stdin...
        let password = password.unwrap_or("");
        let password = password.as_bytes();

        #[allow(deprecated)]
        match algorithm {
            Algorithm::Unknown(v) => Err(format!("unknown algorithm: {v}").into()),
            #[cfg(feature = "openssl")]
            e @ Algorithm::RSASHA1 | e @ Algorithm::RSASHA1NSEC3SHA1 => {
                Err(format!("unsupported Algorithm (insecure): {e:?}").into())
            }
            #[cfg(feature = "openssl")]
            Algorithm::RSASHA256 | Algorithm::RSASHA512 => {
                let key = match self {
                    Self::Der => Rsa::private_key_from_der(bytes)
                        .map_err(|e| format!("error reading RSA as DER: {e}"))?,
                    Self::Pem => {
                        let key = Rsa::private_key_from_pem_passphrase(bytes, password);

                        key.map_err(|e| {
                            format!("could not decode RSA from PEM, bad password?: {e}")
                        })?
                    }
                    e => {
                        return Err(format!(
                            "unsupported key format with RSA (DER or PEM only): \
                             {e:?}"
                        )
                        .into())
                    }
                };

                Ok(KeyPair::from_rsa(key)
                    .map_err(|e| format!("could not translate RSA to KeyPair: {e}"))?)
            }
            Algorithm::ECDSAP256SHA256 | Algorithm::ECDSAP384SHA384 => match self {
                #[cfg(feature = "openssl")]
                Self::Der => {
                    let key = EcKey::private_key_from_der(bytes)
                        .map_err(|e| format!("error reading EC as DER: {e}"))?;

                    Ok(KeyPair::from_ec_key(key)
                        .map_err(|e| format!("could not translate RSA to KeyPair: {e}"))?)
                }
                #[cfg(feature = "openssl")]
                Self::Pem => {
                    let key = EcKey::private_key_from_pem_passphrase(bytes, password)
                        .map_err(|e| format!("could not decode EC from PEM, bad password?: {e}"))?;

                    Ok(KeyPair::from_ec_key(key)
                        .map_err(|e| format!("could not translate RSA to KeyPair: {e}"))?)
                }
                #[cfg(feature = "ring")]
                Self::Pkcs8 => {
                    let ring_algorithm = if algorithm == Algorithm::ECDSAP256SHA256 {
                        &ECDSA_P256_SHA256_FIXED_SIGNING
                    } else {
                        &ECDSA_P384_SHA384_FIXED_SIGNING
                    };
                    let key = EcdsaKeyPair::from_pkcs8(ring_algorithm, bytes)?;

                    Ok(KeyPair::from_ecdsa(key))
                }
                e => Err(format!("unsupported key format with EC: {e:?}").into()),
            },
            Algorithm::ED25519 => match self {
                #[cfg(feature = "ring")]
                Self::Pkcs8 => {
                    let key = Ed25519KeyPair::from_pkcs8(bytes)?;

                    Ok(KeyPair::from_ed25519(key))
                }
                e => Err(format!(
                    "unsupported key format with ED25519 (only Pkcs8 supported): {e:?}"
                )
                .into()),
            },
            e => {
                Err(format!("unsupported Algorithm, enable openssl or ring feature: {e:?}").into())
            }
        }
    }

    /// Generate a new key and encode to the specified format
    pub fn generate_and_encode(
        self,
        algorithm: Algorithm,
        password: Option<&str>,
    ) -> DnsSecResult<Vec<u8>> {
        // on encoding, if the password is empty string, ignore it (empty string is ok on decode)
        #[allow(unused)]
        let password = password
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| s.as_bytes())
            .next();

        // generate the key
        #[allow(unused, deprecated)]
        let key_pair: KeyPair<Private> = match algorithm {
            Algorithm::Unknown(v) => return Err(format!("unknown algorithm: {v}").into()),
            #[cfg(feature = "openssl")]
            e @ Algorithm::RSASHA1 | e @ Algorithm::RSASHA1NSEC3SHA1 => {
                return Err(format!("unsupported Algorithm (insecure): {e:?}").into())
            }
            #[cfg(feature = "openssl")]
            Algorithm::RSASHA256 | Algorithm::RSASHA512 => KeyPair::generate(algorithm)?,
            Algorithm::ECDSAP256SHA256 | Algorithm::ECDSAP384SHA384 => match self {
                #[cfg(feature = "openssl")]
                Self::Der | Self::Pem => KeyPair::generate(algorithm)?,
                #[cfg(feature = "ring")]
                Self::Pkcs8 => return KeyPair::generate_pkcs8(algorithm),
                e => return Err(format!("unsupported key format with EC: {e:?}").into()),
            },
            #[cfg(feature = "ring")]
            Algorithm::ED25519 => return KeyPair::generate_pkcs8(algorithm),
            e => {
                return Err(
                    format!("unsupported Algorithm, enable openssl or ring feature: {e:?}").into(),
                )
            }
        };

        // encode the key
        #[allow(unreachable_code)]
        match key_pair {
            #[cfg(feature = "openssl")]
            KeyPair::EC(ref pkey) | KeyPair::RSA(ref pkey) => {
                match self {
                    Self::Der => {
                        // to avoid accidentally storing a key where there was an expectation that it was password protected
                        if password.is_some() {
                            return Err(format!("Can only password protect PEM: {self:?}").into());
                        }
                        pkey.private_key_to_der()
                            .map_err(|e| format!("error writing key as DER: {e}").into())
                    }
                    Self::Pem => {
                        let key = if let Some(password) = password {
                            pkey.private_key_to_pem_pkcs8_passphrase(
                                Cipher::aes_256_cbc(),
                                password,
                            )
                        } else {
                            pkey.private_key_to_pem_pkcs8()
                        };

                        key.map_err(|e| format!("error writing key as PEM: {e}").into())
                    }
                    e => Err(format!(
                        "unsupported key format with RSA or EC (DER or PEM \
                         only): {e:?}"
                    )
                    .into()),
                }
            }
            #[cfg(feature = "ring")]
            KeyPair::ECDSA(..) | KeyPair::ED25519(..) => panic!("should have returned early"),
            #[cfg(not(feature = "openssl"))]
            KeyPair::Phantom(..) => panic!("Phantom disallowed"),
            #[cfg(not(any(feature = "openssl", feature = "ring")))]
            _ => Err(format!(
                "unsupported Algorithm, enable openssl feature (encode not supported with ring)"
            )
            .into()),
        }
    }

    /// Encode private key
    #[deprecated]
    pub fn encode_key(
        self,
        key_pair: &KeyPair<Private>,
        password: Option<&str>,
    ) -> DnsSecResult<Vec<u8>> {
        // on encoding, if the password is empty string, ignore it (empty string is ok on decode)
        #[allow(unused)]
        let password = password
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| s.as_bytes())
            .next();

        match *key_pair {
            #[cfg(feature = "openssl")]
            KeyPair::EC(ref pkey) | KeyPair::RSA(ref pkey) => {
                match self {
                    Self::Der => {
                        // to avoid accidentally storing a key where there was an expectation that it was password protected
                        if password.is_some() {
                            return Err(format!("Can only password protect PEM: {self:?}").into());
                        }
                        pkey.private_key_to_der()
                            .map_err(|e| format!("error writing key as DER: {e}").into())
                    }
                    Self::Pem => {
                        let key = if let Some(password) = password {
                            pkey.private_key_to_pem_pkcs8_passphrase(
                                Cipher::aes_256_cbc(),
                                password,
                            )
                        } else {
                            pkey.private_key_to_pem_pkcs8()
                        };

                        key.map_err(|e| format!("error writing key as PEM: {e}").into())
                    }
                    e => Err(format!(
                        "unsupported key format with RSA or EC (DER or PEM \
                         only): {e:?}"
                    )
                    .into()),
                }
            }
            #[cfg(any(feature = "ring", not(feature = "openssl")))]
            _ => Err(
                "unsupported Algorithm, enable openssl feature (encode not supported with ring)"
                    .into(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;

    #[test]
    #[cfg(feature = "openssl")]
    fn test_rsa_encode_decode_der() {
        let algorithm = Algorithm::RSASHA256;
        encode_decode_with_format(KeyFormat::Der, algorithm, false, true);
    }

    #[test]
    #[cfg(feature = "openssl")]
    fn test_rsa_encode_decode_pem() {
        let algorithm = Algorithm::RSASHA256;
        encode_decode_with_format(KeyFormat::Pem, algorithm, true, true);
    }

    #[test]
    #[cfg(feature = "openssl")]
    fn test_ec_encode_decode_der() {
        let algorithm = Algorithm::ECDSAP256SHA256;
        encode_decode_with_format(KeyFormat::Der, algorithm, false, true);
    }

    #[test]
    #[cfg(feature = "openssl")]
    fn test_ec_encode_decode_pem() {
        let algorithm = Algorithm::ECDSAP256SHA256;
        encode_decode_with_format(KeyFormat::Pem, algorithm, true, true);
    }

    #[test]
    #[cfg(feature = "ring")]
    fn test_ec_encode_decode_pkcs8() {
        let algorithm = Algorithm::ECDSAP256SHA256;
        encode_decode_with_format(KeyFormat::Pkcs8, algorithm, true, true);
    }

    #[test]
    #[cfg(feature = "ring")]
    fn test_ed25519_encode_decode_pkcs8() {
        let algorithm = Algorithm::ED25519;
        encode_decode_with_format(KeyFormat::Pkcs8, algorithm, true, true);
    }

    #[cfg(test)]
    fn encode_decode_with_format(
        key_format: KeyFormat,
        algorithm: Algorithm,
        ok_pass: bool,
        ok_empty_pass: bool,
    ) {
        let password = Some("test password");
        let empty_password = Some("");
        let no_password = None::<&str>;

        encode_decode_with_password(key_format, password, password, algorithm, ok_pass, true);
        encode_decode_with_password(
            key_format,
            empty_password,
            empty_password,
            algorithm,
            ok_empty_pass,
            true,
        );
        encode_decode_with_password(
            key_format,
            no_password,
            no_password,
            algorithm,
            ok_empty_pass,
            true,
        );
        encode_decode_with_password(
            key_format,
            no_password,
            empty_password,
            algorithm,
            ok_empty_pass,
            true,
        );
        encode_decode_with_password(
            key_format,
            empty_password,
            no_password,
            algorithm,
            ok_empty_pass,
            true,
        );
        // TODO: disabled for now... add back in if ring supports passwords on pkcs8
        // encode_decode_with_password(key_format,
        //                             password,
        //                             no_password,
        //                             algorithm,
        //                             ok_pass,
        //                             false);
    }

    #[cfg(test)]
    fn encode_decode_with_password(
        key_format: KeyFormat,
        en_pass: Option<&str>,
        de_pass: Option<&str>,
        algorithm: Algorithm,
        encode: bool,
        decode: bool,
    ) {
        println!(
            "test params: format: {key_format:?}, en_pass: {en_pass:?}, de_pass: {de_pass:?}, alg: {algorithm:?}, encode: {encode}, decode: {decode}"
        );
        let encoded_rslt = key_format.generate_and_encode(algorithm, en_pass);

        if encode {
            let encoded = encoded_rslt.expect("Encoding error");
            let decoded = key_format.decode_key(&encoded, de_pass, algorithm);
            assert_eq!(decoded.is_ok(), decode);
        } else {
            assert!(encoded_rslt.is_err());
        }
    }
}
