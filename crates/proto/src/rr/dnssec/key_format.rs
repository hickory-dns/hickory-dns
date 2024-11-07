#[cfg(feature = "dnssec-openssl")]
use openssl::symm::Cipher;

use crate::error::DnsSecResult;
use crate::rr::dnssec::{Algorithm, KeyPair};

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
        let key_pair = match algorithm {
            Algorithm::Unknown(v) => return Err(format!("unknown algorithm: {v}").into()),
            #[cfg(feature = "dnssec-openssl")]
            e @ Algorithm::RSASHA1 | e @ Algorithm::RSASHA1NSEC3SHA1 => {
                return Err(format!("unsupported Algorithm (insecure): {e:?}").into())
            }
            #[cfg(feature = "dnssec-openssl")]
            Algorithm::RSASHA256 | Algorithm::RSASHA512 => KeyPair::generate(algorithm)?,
            Algorithm::ECDSAP256SHA256 | Algorithm::ECDSAP384SHA384 => match self {
                #[cfg(feature = "dnssec-openssl")]
                Self::Der | Self::Pem => KeyPair::generate(algorithm)?,
                e => return Err(format!("unsupported key format with EC: {e:?}").into()),
            },
            e => {
                return Err(
                    format!("unsupported Algorithm, enable openssl or ring feature: {e:?}").into(),
                )
            }
        };

        // encode the key
        #[allow(unreachable_code)]
        match key_pair {
            #[cfg(feature = "dnssec-openssl")]
            KeyPair::EC(pkey, _) | KeyPair::RSA(pkey, _) => {
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
            #[cfg(not(any(feature = "dnssec-openssl", feature = "dnssec-ring")))]
            _ => Err(format!(
                "unsupported Algorithm, enable openssl feature (encode not supported with ring)"
            )
            .into()),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;
    use crate::rr::dnssec::keypair::decode_key;
    #[cfg(feature = "dnssec-ring")]
    use crate::rr::dnssec::{EcdsaSigningKey, Ed25519SigningKey};

    #[test]
    #[cfg(feature = "dnssec-openssl")]
    fn test_rsa_encode_decode_der() {
        let algorithm = Algorithm::RSASHA256;
        encode_decode_with_format(KeyFormat::Der, algorithm, false, true);
    }

    #[test]
    #[cfg(feature = "dnssec-openssl")]
    fn test_rsa_encode_decode_pem() {
        let algorithm = Algorithm::RSASHA256;
        encode_decode_with_format(KeyFormat::Pem, algorithm, true, true);
    }

    #[test]
    #[cfg(feature = "dnssec-openssl")]
    fn test_ec_encode_decode_der() {
        let algorithm = Algorithm::ECDSAP256SHA256;
        encode_decode_with_format(KeyFormat::Der, algorithm, false, true);
    }

    #[test]
    #[cfg(feature = "dnssec-openssl")]
    fn test_ec_encode_decode_pem() {
        let algorithm = Algorithm::ECDSAP256SHA256;
        encode_decode_with_format(KeyFormat::Pem, algorithm, true, true);
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
            let decoded = decode_key(&encoded, de_pass, algorithm, key_format);
            assert_eq!(decoded.is_ok(), decode);
        } else {
            assert!(encoded_rslt.is_err());
        }
    }
}
