#[cfg(feature = "openssl")]
use openssl::ec::EcKey;
#[cfg(feature = "openssl")]
use openssl::rsa::Rsa;
#[cfg(feature = "openssl")]
use openssl::symm::Cipher;

use error::*;
use rr::dnssec::Algorithm;
use rr::dnssec::KeyPair;

/// The format of the binary key
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyFormat {
    /// A der encoded key
    Der,
    /// A pem encoded key, the default of OpenSSL
    Pem,
    /// Raw bytes unformatted
    Raw,
}

impl KeyFormat {
    /// Decode private key
    #[allow(unused)]
    pub fn decode_key(self,
                      bytes: &[u8],
                      password: Option<&str>,
                      algorithm: Algorithm)
                      -> DnsSecResult<KeyPair> {
        //  empty string prevents openssl from triggering a read from stdin...
        let password = password.unwrap_or("");
        let password = password.as_bytes();

        match algorithm {
            #[cfg(feature = "openssl")]
            Algorithm::RSASHA1 |
            Algorithm::RSASHA1NSEC3SHA1 |
            Algorithm::RSASHA256 |
            Algorithm::RSASHA512 => {
                let key = match self {
                    KeyFormat::Der => {
                        try!(Rsa::private_key_from_der(bytes)
                            .map_err(|e| format!("error reading RSA as DER: {}", e)))
                    }
                    KeyFormat::Pem => {
                        let key = Rsa::private_key_from_pem_passphrase(bytes, password);

                        try!(key.map_err(|e| {
                            format!("could not decode RSA from PEM, bad password?: {}", e)
                        }))
                    }
                    e @ _ => {
                        return Err(format!("unsupported key format with RSA (DER or PEM only): \
                                            {:?}",
                                           e)
                                           .into())
                    }
                };

                return Ok(try!(KeyPair::from_rsa(key)
                    .map_err(|e| format!("could not tranlate RSA to KeyPair: {}", e))));
            }
            #[cfg(feature = "openssl")]
            Algorithm::ECDSAP256SHA256 |
            Algorithm::ECDSAP384SHA384 => {
                let key = match self {
                    KeyFormat::Der => {
                        try!(EcKey::private_key_from_der(bytes)
                            .map_err(|e| format!("error reading EC as DER: {}", e)))
                    }
                    KeyFormat::Pem => {
                        let key = EcKey::private_key_from_pem_passphrase(bytes, password);

                        try!(key.map_err(|e| {
                            format!("could not decode EC from PEM, bad password?: {}", e)
                        }))
                    }
                    e @ _ => {
                        return Err(format!("unsupported key format with EC (DER or PEM only): \
                                            {:?}",
                                           e)
                                           .into())
                    }
                };

                return Ok(try!(KeyPair::from_ec_key(key)
                    .map_err(|e| format!("could not tranlate RSA to KeyPair: {}", e))));
            }
            Algorithm::ED25519 => {
                match self {
                    KeyFormat::Raw => {
                        return KeyPair::from_private_bytes(algorithm, bytes)
                            .map_err(|e| format!("error reading ED25519 as RAW: {}", e).into())
                    }
                    e @ _ => {
                        return Err(format!("unsupported key format with ED25519 (RAW only): {:?}",
                                           e)
                                           .into())
                    }
                }
            }
            #[cfg(not(feature = "openssl"))]
            e @ _ => {
                return Err(format!("unsupported Algorith, enable openssl feature: {:?}", e).into())
            }
        }
    }

    /// Decode private key
    pub fn encode_key(self, key_pair: &KeyPair, password: Option<&str>) -> DnsSecResult<Vec<u8>> {
        // on encoding, if the password is empty string, ignore it (empty string is ok on decode)
        let password = password
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| s.as_bytes())
            .next();

        match *key_pair {
            #[cfg(feature = "openssl")]
            KeyPair::EC(ref pkey) |
            KeyPair::RSA(ref pkey) => {
                match self {
                    KeyFormat::Der => {
                        // to avoid accientally storing a key where there was an expectation that it was password protected
                        if password.is_some() {
                            return Err(format!("Can only password protect PEM: {:?}", self).into());
                        }
                        return pkey.private_key_to_der()
                                   .map_err(|e| {
                                                format!("error writing key as DER: {}", e).into()
                                            });
                    }
                    KeyFormat::Pem => {
                        let key = if let Some(password) = password {
                            pkey.private_key_to_pem_passphrase(Cipher::aes_256_cbc(), password)
                        } else {
                            pkey.private_key_to_pem()
                        };

                        return key.map_err(|e| format!("error writing key as PEM: {}", e).into());
                    }
                    e @ _ => {
                        return Err(format!("unsupported key format with RSA or EC (DER or PEM \
                                            only): {:?}",
                                           e)
                                           .into())
                    }
                }
            }
            #[cfg(feature = "ring")] KeyPair::ED25519(..) => {
                match self {
                    KeyFormat::Raw => {
                        // to avoid accientally storing a key where there was an expectation that it was password protected
                        if password.is_some() {
                            return Err(format!("Can only password protect PEM: {:?}", self).into());
                        }
                        return key_pair
                                   .to_private_bytes()
                                   .map_err(|e| {
                                                format!("error writing ED25519 as RAW: {}", e)
                                                    .into()
                                            });
                    }
                    e @ _ => {
                        return Err(format!("unsupported key format with ED25519 (RAW only): {:?}",
                                           e)
                                           .into())
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    pub use super::*;

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
    fn test_rsa_encode_decode_raw() {
        let algorithm = Algorithm::RSASHA256;
        encode_decode_with_format(KeyFormat::Raw, algorithm, false, false);
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
    #[cfg(feature = "openssl")]
    fn test_ec_encode_decode_raw() {
        let algorithm = Algorithm::ECDSAP256SHA256;
        encode_decode_with_format(KeyFormat::Raw, algorithm, false, false);
    }


    #[test]
    #[cfg(feature = "ring")]
    fn test_ed25519_encode_decode() {
        let algorithm = Algorithm::ED25519;
        encode_decode_with_format(KeyFormat::Der, algorithm, false, false);
        encode_decode_with_format(KeyFormat::Pem, algorithm, false, false);
        encode_decode_with_format(KeyFormat::Raw, algorithm, false, true);
    }

    #[cfg(test)]
    fn encode_decode_with_format(key_format: KeyFormat,
                                 algorithm: Algorithm,
                                 ok_pass: bool,
                                 ok_empty_pass: bool) {
        let keypair = KeyPair::generate(algorithm).unwrap();
        let password = Some("test password");
        let empty_password = Some("");
        let no_password = None::<&str>;

        encode_decode_with_password(key_format,
                                    &keypair,
                                    password,
                                    password,
                                    algorithm,
                                    ok_pass,
                                    true);
        encode_decode_with_password(key_format,
                                    &keypair,
                                    empty_password,
                                    empty_password,
                                    algorithm,
                                    ok_empty_pass,
                                    true);
        encode_decode_with_password(key_format,
                                    &keypair,
                                    no_password,
                                    no_password,
                                    algorithm,
                                    ok_empty_pass,
                                    true);
        encode_decode_with_password(key_format,
                                    &keypair,
                                    no_password,
                                    empty_password,
                                    algorithm,
                                    ok_empty_pass,
                                    true);
        encode_decode_with_password(key_format,
                                    &keypair,
                                    empty_password,
                                    no_password,
                                    algorithm,
                                    ok_empty_pass,
                                    true);
        encode_decode_with_password(key_format,
                                    &keypair,
                                    password,
                                    no_password,
                                    algorithm,
                                    ok_pass,
                                    false);
    }

    #[cfg(test)]
    fn encode_decode_with_password(key_format: KeyFormat,
                                   keypair: &KeyPair,
                                   en_pass: Option<&str>,
                                   de_pass: Option<&str>,
                                   algorithm: Algorithm,
                                   encode: bool,
                                   decode: bool) {
        let encoded = key_format.encode_key(&keypair, en_pass);
        if encode {
            assert!(encoded.is_ok(), format!("{}", encoded.unwrap_err()));
            let decoded = key_format.decode_key(&encoded.unwrap(), de_pass, algorithm);
            assert_eq!(decoded.is_ok(), decode);
        } else {
            assert!(encoded.is_err());
        }
    }
}