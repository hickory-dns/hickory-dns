use openssl::ec::EcKey;
use openssl::rsa::Rsa;
use openssl::symm::Cipher;

use ::error::*;
use ::rr::dnssec::Algorithm;
use ::rr::dnssec::KeyPair;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyFormat { Der, Pem, Pkcs12, Raw, }

impl KeyFormat {
  /// Decode private key
  pub fn decode_key(self, bytes: &[u8], password: Option<&str>, algorithm: Algorithm) -> DnsSecResult<KeyPair> {
    // if self == KeyFormat::Pkcs12 {
    //   let pkcs12 = try!(Pkcs12::from_der(bytes)
    //                           .map_err(|e| DnsSecErrorKind::Msg(format!("could not decode pkcs12: {}", e).into())));
    //   let pkcs12 = try!(pkcs12.parse(password.unwrap_or(""))
    //                           .map_err(|e| format!("could not parse pkcs12, bad password?: {}", e).into()));
    //
    //   let pkey = pkcs12.pkey;
    //   match algorithm {
    //     Algorithm::RSASHA1 |
    //     Algorithm::RSASHA1NSEC3SHA1 |
    //     Algorithm::RSASHA256 |
    //     Algorithm::RSASHA512 => {
    //       return Ok(KeyPair::from_rsa_pkey(pkey))
    //     },
    //     Algorithm::ECDSAP256SHA256 |
    //     Algorithm::ECDSAP384SHA384 => {
    //       return Ok(KeyPair::from_ec_pkey(pkey))
    //     },
    //     e @ _ => return Err(format!("unsupported algorithm with pkcs12 (RSA or EC only): {:?}", e).into())
    //   }
    // }

    // the next password users all
    let password = password.map(|s|s.as_bytes());

    match algorithm {
      Algorithm::RSASHA1 |
      Algorithm::RSASHA1NSEC3SHA1 |
      Algorithm::RSASHA256 |
      Algorithm::RSASHA512 => {
        let key = match self {
          KeyFormat::Der => try!(Rsa::private_key_from_der(bytes)
                                    .map_err(|e| format!("error reading RSA as DER: {}", e))),
          KeyFormat::Pem => {
            let key = if let Some(password) = password {
              Rsa::private_key_from_pem_passphrase(bytes, password)
            } else {
              Rsa::private_key_from_pem(bytes)
            };

            try!(key.map_err(|e| format!("could not decode RSA from PEM, bad password?: {}", e)))
          },
          e @ _ => return Err(format!("unsupported key format with RSA (DER or PEM only): {:?}", e).into()),
        };

        return Ok(try!(KeyPair::from_rsa(key).map_err(|e| format!("could not tranlate RSA to KeyPair: {}", e))))
      },
      Algorithm::ECDSAP256SHA256 |
      Algorithm::ECDSAP384SHA384 => {
        let key = match self {
          KeyFormat::Der => try!(EcKey::private_key_from_der(bytes).map_err(|e| format!("error reading EC as DER: {}", e))),
          KeyFormat::Pem => {
            let key = if let Some(password) = password {
              EcKey::private_key_from_pem_passphrase(bytes, password)
            } else {
              EcKey::private_key_from_pem(bytes)
            };

            try!(key.map_err(|e| format!("could not decode EC from PEM, bad password?: {}", e)))
          },
          e @ _ => return Err(format!("unsupported key format with EC (DER or PEM only): {:?}", e).into()),
        };

        return Ok(try!(KeyPair::from_ec_key(key).map_err(|e| format!("could not tranlate RSA to KeyPair: {}", e))))
      },
      Algorithm::ED25519 => {
        match self {
          KeyFormat::Raw => return KeyPair::from_private_bytes(algorithm, bytes)
                                           .map_err(|e| format!("error reading ED25519 as RAW: {}", e).into()),
          e @ _ => return Err(format!("unsupported key format with ED25519 (RAW only): {:?}", e).into()),
        }
      }
    }
  }

  /// Decode private key
  pub fn encode_key(self, key_pair: &KeyPair, password: Option<&str>) -> DnsSecResult<Vec<u8>> {
    // the next password users all
    let password = password.map(|s|s.as_bytes());

    match *key_pair {
      KeyPair::EC(ref pkey) | KeyPair::RSA(ref pkey) => {
        match self {
          KeyFormat::Der => return pkey.private_key_to_der().map_err(|e| format!("error writing key as DER: {}", e).into()),
          KeyFormat::Pem => {
            let key = if let Some(password) = password {
              pkey.private_key_to_pem_passphrase(Cipher::aes_256_gcm(), password)
            } else {
              pkey.private_key_to_pem()
            };

            return key.map_err(|e| format!("error writing key as PEM: {}", e).into())
          },
          e @ _ => return Err(format!("unsupported key format with RSA or EC (DER or PEM only): {:?}", e).into()),
        }
      },
      KeyPair::ED25519(..) => {
        match self {
          KeyFormat::Raw => {
            return key_pair.to_private_bytes()
                           .map_err(|e| format!("error writing ED25519 as RAW: {}", e).into())
          },
          e @ _ => return Err(format!("unsupported key format with ED25519 (RAW only): {:?}", e).into()),
        }
      }
    }
  }
}
