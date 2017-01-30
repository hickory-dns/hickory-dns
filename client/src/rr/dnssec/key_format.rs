use openssl::ec::EcKey;
use openssl::rsa::Rsa;
use openssl::symm::Cipher;

use ::error::*;
use ::rr::dnssec::Algorithm;
use ::rr::dnssec::KeyPair;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyFormat { Der, Pem, Raw }

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

    //  empty string prevents openssl from triggering a read from stdin...
    let password = password.unwrap_or("");
    let password = password.as_bytes();

    match algorithm {
      Algorithm::RSASHA1 |
      Algorithm::RSASHA1NSEC3SHA1 |
      Algorithm::RSASHA256 |
      Algorithm::RSASHA512 => {
        let key = match self {
          KeyFormat::Der => try!(Rsa::private_key_from_der(bytes)
                                    .map_err(|e| format!("error reading RSA as DER: {}", e))),
          KeyFormat::Pem => {
            let key = //if let Some(password) = password {
              Rsa::private_key_from_pem_passphrase(bytes, password)
            /* } else {
               Rsa::private_key_from_pem(bytes)
             }*/;

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
            let key = // if let Some(password) = password {
              EcKey::private_key_from_pem_passphrase(bytes, password)
            /* } else {
              EcKey::private_key_from_pem(bytes)
            }*/;

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
    // on encoding, if the password is empty string, ignore it (empty string is ok on decode)
    let password = password.iter().filter(|s| !s.is_empty()).map(|s|s.as_bytes()).next();

    match *key_pair {
      KeyPair::EC(ref pkey) | KeyPair::RSA(ref pkey) => {
        match self {
          KeyFormat::Der => {
            // to avoid accientally storing a key where there was an expectation that it was password protected
            if password.is_some() { return Err(format!("Can only password protect PEM: {:?}", self).into()) }
            return pkey.private_key_to_der().map_err(|e| format!("error writing key as DER: {}", e).into())
          },
          KeyFormat::Pem => {
            let key = if let Some(password) = password {
              pkey.private_key_to_pem_passphrase(Cipher::aes_256_cbc(), password)
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
            // to avoid accientally storing a key where there was an expectation that it was password protected
            if password.is_some() { return Err(format!("Can only password protect PEM: {:?}", self).into()) }
            return key_pair.to_private_bytes()
                           .map_err(|e| format!("error writing ED25519 as RAW: {}", e).into())
          },
          e @ _ => return Err(format!("unsupported key format with ED25519 (RAW only): {:?}", e).into()),
        }
      }
    }
  }
}

#[test]
fn test_rsa_encode_decode_der() {
  let algorithm = Algorithm::RSASHA256;
  encode_decode_with_format(KeyFormat::Der, algorithm, false, true);
}

#[test]
fn test_rsa_encode_decode_pem() {
  let algorithm = Algorithm::RSASHA256;
  encode_decode_with_format(KeyFormat::Pem, algorithm, true, true);
}

#[test]
fn test_rsa_encode_decode_raw() {
  let algorithm = Algorithm::RSASHA256;
  encode_decode_with_format(KeyFormat::Raw, algorithm, false, false);
}


#[test]
fn test_ec_encode_decode_der() {
  let algorithm = Algorithm::ECDSAP256SHA256;
  encode_decode_with_format(KeyFormat::Der, algorithm, false, true);
}

#[test]
fn test_ec_encode_decode_pem() {
  let algorithm = Algorithm::ECDSAP256SHA256;
  encode_decode_with_format(KeyFormat::Pem, algorithm, true, true);
}

#[test]
fn test_ec_encode_decode_raw() {
  let algorithm = Algorithm::ECDSAP256SHA256;
  encode_decode_with_format(KeyFormat::Raw, algorithm, false, false);
}


#[test]
fn test_ed25519_encode_decode() {
  let algorithm = Algorithm::ED25519;
  encode_decode_with_format(KeyFormat::Der, algorithm, false, false);
  encode_decode_with_format(KeyFormat::Pem, algorithm, false, false);
  encode_decode_with_format(KeyFormat::Raw, algorithm, false, true);
}

#[cfg(test)]
fn encode_decode_with_format(key_format: KeyFormat, algorithm: Algorithm, ok_pass: bool, ok_empty_pass: bool) {
  let keypair = KeyPair::generate(algorithm).unwrap();
  let password = Some("test password");
  let empty_password = Some("");
  let no_password = None::<&str>;

  encode_decode_with_password(key_format, &keypair, password, password, algorithm, ok_pass, true);
  encode_decode_with_password(key_format, &keypair, empty_password, empty_password, algorithm, ok_empty_pass, true);
  encode_decode_with_password(key_format, &keypair, no_password, no_password, algorithm, ok_empty_pass, true);
  encode_decode_with_password(key_format, &keypair, no_password, empty_password, algorithm, ok_empty_pass, true);
  encode_decode_with_password(key_format, &keypair, empty_password, no_password, algorithm, ok_empty_pass, true);
  encode_decode_with_password(key_format, &keypair, password, no_password, algorithm, ok_pass, false);
}

#[cfg(test)]
fn encode_decode_with_password(key_format: KeyFormat, keypair: &KeyPair, en_pass: Option<&str>,
   de_pass: Option<&str>, algorithm: Algorithm, encode: bool, decode: bool) {
  let encoded = key_format.encode_key(&keypair, en_pass);
  if encode {
    assert!(encoded.is_ok(), format!("{}", encoded.unwrap_err()));
    let decoded = key_format.decode_key(&encoded.unwrap(), de_pass, algorithm);
    assert_eq!(decoded.is_ok(), decode);
  } else {
    assert!(encoded.is_err());
  }
}
