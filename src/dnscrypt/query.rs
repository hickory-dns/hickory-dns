// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std::io::{Cursor, Read};
use std::cmp::{ Ord, Ordering };
use std::usize;

use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey;

use ::client::{Client, ClientConnection};
use ::error::{ClientResult, ClientErrorKind};
use ::op::Message;
use ::rr::{ DNSClass, Name, RData, RecordType };
use ::serialize::binary::{ BinEncoder, BinDecoder, BinSerializable };

use super::iso_iec_7816_4::pad;

/// <dnscrypt-query> ::= <client-magic> <client-pk> <client-nonce> <encrypted-query>
struct CryptQuery {
  /// <client-magic> ::= a 8 byte identifier for the resolver certificate chosen by the client.
  client_magic: u8,
  /// <client-pk> ::= the client's public key, whose length depends on the
  ///  encryption algorithm defined in the chosen certificate.
  client_pk: Vec<u8>,
  /// <client-nonce> ::= a unique query identifier for a given
  ///  (<client-sk>, <resolver-pk>) tuple. The same query sent twice for the same
  ///  (<client-sk>, <resolver-pk>) tuple must use two distinct <client-nonce>
  ///  values. The length of <client-nonce> depends on the chosen encryption
  ///  algorithm.
  client_nonce: Vec<u8>,
  /// <encrypted-query> ::= AE(<shared-key> <client-nonce> <client-nonce-pad>,
  ///                          <client-query> <client-query-pad>)
  ///
  /// AE ::= the authenticated encryption algorithm.
  encrypted_query: Vec<u8>,
}

impl CryptQuery {
  /// query's a server (as defined in the client) for a DNSCrypt certificate.
  ///
  /// # Arguments
  /// * `client` - client client connection for the DNSCrypt connection
  /// * `zone` - zone name to query for the DNSCrypt certificate
  ///
  /// ```text
  /// The client begins a DNSCrypt session by sending a regular unencrypted
  ///  TXT DNS query to the resolver IP address, on the DNSCrypt port, first
  ///  over UDP, then, in case of failure, timeout or truncation, over TCP.
  ///
  /// Resolvers are not required to serve certificates both on UDP and TCP.
  ///
  /// The name in the question must follow this scheme:
  ///
  /// <provider name> ::= <protocol-major-version> . dnscrypt-cert . <zone>
  ///
  /// A major protocol version has only one certificate format.
  /// ```
  pub fn query_cert<C>(client: Client<C>, zone: &Name) -> ClientResult<Option<Certificate>> where C: ClientConnection {
    // this can be static...
    let mut name = Name::with_labels(vec!["1".to_string(), "dnscrypt-cert".to_string()]);
    let query = name.append(zone);

    let message = try!(client.secure_query(query, DNSClass::IN, RecordType::TXT));

    Ok(message.get_answers().iter()
                            .filter(|r| r.get_rr_type() == RecordType::TXT)
                            .filter_map(|r| if let &RData::TXT(ref txt) = r.get_rdata() {
                              match Certificate::parse(txt.get_txt_data()) {
                                Ok(cert) => Some(cert),
                                Err(e) => { warn!("could not parse TXT into cert: {} for {:?}", e, r); None },
                              }
                            } else {
                              panic!("This should absolutely be a TXT rdata: {:?}", r.get_rdata())
                            })
                            .filter(|c| {
                              // After having received a set of certificates, the client checks their
                              //  validity based on the current date, filters out the ones designed for
                              //  encryption systems that are not supported by the client,
                              c.get_cert_version() == &CertVersion::X25519_XSalsa20Poly1305
                            })
                            //  and chooses the certificate with the higher serial number
                            .max())
  }

  pub fn encrypt_query(message: &Message, public_key: Vec<u8>, ) -> ClientResult<CryptQuery> {
    let mut buffer = Vec::with_capacity(512);
    {
      let mut encoder = BinEncoder::new(&mut buffer);
      try!(message.emit(&mut encoder));
    }

    // minimum is 256 for udp and 64 byte boundaries
    // TODO: make this pad in place...
    let padded = pad(&buffer, 256, 64);



    Ok(CryptQuery { client_magic: 0,
                    client_pk: vec![],
                    client_nonce: vec![],
                    encrypted_query: vec![]})
  }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum CertVersion {
  X25519_XSalsa20Poly1305,
  X25519_Chacha20Poly1305,
  Unknown,
}

impl CertVersion {
  #[inline]
  pub fn get_public_key_len(&self) -> usize {
    match *self {
      CertVersion::X25519_XSalsa20Poly1305 | CertVersion::X25519_Chacha20Poly1305 => 32,
      _ => usize::MAX, // MAX will cause parsers to fail if this is not checked...
    }
  }

  pub fn to_public_key(&self, bytes: &[u8]) -> PublicKey {
    match *self {
      CertVersion::X25519_XSalsa20Poly1305 => {
        PublicKey::from_slice(bytes).expect("poorly formatted key?")
      },
      _ => panic!("unsupported key: {:?}", bytes), // MAX will cause parsers to fail if this is not checked...
    }
  }
}

impl From<CertVersion> for u16 {
  fn from(version: CertVersion) -> Self {
    match version {
      CertVersion::X25519_XSalsa20Poly1305 => 0x00_01_u16,
      CertVersion::X25519_Chacha20Poly1305 => 0x00_02_u16,
      CertVersion::Unknown => 0x00_00_u16,
    }
  }
}

impl From<u16> for CertVersion {
  fn from(version: u16) -> Self {
    match version {
      0x00_01_u16 => CertVersion::X25519_XSalsa20Poly1305,
      0x00_02_u16 => CertVersion::X25519_Chacha20Poly1305,
      _ => CertVersion::Unknown,
    }
  }
}


/// A DNSCrypt Certificate
///
/// ```text
/// <cert-magic> <es-version> <protocol-minor-version> <signature>
/// <resolver-pk> <client-magic> <serial> <ts-start> <ts-end>
/// <extensions>
/// ```
pub struct Certificate {
  // no field for the cert-magic, it's static
  // 0x44 0x4e 0x53 0x43

  /// the cryptographic construction to use with this certificate
  es_version: CertVersion,
  /// Currently only 0x00 0x00
  protocol_minor_version: u16,
  /// a 64-byte signature of (<resolver-pk> <client-magic>
  ///  <serial> <ts-start> <ts-end> <extensions>) using the Ed25519 algorithm and the
  ///  provider secret key. Ed25519 must be used in this version of the
  ///  protocol.
  signature: Vec<u8>, //[u8; 64],
  /// the resolver short-term public key, which is 32 bytes when using X25519
  resolver_pk: PublicKey,
  /// the first 8 bytes of a client query that was built
  ///  using the information from this certificate. It may be a truncated
  ///  public key. Two valid certificates cannot share the same <client-magic>
  client_magic: Vec<u8>, // [u8; 8],
  /// a 4 byte serial number in big-endian format. If more than
  ///  one certificates are valid, the client must prefer the certificate
  ///  with a higher serial number
  serial: u32,
  /// the date the certificate is valid from, as a 4-byte
  ///  unsigned Unix timestamp.
  ts_start: u32,
  /// the date the certificate is valid until (inclusive), as a
  ///  4-byte unsigned Unix timestamp
  ts_end: u32,
  /// empty in the current protocol version, but may
  ///  contain additional data in future revisions, including minor versions.
  ///  The computation and the verification of the signature must include the
  ///  extensions. An implementation not supporting these extensions must
  ///  ignore them.
  extensions: Vec<u8>,
}

const CERT_MAGIC: [u8; 4] = [0x44,0x4e,0x53,0x43];

impl Certificate {
  pub fn get_cert_version(&self) -> &CertVersion { &self.es_version }

  fn parse(bytes: &[u8]) -> ClientResult<Self> {
    let mut decoder = BinDecoder::new(bytes);

    // validate cert magic
    let cert_magic = try!(decoder.read_vec(4));
    if &cert_magic != &CERT_MAGIC {
      return Err(ClientErrorKind::Msg(format!("incorrect cer-magic: {:?}", cert_magic)).into())
    }

    // es-version
    let cert_version: CertVersion = try!(decoder.read_u16()).into();
    if cert_version != CertVersion::X25519_XSalsa20Poly1305 {
      return Err(ClientErrorKind::Msg(format!("unsupported es-version: {:?}", cert_version)).into())
    }

    // protocol-minor-version
    let protocol_minor_version = try!(decoder.read_u16());

    // signature a 64-byte signature
    let signature = try!(decoder.read_vec(64));

    // the resolver short-term public key, which is 32 bytes when using X25519
    //  if this was not x25519, it would have returned above
    let resolver_pk = try!(decoder.read_vec(cert_version.get_public_key_len()));

    // the first 8 bytes of a client query that was built
    //  using the information from this certificate. It may be a truncated
    //  public key. Two valid certificates cannot share the same <client-magic>
    let client_magic = try!(decoder.read_vec(8));

    // a 4 byte serial number in big-endian format. If more than
    //  one certificates are valid, the client must prefer the certificate
    //  with a higher serial number.
    let serial = try!(decoder.read_u32());

    // the date the certificate is valid from, as a 4-byte
    //  unsigned Unix timestamp.
    let start_timestamp = try!(decoder.read_u32());
    let end_timestamp = try!(decoder.read_u32());

    // empty in the current protocol version, but may
    //  contain additional data in future revisions, including minor versions.
    //  The computation and the verification of the signature must include the
    //  extensions. An implementation not supporting these extensions must
    //  ignore them.
    // let extensions = try!(decoder.read_vec(0));

    Ok(Certificate{ es_version: cert_version,
                    protocol_minor_version: protocol_minor_version,
                    signature: signature,
                    resolver_pk: cert_version.to_public_key(&resolver_pk),
                    client_magic: client_magic,
                    serial: serial,
                    ts_start: start_timestamp,
                    ts_end: end_timestamp,
                    extensions: vec![],
                  })
  }
}

// TODO: these are a little ugly since they aren't true comparison operators, needed for max()
//  on iterator.
impl Ord for Certificate {
  fn cmp(&self, other: &Self) -> Ordering {
    self.serial.cmp(&other.serial)
  }
}

impl PartialOrd<Certificate> for Certificate {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

impl PartialEq<Certificate> for Certificate {
  fn eq(&self, other: &Self) -> bool {
    self.eq(other)
  }
}

impl Eq for Certificate {}
