// Copyright (C) 2015 - 2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::sync::Arc as Rc;

use data_encoding::base32hex;
use openssl::crypto::pkey::Role;

use ::error::*;
use ::rr::{DNSClass, RecordType, Record, RData};
use ::rr::domain;
use ::rr::dnssec::{Signer, TrustAnchor};
use ::op::{ Message, MessageType, OpCode, Query, Edns, ResponseCode };
use ::serialize::binary::*;
use ::client::ClientConnection;

/// The Client is abstracted over either trust_dns::tcp::TcpClientConnection or
///  trust_dns::udp::UdpClientConnection, usage of TCP or UDP is up to the user. Some DNS servers
///  disallow TCP in some cases, so if TCP double check if UDP works.
pub struct Client<C: ClientConnection> {
  client_connection: RefCell<C>,
  next_id: Cell<u16>,
}

impl<C: ClientConnection> Client<C> {
  /// name_server to connect to with default port 53
  pub fn new(client_connection: C) -> Client<C> {
    Client{ client_connection: RefCell::new(client_connection), next_id: Cell::new(1037) }
  }

  /// When the resolver receives an answer via the normal DNS lookup process, it then checks to
  ///  make sure that the answer is correct. Then starts
  ///  with verifying the DS and DNSKEY records at the DNS root. Then use the DS
  ///  records for the top level domain found at the root, e.g. 'com', to verify the DNSKEY
  ///  records in the 'com' zone. From there see if there is a DS record for the
  ///  subdomain, e.g. 'example.com', in the 'com' zone, and if there is use the
  ///  DS record to verify a DNSKEY record found in the 'example.com' zone. Finally,
  ///  verify the RRSIG record found in the answer for the rrset, e.g. 'www.example.com'.
  pub fn secure_query(&self, query_name: &domain::Name, query_class: DNSClass, query_type: RecordType) -> ClientResult<Message> {
    // TODO: if we knew we were talking with a DNS server that supported multiple queries, these
    //  could be a single multiple query request...

    // with the secure setting, we should get the RRSIG as well as the answer
    //  the RRSIG is signed by the DNSKEY, the DNSKEY is signed by the DS record in the Parent
    //  zone. The key_tag is the DS record is assigned to the DNSKEY.
    let record_response = try!(self.inner_query(query_name, query_class, query_type, true));
    {
      // TODO, would iterators be more efficient to pass around?
      let rrsigs: Vec<&Record> = record_response.get_answers().iter()
                                                .chain(record_response.get_name_servers())
                                                .filter(|rr| rr.get_rr_type() == RecordType::RRSIG).collect();

      if rrsigs.is_empty() {
        return Err(ClientError::NoRRSIG);
      }

      // group the record sets by name and type
      let mut rrset_types: HashSet<(domain::Name, RecordType)> = HashSet::new();
      for rrset in record_response.get_answers().iter()
                                  .chain(record_response.get_name_servers())
                                  .filter(|rr| rr.get_rr_type() != RecordType::RRSIG)
                                  .map(|rr| (rr.get_name().clone(), rr.get_rr_type())) {
        rrset_types.insert(rrset);
      }

      // verify all returned rrsets
      for &(ref name, rrset_type) in rrset_types.iter() {
        let rrset: Vec<&Record> = record_response.get_answers().iter()
                                                 .chain(record_response.get_name_servers())
                                                 .filter(|rr| rr.get_rr_type() == rrset_type && rr.get_name() == name).collect();

        // '. DNSKEY' -> 'com. DS' -> 'com. DNSKEY' -> 'examle.com. DS' -> 'example.com. DNSKEY'
        // 'com. DS' is signed by '. DNSKEY' which produces 'com. RRSIG', all are in the same zone, '.'
        //  the '.' DNSKEY is signed by the well known root certificate.
        // TODO fix rrsigs clone()
        let proof = try!(self.recursive_query_verify(&name, rrset, rrsigs.clone(), query_type, query_class));

        // TODO return this, also make a prettier print
        debug!("proved existance through: {:?}", proof);
      }

      // at this point all records are validated, but if there are NSEC records present,
      //  then it's a negative confirmation...
      if record_response.get_response_code() == ResponseCode::NXDomain ||
         record_response.get_answers().is_empty() {
        let mut validated_nx = false;
        for &(_, rrset_type) in rrset_types.iter() {
          match rrset_type {
            rt @ RecordType::NSEC => {
              try!(self.verify_nsec(query_name, query_type, query_class,
                 record_response.get_name_servers().iter().filter(|rr| rr.get_rr_type() == rt).collect()));
              validated_nx = true;
            },
            rt @ RecordType::NSEC3 => {
              try!(self.verify_nsec3(query_name, query_type, query_class,
                record_response.get_name_servers().iter().filter(|rr| rr.get_rr_type() == RecordType::SOA).next(),
                record_response.get_name_servers().iter().filter(|rr| rr.get_rr_type() == rt).collect()));
              validated_nx = true;
            },
            _ => (),
          }
        }

        if !validated_nx { return Err(ClientError::NoNsec) }
      }
    }

    // getting here means that we looped through all records with validation
    Ok(record_response)
  }

  /// Verifies a record set against the supplied signatures, looking up the DNSKey chain.
  /// returns the chain of proof or an error if there is none.
  fn recursive_query_verify(&self, name: &domain::Name, rrset: Vec<&Record>, rrsigs: Vec<&Record>,
    query_type: RecordType, query_class: DNSClass) -> ClientResult<Vec<Record>> {

    // TODO: this is ugly, what reference do I want?
    let rrset: Vec<Record> = rrset.iter().map(|rr|rr.clone()).cloned().collect();

    // verify the DNSKey via a DS key if it's the secure_entry_point
    if let Some(record) = rrset.first() {
      if let &RData::DNSKEY{zone_key, secure_entry_point, ..} = record.get_rdata() {
        // the spec says that the secure_entry_point isn't reliable for the main DNSKey...
        //  but how do you know which needs to be validated with the DS in the parent zone?
        if zone_key && secure_entry_point {
          let mut proof = try!(self.verify_dnskey(record));
          // TODO: this is verified, it can be cached
          proof.push(record.clone());
          return Ok(proof);
        }
      }
    }

    // standard rrsig verification
    for rrsig in rrsigs.iter().filter(|rr| rr.get_name() == name) {
      // TODO: need to verify inception and experation...
      if let &RData::SIG(ref sig) = rrsig.get_rdata() {
        // get DNSKEY from signer_name
        let key_response = try!(self.inner_query(sig.get_signer_name(), query_class, RecordType::DNSKEY, true));
        let key_rrset: Vec<&Record> = key_response.get_answers().iter().filter(|rr| rr.get_rr_type() == RecordType::DNSKEY).collect();
        let key_rrsigs: Vec<&Record> = key_response.get_answers().iter().filter(|rr| rr.get_rr_type() == RecordType::RRSIG).collect();

        for dnskey in key_rrset.iter() {
          if let &RData::DNSKEY{zone_key, algorithm, revoke, ref public_key, ..} = dnskey.get_rdata() {
            if revoke { debug!("revoked: {}", dnskey.get_name()); continue } // TODO: does this need to be validated? RFC 5011
            if !zone_key { continue }
            if algorithm != sig.get_algorithm() { continue }

            let pkey = try!(algorithm.public_key_from_vec(public_key));
            if !pkey.can(Role::Verify) { debug!("pkey can't verify, {:?}", dnskey.get_name()); continue }

            let signer: Signer = Signer::new_verifier(algorithm, pkey, sig.get_signer_name().clone());
            let rrset_hash: Vec<u8> = signer.hash_rrset_with_rrsig(rrsig, &rrset);

            if signer.verify(&rrset_hash, sig.get_sig()) {
              if sig.get_signer_name() == name && query_type == RecordType::DNSKEY {
                // this is self signed... let's skip to DS validation
                let mut proof: Vec<Record> = try!(self.verify_dnskey(dnskey));
                // TODO: this is verified, cache it
                proof.push((*dnskey).clone());
                return Ok(proof);
              } else {
                let mut proof = try!(self.recursive_query_verify(sig.get_signer_name(), key_rrset.clone(), key_rrsigs, RecordType::DNSKEY, query_class));
                // TODO: this is verified, cache it
                proof.push((*dnskey).clone());
                return Ok(proof);
              }
            } else {
              debug!("could not verify: {} with: {}", name, rrsig.get_name());
            }
          } else {
            panic!("this should be a DNSKEY")
          }
        }
      } else {
        panic!("expected RRSIG: {:?}", rrsig.get_rr_type());
      }
    }

    Err(ClientError::NoDNSKEY)
  }

  /// attempts to verify the DNSKey against the DS of the parent.
  /// returns the chain of proof or an error if there is none.
  fn verify_dnskey(&self, dnskey: &Record) -> ClientResult<Vec<Record>> {
    let name: &domain::Name = dnskey.get_name();

    if dnskey.get_name().is_root() {
      if let &RData::DNSKEY{ ref public_key, .. } = dnskey.get_rdata() {
        if TrustAnchor::new().contains(public_key) {
          return Ok(vec![dnskey.clone()])
        }
      }
    }

    let ds_response = try!(self.inner_query(&name, dnskey.get_dns_class(), RecordType::DS, true));
    let ds_rrset: Vec<&Record> = ds_response.get_answers().iter().filter(|rr| rr.get_rr_type() == RecordType::DS).collect();
    let ds_rrsigs: Vec<&Record> = ds_response.get_answers().iter().filter(|rr| rr.get_rr_type() == RecordType::RRSIG).collect();

    for ds in ds_rrset.iter() {
      if let &RData::DS{digest_type, ref digest, ..} = ds.get_rdata() {
        // 5.1.4.  The Digest Field
        //
        //    The DS record refers to a DNSKEY RR by including a digest of that
        //    DNSKEY RR.
        //
        //    The digest is calculated by concatenating the canonical form of the
        //    fully qualified owner name of the DNSKEY RR with the DNSKEY RDATA,
        //    and then applying the digest algorithm.
        //
        //      digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
        //
        //       "|" denotes concatenation
        //
        //      DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.
        //
        //    The size of the digest may vary depending on the digest algorithm and
        //    DNSKEY RR size.  As of the time of this writing, the only defined
        //    digest algorithm is SHA-1, which produces a 20 octet digest.
        let mut buf: Vec<u8> = Vec::new();
        {
          let mut encoder: BinEncoder = BinEncoder::new(&mut buf);
          encoder.set_canonical_names(true);
          try!(name.emit(&mut encoder));
          try!(dnskey.get_rdata().emit(&mut encoder));
        }

        let hash: Vec<u8> = digest_type.hash(&buf);
        if &hash == digest {
          // continue to verify the chain...
          let mut proof: Vec<Record> = try!(self.recursive_query_verify(&name, ds_rrset.clone(), ds_rrsigs, RecordType::DNSKEY, dnskey.get_dns_class()));
          proof.push(dnskey.clone());
          return Ok(proof)
        }
      } else {
        panic!("expected DS: {:?}", ds.get_rr_type());
      }
    }

    Err(ClientError::NoDS)
  }

  // RFC 4035             DNSSEC Protocol Modifications            March 2005
  //
  // 5.4.  Authenticated Denial of Existence
  //
  //  A resolver can use authenticated NSEC RRs to prove that an RRset is
  //  not present in a signed zone.  Security-aware name servers should
  //  automatically include any necessary NSEC RRs for signed zones in
  //  their responses to security-aware resolvers.
  //
  //  Denial of existence is determined by the following rules:
  //
  //  o  If the requested RR name matches the owner name of an
  //     authenticated NSEC RR, then the NSEC RR's type bit map field lists
  //     all RR types present at that owner name, and a resolver can prove
  //     that the requested RR type does not exist by checking for the RR
  //     type in the bit map.  If the number of labels in an authenticated
  //     NSEC RR's owner name equals the Labels field of the covering RRSIG
  //     RR, then the existence of the NSEC RR proves that wildcard
  //     expansion could not have been used to match the request.
  //
  //  o  If the requested RR name would appear after an authenticated NSEC
  //     RR's owner name and before the name listed in that NSEC RR's Next
  //     Domain Name field according to the canonical DNS name order
  //     defined in [RFC4034], then no RRsets with the requested name exist
  //     in the zone.  However, it is possible that a wildcard could be
  //     used to match the requested RR owner name and type, so proving
  //     that the requested RRset does not exist also requires proving that
  //     no possible wildcard RRset exists that could have been used to
  //     generate a positive response.
  //
  //  In addition, security-aware resolvers MUST authenticate the NSEC
  //  RRsets that comprise the non-existence proof as described in Section
  //  5.3.
  //
  //  To prove the non-existence of an RRset, the resolver must be able to
  //  verify both that the queried RRset does not exist and that no
  //  relevant wildcard RRset exists.  Proving this may require more than
  //  one NSEC RRset from the zone.  If the complete set of necessary NSEC
  //  RRsets is not present in a response (perhaps due to message
  //  truncation), then a security-aware resolver MUST resend the query in
  //  order to attempt to obtain the full collection of NSEC RRs necessary
  //  to verify the non-existence of the requested RRset.  As with all DNS
  //  operations, however, the resolver MUST bound the work it puts into
  //  answering any particular query.
  //
  //  Since a validated NSEC RR proves the existence of both itself and its
  //  corresponding RRSIG RR, a validator MUST ignore the settings of the
  //  NSEC and RRSIG bits in an NSEC RR.
  fn verify_nsec(&self, query_name: &domain::Name, query_type: RecordType,
                 query_class: DNSClass, nsecs: Vec<&Record>) -> ClientResult<()> {
    debug!("verifying nsec");

    // first look for a record with the same name
    //  if they are, then the query_type should not exist in the NSEC record.
    //  if we got an NSEC record of the same name, but it is listed in the NSEC types,
    //    WTF? is that bad server, bad record
    if nsecs.iter().any(|r| query_name == r.get_name() && {
      if let &RData::NSEC { ref type_bit_maps, .. } = r.get_rdata() {
        !type_bit_maps.contains(&query_type)
      } else {
        panic!("expected NSEC was {:?}", r.get_rr_type())
      }
    }) { return Ok(()) }

    // based on the WTF? above, we will ignore any NSEC records of the same name
    if nsecs.iter().filter(|r| query_name != r.get_name()).any(|r| query_name > r.get_name() && {
      if let &RData::NSEC { ref next_domain_name, ..} = r.get_rdata() {
        query_name < next_domain_name
      } else {
        panic!("expected NSEC was {:?}", r.get_rr_type())
      }
    }) { return Ok(()) }

    // TODO: need to validate ANY or *.domain record existance, which doesn't make sense since
    //  that would have been returned in the request
    // if we got here, then there are no matching NSEC records, no validation
    Err(ClientError::InvalidNsec)
  }

  // Laurie, et al.              Standards Track                    [Page 22]
  //
  // RFC 5155                         NSEC3                        March 2008
  //
  //
  // 8.  Validator Considerations
  //
  // 8.1.  Responses with Unknown Hash Types
  //
  //    A validator MUST ignore NSEC3 RRs with unknown hash types.  The
  //    practical result of this is that responses containing only such NSEC3
  //    RRs will generally be considered bogus.
  //
  // 8.2.  Verifying NSEC3 RRs
  //
  //    A validator MUST ignore NSEC3 RRs with a Flag fields value other than
  //    zero or one.
  //
  //    A validator MAY treat a response as bogus if the response contains
  //    NSEC3 RRs that contain different values for hash algorithm,
  //    iterations, or salt from each other for that zone.
  //
  // 8.3.  Closest Encloser Proof
  //
  //    In order to verify a closest encloser proof, the validator MUST find
  //    the longest name, X, such that
  //
  //    o  X is an ancestor of QNAME that is matched by an NSEC3 RR present
  //       in the response.  This is a candidate for the closest encloser,
  //       and
  //
  //    o  The name one label longer than X (but still an ancestor of -- or
  //       equal to -- QNAME) is covered by an NSEC3 RR present in the
  //       response.
  //
  //    One possible algorithm for verifying this proof is as follows:
  //
  //    1.  Set SNAME=QNAME.  Clear the flag.
  //
  //    2.  Check whether SNAME exists:
  //
  //        *  If there is no NSEC3 RR in the response that matches SNAME
  //           (i.e., an NSEC3 RR whose owner name is the same as the hash of
  //           SNAME, prepended as a single label to the zone name), clear
  //           the flag.
  //
  //        *  If there is an NSEC3 RR in the response that covers SNAME, set
  //           the flag.
  //
  //        *  If there is a matching NSEC3 RR in the response and the flag
  //           was set, then the proof is complete, and SNAME is the closest
  //           encloser.
  //
  //        *  If there is a matching NSEC3 RR in the response, but the flag
  //           is not set, then the response is bogus.
  //
  //    3.  Truncate SNAME by one label from the left, go to step 2.
  //
  //    Once the closest encloser has been discovered, the validator MUST
  //    check that the NSEC3 RR that has the closest encloser as the original
  //    owner name is from the proper zone.  The DNAME type bit must not be
  //    set and the NS type bit may only be set if the SOA type bit is set.
  //    If this is not the case, it would be an indication that an attacker
  //    is using them to falsely deny the existence of RRs for which the
  //    server is not authoritative.
  //
  //    In the following descriptions, the phrase "a closest (provable)
  //    encloser proof for X" means that the algorithm above (or an
  //    equivalent algorithm) proves that X does not exist by proving that an
  //    ancestor of X is its closest encloser.
  fn verify_nsec3(&self, query_name: &domain::Name, query_type: RecordType,
                  query_class: DNSClass, soa: Option<&Record>,
                  nsec3s: Vec<&Record>) -> ClientResult<()> {
    // the search name is the one to look for
    let zone_name = try!(soa.ok_or(ClientError::NoSOARecord(query_name.clone()))).get_name();
    debug!("nsec3s: {:?}", nsec3s);

    for nsec3 in nsec3s {
      // for each nsec3 we search for matching hashed names
      let mut search_name: domain::Name = query_name.clone();

      // hash the search name
      if let &RData::NSEC3{hash_algorithm, iterations, ref salt, ref type_bit_maps, ..} = nsec3.get_rdata() {
        // search all the name options
        while search_name.num_labels() >= zone_name.num_labels() {

          // TODO: cache hashes across nsec3 validations
          let hash = hash_algorithm.hash(salt, &search_name, iterations);
          let hash_label = base32hex::encode(&hash).to_lowercase();
          let hash_name = zone_name.prepend_label(Rc::new(hash_label));

          if &hash_name == nsec3.get_name() {
            // like nsec, if there is a name that matches, then we have proof that the name does
            //  not exist
            if &search_name == query_name {
              if !type_bit_maps.contains(&query_type) { return Ok(()) }
            }

            return Ok(())
          }

          // need to continue up the chain
          search_name = search_name.base_name();
        }
      }
    }

    Err(ClientError::InvalidNsec3)
  }

  // send a DNS query to the name_server specified in Client.
  //
  // ```
  // use std::net::*;
  //
  // use trust_dns::rr::dns_class::DNSClass;
  // use trust_dns::rr::record_type::RecordType;
  // use trust_dns::rr::domain;
  // use trust_dns::rr::record_data::RData;
  // use trust_dns::udp::client::Client;
  //
  // let name = domain::Name::with_labels(vec!["www".to_string(), "example".to_string(), "com".to_string()]);
  // let client = Client::new(("8.8.8.8").parse().unwrap()).unwrap();
  // let response = client.query(name.clone(), DNSClass::IN, RecordType::A).unwrap();
  //
  // let record = &response.get_answers()[0];
  // assert_eq!(record.get_name(), &name);
  // assert_eq!(record.get_rr_type(), RecordType::A);
  // assert_eq!(record.get_dns_class(), DNSClass::IN);
  //
  // if let &RData::A{ ref address } = record.get_rdata() {
  //   assert_eq!(address, &Ipv4Addr::new(93,184,216,34))
  // } else {
  //   assert!(false);
  // }
  //
  // ```
  pub fn query(&self, name: &domain::Name, query_class: DNSClass, query_type: RecordType) -> ClientResult<Message> {
    self.inner_query(name, query_class, query_type, false)
  }

  fn inner_query(&self, name: &domain::Name, query_class: DNSClass, query_type: RecordType, secure: bool) -> ClientResult<Message> {
    debug!("querying: {} {:?}", name, query_type);

    // TODO: this isn't DRY, duplicate code with the TCP client

    // build the message
    let mut message: Message = Message::new();
    let id = self.next_id();
    // TODO make recursion a parameter
    message.id(id).message_type(MessageType::Query).op_code(OpCode::Query).recursion_desired(true);

    // Extended dns
    let mut edns: Edns = Edns::new();

    if secure {
      edns.set_dnssec_ok(true);
      message.authentic_data(true);
      message.checking_disabled(false);
    }

    edns.set_max_payload(1500);
    edns.set_version(0);

    message.set_edns(edns);

    // add the query
    let mut query: Query = Query::new();
    query.name(name.clone()).query_class(query_class).query_type(query_type);
    message.add_query(query);

    // get the message bytes and send the query
    let mut buffer: Vec<u8> = Vec::with_capacity(512);
    {
      let mut encoder = BinEncoder::new(&mut buffer);
      try!(message.emit(&mut encoder));
    }

    // send the message and get the response from the connection.
    let resp_buffer = try!(self.client_connection.borrow_mut().send(buffer));

    let mut decoder = BinDecoder::new(&resp_buffer);
    let response = try!(Message::read(&mut decoder));

    if response.get_id() != id { return Err(ClientError::IncorrectMessageId{ got: response.get_id(), expect: id }); }

    Ok(response)
  }

  fn next_id(&self) -> u16 {
    let id = self.next_id.get();
    self.next_id.set(id + 1);
    id
  }
}

#[cfg(test)]
#[cfg(feature = "ftest")]
mod test {
  use std::net::*;

  use ::rr::{DNSClass, RecordType, domain, RData};
  use ::op::ResponseCode;
  use ::udp::UdpClientConnection;
  use ::tcp::TcpClientConnection;
  use super::Client;
  use super::super::ClientConnection;

  #[test]
  #[cfg(feature = "ftest")]
  fn test_query_udp() {
    let addr: SocketAddr = ("8.8.8.8",53).to_socket_addrs().unwrap().next().unwrap();
    let conn = UdpClientConnection::new(addr).unwrap();
    test_query(conn);
  }

  #[test]
  #[cfg(feature = "ftest")]
  fn test_query_tcp() {
    let addr: SocketAddr = ("8.8.8.8",53).to_socket_addrs().unwrap().next().unwrap();
    let conn = TcpClientConnection::new(addr).unwrap();
    test_query(conn);
  }


  // TODO: this should be flagged with cfg as a functional test.
  #[cfg(test)]
  #[cfg(feature = "ftest")]
  fn test_query<C: ClientConnection>(conn: C) {
    let name = domain::Name::with_labels(vec!["www".to_string(), "example".to_string(), "com".to_string()]);
    let client = Client::new(conn);

    let response = client.query(&name, DNSClass::IN, RecordType::A);
    assert!(response.is_ok(), "query failed: {}", response.unwrap_err());

    let response = response.unwrap();

    println!("response records: {:?}", response);

    let record = &response.get_answers()[0];
    assert_eq!(record.get_name(), &name);
    assert_eq!(record.get_rr_type(), RecordType::A);
    assert_eq!(record.get_dns_class(), DNSClass::IN);

    if let &RData::A(ref address) = record.get_rdata() {
      assert_eq!(address, &Ipv4Addr::new(93,184,216,34))
    } else {
      assert!(false);
    }
  }

  #[test]
  #[cfg(feature = "ftest")]
  fn test_secure_query_example_udp() {
    let addr: SocketAddr = ("8.8.8.8",53).to_socket_addrs().unwrap().next().unwrap();
    let conn = UdpClientConnection::new(addr).unwrap();
    test_secure_query_example(conn);
  }

  #[test]
  #[cfg(feature = "ftest")]
  fn test_secure_query_example_tcp() {
    let addr: SocketAddr = ("8.8.8.8",53).to_socket_addrs().unwrap().next().unwrap();
    let conn = TcpClientConnection::new(addr).unwrap();
    test_secure_query_example(conn);
  }

  #[cfg(test)]
  #[cfg(feature = "ftest")]
  fn test_secure_query_example<C: ClientConnection>(conn: C) {
    let name = domain::Name::with_labels(vec!["www".to_string(), "example".to_string(), "com".to_string()]);
    let client = Client::new(conn);

    let response = client.secure_query(&name, DNSClass::IN, RecordType::A);
    assert!(response.is_ok(), "query failed: {}", response.unwrap_err());

    let response = response.unwrap();

    println!("response records: {:?}", response);

    let record = &response.get_answers()[0];
    assert_eq!(record.get_name(), &name);
    assert_eq!(record.get_rr_type(), RecordType::A);
    assert_eq!(record.get_dns_class(), DNSClass::IN);

    if let &RData::A(ref address) = record.get_rdata() {
      assert_eq!(address, &Ipv4Addr::new(93,184,216,34))
    } else {
      assert!(false);
    }
  }

  #[test]
  #[cfg(feature = "ftest")]
  fn test_nsec_query_example_udp() {
    let addr: SocketAddr = ("8.8.8.8",53).to_socket_addrs().unwrap().next().unwrap();
    let conn = UdpClientConnection::new(addr).unwrap();
    test_nsec_query_example(conn);
  }

  #[test]
  #[cfg(feature = "ftest")]
  fn test_nsec_query_example_tcp() {
    let addr: SocketAddr = ("8.8.8.8",53).to_socket_addrs().unwrap().next().unwrap();
    let conn = TcpClientConnection::new(addr).unwrap();
    test_nsec_query_example(conn);
  }


  #[cfg(test)]
  #[cfg(feature = "ftest")]
  fn test_nsec_query_example<C: ClientConnection>(conn: C) {
    let name = domain::Name::with_labels(vec!["none".to_string(), "example".to_string(), "com".to_string()]);
    let client = Client::new(conn);

    let response = client.secure_query(&name, DNSClass::IN, RecordType::A);
    assert!(response.is_ok(), "query failed: {}", response.unwrap_err());

    let response = response.unwrap();
    assert_eq!(response.get_response_code(), ResponseCode::NXDomain);
  }


  #[test]
  #[cfg(feature = "ftest")]
  fn test_nsec_query_type() {
    let name = domain::Name::with_labels(vec!["www".to_string(), "example".to_string(), "com".to_string()]);

    let addr: SocketAddr = ("8.8.8.8",53).to_socket_addrs().unwrap().next().unwrap();
    let conn = TcpClientConnection::new(addr).unwrap();
    let client = Client::new(conn);

    let response = client.secure_query(&name, DNSClass::IN, RecordType::NS);
    assert!(response.is_ok(), "query failed: {}", response.unwrap_err());

    let response = response.unwrap();
    // TODO: it would be nice to verify that the NSEC records were validated...
    assert_eq!(response.get_response_code(), ResponseCode::NoError);
    assert!(response.get_answers().is_empty());
  }

  // TODO these NSEC3 tests don't work, it seems that the zone is not signed properly.
  #[test]
  #[cfg(feature = "ftest")]
  fn test_nsec3_sdsmt() {
    let addr: SocketAddr = ("75.75.75.75",53).to_socket_addrs().unwrap().next().unwrap();
    let conn = TcpClientConnection::new(addr).unwrap();
    let name = domain::Name::with_labels(vec!["none".to_string(), "sdsmt".to_string(), "edu".to_string()]);
    let client = Client::new(conn);

    let response = client.secure_query(&name, DNSClass::IN, RecordType::NS);
    assert!(response.is_ok(), "query failed: {}", response.unwrap_err());

    let response = response.unwrap();
    assert_eq!(response.get_response_code(), ResponseCode::NXDomain);
  }

  #[test]
  #[cfg(feature = "ftest")]
  fn test_nsec3_sdsmt_type() {
    let addr: SocketAddr = ("75.75.75.75",53).to_socket_addrs().unwrap().next().unwrap();
    let conn = TcpClientConnection::new(addr).unwrap();
    let name = domain::Name::with_labels(vec!["www".to_string(), "sdsmt".to_string(), "edu".to_string()]);
    let client = Client::new(conn);

    let response = client.secure_query(&name, DNSClass::IN, RecordType::NS);
    assert!(response.is_ok(), "query failed: {}", response.unwrap_err());

    let response = response.unwrap();
    assert_eq!(response.get_response_code(), ResponseCode::NXDomain);
  }
}
