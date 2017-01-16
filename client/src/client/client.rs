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

use std::cell::RefCell;
#[cfg(feature = "openssl")]
use std::collections::HashSet;
#[cfg(feature = "openssl")]
use std::sync::Arc as Rc;
#[cfg(feature = "openssl")]
use std::convert::From;

use chrono::UTC;
#[cfg(feature = "openssl")]
use data_encoding::base32hex;
use rand;

use ::error::*;
use ::rr::{DNSClass, RecordType, Record, RData};
use ::rr::rdata::NULL;
use ::rr::domain;
use ::rr::dnssec::{KeyPair, Signer};
#[cfg(feature = "openssl")]
use ::rr::dnssec::TrustAnchor;
use ::op::{Message, MessageType, OpCode, Query, UpdateMessage};
#[cfg(feature = "openssl")]
use ::op::ResponseCode;
use ::serialize::binary::*;
use ::client::ClientConnection;

/// The Client is abstracted over either trust_dns::tcp::TcpClientConnection or
///  trust_dns::udp::UdpClientConnection.
///
/// Usage of TCP or UDP is up to the user. Some DNS servers
///  disallow TCP in some cases, so if TCP double check if UDP works.
///
/// *note* As of 0.8.0, Client as been deprecated in favor of `trust_dns::client::ClientFuture`
#[deprecated = "see trust_dns::client::ClientFuture"]
pub struct Client<C: ClientConnection> {
  client_connection: RefCell<C>,
  #[cfg(feature = "openssl")]
  trust_anchor: TrustAnchor,
}

#[allow(deprecated)]
impl<C: ClientConnection> Client<C> {
  /// Creates a new DNS client with the specified connection type
  ///
  /// # Arguments
  ///
  /// * `client_connection` - the client_connection to use for all communication
  #[allow(deprecated)]
  #[cfg(feature = "openssl")]
  pub fn new(client_connection: C) -> Client<C> {
    Self::with_trust_anchor(client_connection, TrustAnchor::default())
  }

  /// Creates a new DNS client with the specified connection type
  ///
  /// # Arguments
  ///
  /// * `client_connection` - the client_connection to use for all communication
  #[allow(deprecated)]
  #[cfg(not(feature = "openssl"))]
  pub fn new(client_connection: C) -> Client<C> {
    Client{ client_connection: RefCell::new(client_connection) }
  }


  /// This variant allows for the trust_anchor to be replaced
  ///
  /// # Arguments
  ///
  /// * `client_connection` - the client_connection to use for all communication
  /// * `trust_anchor` - the set of trusted DNSKEY public_keys, by default this only contains the
  ///                    root public_key.
  #[allow(deprecated)]
  #[cfg(feature = "openssl")]
  pub fn with_trust_anchor(client_connection: C, trust_anchor: TrustAnchor) -> Client<C> {
    Client{ client_connection: RefCell::new(client_connection),
            trust_anchor: trust_anchor }
  }

  /// DNSSec validating query, this will return an error if the requested records can not be
  ///  validated against the trust_anchor.
  ///
  /// When the resolver receives an answer via the normal DNS lookup process, it then checks to
  ///  make sure that the answer is correct. Then starts
  ///  with verifying the DS and DNSKEY records at the DNS root. Then use the DS
  ///  records for the top level domain found at the root, e.g. 'com', to verify the DNSKEY
  ///  records in the 'com' zone. From there see if there is a DS record for the
  ///  subdomain, e.g. 'example.com', in the 'com' zone, and if there is use the
  ///  DS record to verify a DNSKEY record found in the 'example.com' zone. Finally,
  ///  verify the RRSIG record found in the answer for the rrset, e.g. 'www.example.com'.
  ///
  /// *Note* As of now, this will not recurse on PTR or CNAME record responses, that is up to
  ///        the caller.
  ///
  /// # Arguments
  ///
  /// * `query_name` - the label to lookup
  /// * `query_class` - most likely this should always be DNSClass::IN
  /// * `query_type` - record type to lookup
  #[cfg(feature = "openssl")]
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
        return Err(ClientErrorKind::NoRRSIG.into());
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
        let proof = try!(self.recursive_query_verify(&name, rrset, rrsigs.clone(), rrset_type, query_class));

        // TODO return this, also make a prettier print
        debug!("proved existance through for {}:{:?}: {:?}", name, rrset_type, proof);
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

        if !validated_nx { return Err(ClientErrorKind::Message("no nsec(3) records to validate nxdomain").into()) }
      }
    }

    // getting here means that we looped through all records with validation
    Ok(record_response)
  }

  /// Verifies a record set against the supplied signatures, looking up the DNSKey chain.
  /// returns the chain of proof or an error if there is none.
  #[cfg(feature = "openssl")]
  fn recursive_query_verify(&self, name: &domain::Name, rrset: Vec<&Record>, rrsigs: Vec<&Record>,
    query_type: RecordType, query_class: DNSClass) -> ClientResult<Vec<Record>> {

    // TODO: this is ugly, what reference do I want?
    let rrset: Vec<Record> = rrset.iter().map(|rr|rr.clone()).cloned().collect();

    // verify the DNSKey via a DS key if it's the secure_entry_point
    if let Some(record) = rrset.first() {
      if let &RData::DNSKEY(ref dnskey) = record.get_rdata() {
        // the spec says that the secure_entry_point isn't reliable for the main DNSKey...
        //  but how do you know which needs to be validated with the DS in the parent zone?
        if dnskey.is_zone_key() && dnskey.is_secure_entry_point() {
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
        let key_response = self.inner_query(sig.get_signer_name(), query_class, RecordType::DNSKEY, true);
        if key_response.is_err() { debug!("error querying for: {}, {:?}, {}", sig.get_signer_name(), RecordType::DNSKEY, key_response.unwrap_err()); continue }
        let key_response = key_response.unwrap();

        let key_rrset: Vec<&Record> = key_response.get_answers().iter().filter(|rr| rr.get_rr_type() == RecordType::DNSKEY).collect();
        let key_rrsigs: Vec<&Record> = key_response.get_answers().iter().filter(|rr| rr.get_rr_type() == RecordType::RRSIG).collect();

        for dnskey in key_rrset.iter() {
          if let &RData::DNSKEY(ref rdata) = dnskey.get_rdata() {
            if rdata.is_revoke() { debug!("revoked: {}", dnskey.get_name()); continue } // TODO: does this need to be validated? RFC 5011
            if !rdata.is_zone_key() { continue }
            if *rdata.get_algorithm() != sig.get_algorithm() { continue }

            let pkey = KeyPair::from_public_bytes(rdata.get_public_key(), *rdata.get_algorithm());
            if pkey.is_err() { debug!("could not translate public_key_from_vec: {}", pkey.err().unwrap()); continue }
            let pkey = pkey.unwrap();

            let signer: Signer = Signer::new_verifier(*rdata.get_algorithm(), pkey, sig.get_signer_name().clone(), rdata.is_zone_key(), false);
            let rrset_hash = signer.hash_rrset_with_rrsig(rrsig, &rrset);
            if rrset_hash.is_err() { debug!("could not hash_rrset_with_rrsig: {}, {}", name, rrset_hash.unwrap_err()); continue }
            let rrset_hash: Vec<u8> = rrset_hash.unwrap();

            // FYI mapping the error to bool here, this code is going away after futures land
            if signer.verify(&rrset_hash, sig.get_sig()).map(|_| true).unwrap_or(false) {
              debug!("verified: {}:{:?} with: {}:{:?}", name, query_type, rrsig.get_name(),
                     if let &RData::SIG(ref sig) = rrsig.get_rdata() { sig.get_type_covered() } else { RecordType::NULL });

              if sig.get_signer_name() == name && query_type == RecordType::DNSKEY {
                // this is self signed... let's skip to DS validation
                let proof = self.verify_dnskey(dnskey);
                if proof.is_err() { debug!("could not verify dnskey: {}, {}", dnskey.get_name(), proof.unwrap_err()); continue }
                let mut proof: Vec<Record> = proof.unwrap();

                // TODO: this is verified, cache it
                proof.push((*dnskey).clone());
                return Ok(proof);
              } else {
                let proof = self.recursive_query_verify(sig.get_signer_name(), key_rrset.clone(), key_rrsigs.clone(), RecordType::DNSKEY, query_class);
                if proof.is_err() { debug!("could not recursive_query_verify: {}, {}", sig.get_signer_name(), proof.unwrap_err()); continue }
                let mut proof: Vec<Record> = proof.unwrap();

                // TODO: this is verified, cache it
                proof.push((*dnskey).clone());
                return Ok(proof);
              }
            } else {
              debug!("could not verify: {}:{:?} with: {}:{:?}", name, query_type, rrsig.get_name(),
                     if let &RData::SIG(ref sig) = rrsig.get_rdata() { sig.get_type_covered() } else { RecordType::NULL });
            }
          } else {
            panic!("this should be a DNSKEY") // valid panic, never should happen
          }
        }
      } else {
        panic!("expected RRSIG: {:?}", rrsig.get_rr_type()); // valid panic, never should happen
      }
    }

    Err(ClientErrorKind::NoDNSKEY.into())
  }

  /// attempts to verify the DNSKey against the DS of the parent.
  /// returns the chain of proof or an error if there is none.
  #[cfg(feature = "openssl")]
  fn verify_dnskey(&self, dnskey: &Record) -> ClientResult<Vec<Record>> {
    let name: &domain::Name = dnskey.get_name();

    if let &RData::DNSKEY(ref rdata) = dnskey.get_rdata() {
      if self.trust_anchor.contains(rdata.get_public_key()) {
        return Ok(vec![dnskey.clone()])
      }
    }

    let ds_response = try!(self.inner_query(&name, dnskey.get_dns_class(), RecordType::DS, true));
    let ds_rrset: Vec<&Record> = ds_response.get_answers().iter().filter(|rr| rr.get_rr_type() == RecordType::DS).collect();
    let ds_rrsigs: Vec<&Record> = ds_response.get_answers().iter().filter(|rr| rr.get_rr_type() == RecordType::RRSIG).collect();

    for ds in ds_rrset.iter() {
      if let &RData::DS(ref ds_rdata) = ds.get_rdata() {
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
          if let Err(e) = name.emit(&mut encoder) { error!("could not emit name: {}, {}", name, e); continue };
          if let Err(e) = dnskey.get_rdata().emit(&mut encoder) { error!("could not emit dnskey.rdate: {}, {}", name, e); continue };
        }

        let ds_verify = ds_rdata.get_digest_type()
                       .hash(&buf)
                       .map_err(|e| e.into())
                       .and_then(|hash|
          if &hash as &[u8] == ds_rdata.get_digest() {
            // continue to verify the chain...
            let mut proof: Vec<Record> = try!(self.recursive_query_verify(&name, ds_rrset.clone(), ds_rrsigs.clone(), RecordType::DNSKEY, dnskey.get_dns_class()));
            proof.push(dnskey.clone());
            return Ok(proof)
          } else {
            return Err(ClientErrorKind::NoDS.into())
          }
        );

        if ds_verify.is_ok() { return ds_verify }
        else { debug!("verify with DS failed: {}", name) }

      } else {
        panic!("expected DS: {:?}", ds.get_rr_type()); // valid panic, never should happen
      }
    }

    Err(ClientErrorKind::NoDS.into())
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
  #[cfg(feature = "openssl")]
  fn verify_nsec(&self, query_name: &domain::Name, query_type: RecordType,
                 _: DNSClass, nsecs: Vec<&Record>) -> ClientResult<()> {
    // first look for a record with the same name
    //  if they are, then the query_type should not exist in the NSEC record.
    //  if we got an NSEC record of the same name, but it is listed in the NSEC types,
    //    WTF? is that bad server, bad record
    if nsecs.iter().any(|r| query_name == r.get_name() && {
      if let &RData::NSEC(ref rdata) = r.get_rdata() {
        !rdata.get_type_bit_maps().contains(&query_type)
      } else {
        panic!("expected NSEC was {:?}", r.get_rr_type()) // valid panic, never should happen
      }
    }) { return Ok(()) }

    // based on the WTF? above, we will ignore any NSEC records of the same name
    if nsecs.iter().filter(|r| query_name != r.get_name()).any(|r| query_name > r.get_name() && {
      if let &RData::NSEC(ref rdata) = r.get_rdata() {
        query_name < rdata.get_next_domain_name()
      } else {
        panic!("expected NSEC was {:?}", r.get_rr_type()) // valid panic, never should happen
      }
    }) { return Ok(()) }

    // TODO: need to validate ANY or *.domain record existance, which doesn't make sense since
    //  that would have been returned in the request
    // if we got here, then there are no matching NSEC records, no validation
    Err(ClientErrorKind::Message("can not validate nsec records").into())
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
  #[cfg(feature = "openssl")]
  fn verify_nsec3(&self, query_name: &domain::Name, query_type: RecordType,
                  _: DNSClass, soa: Option<&Record>,
                  nsec3s: Vec<&Record>) -> ClientResult<()> {
    // the search name is the one to look for
    let zone_name = try!(soa.ok_or(ClientError::from(ClientErrorKind::NoSOARecord(query_name.clone())))).get_name();
    debug!("nsec3s: {:?}", nsec3s);

    for nsec3 in nsec3s {
      // for each nsec3 we search for matching hashed names
      let mut search_name: domain::Name = query_name.clone();

      // hash the search name
      if let &RData::NSEC3(ref rdata) = nsec3.get_rdata() {
        // search all the name options
        while search_name.num_labels() >= zone_name.num_labels() {

          // TODO: cache hashes across nsec3 validations
          let hash = try!(rdata.get_hash_algorithm().hash(rdata.get_salt(), &search_name, rdata.get_iterations()));
          let hash_label = base32hex::encode(&hash).to_lowercase();
          let hash_name = zone_name.prepend_label(Rc::new(hash_label));

          if &hash_name == nsec3.get_name() {
            // like nsec, if there is a name that matches, then we have proof that the name does
            //  not exist
            if &search_name == query_name {
              if !rdata.get_type_bit_maps().contains(&query_type) { return Ok(()) }
            }

            return Ok(())
          }

          // need to continue up the chain
          search_name = search_name.base_name();
        }
      }
    }

    Err(ClientErrorKind::Message("can not validate nsec3 records").into())
  }

  /// A *classic* DNS query, i.e. does not perform and DNSSec operations
  ///
  /// *Note* As of now, this will not recurse on PTR or CNAME record responses, that is up to
  ///        the caller.
  ///
  /// # Arguments
  ///
  /// * `name` - the label to lookup
  /// * `query_class` - most likely this should always be DNSClass::IN
  /// * `query_type` - record type to lookup
  pub fn query(&self, name: &domain::Name, query_class: DNSClass, query_type: RecordType) -> ClientResult<Message> {
    self.inner_query(name, query_class, query_type, false)
  }

  fn inner_query(&self, name: &domain::Name, query_class: DNSClass, query_type: RecordType, secure: bool) -> ClientResult<Message> {
    debug!("querying: {} {:?}", name, query_type);

    // build the message
    let mut message: Message = Message::new();
    let id: u16 = rand::random();
    // TODO make recursion a parameter
    message.id(id).message_type(MessageType::Query).op_code(OpCode::Query).recursion_desired(true);

    // Extended dns
    {
      let edns = message.get_edns_mut();

      if secure {
        edns.set_dnssec_ok(true);
      }

      edns.set_max_payload(1500);
      edns.set_version(0);
    }

    if secure {
      message.authentic_data(true);
      message.checking_disabled(false);
    }

    // add the query
    let mut query: Query = Query::new();
    query.name(name.clone()).query_class(query_class).query_type(query_type);
    message.add_query(query);

    self.send_message(&message)
  }

  /// Sends a record to create on the server, this will fail if the record exists (atomicity
  ///  depends on the server)
  ///
  /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
  ///
  /// ```text
  ///  2.4.3 - RRset Does Not Exist
  ///
  ///   No RRs with a specified NAME and TYPE (in the zone and class denoted
  ///   by the Zone Section) can exist.
  ///
  ///   For this prerequisite, a requestor adds to the section a single RR
  ///   whose NAME and TYPE are equal to that of the RRset whose nonexistence
  ///   is required.  The RDLENGTH of this record is zero (0), and RDATA
  ///   field is therefore empty.  CLASS must be specified as NONE in order
  ///   to distinguish this condition from a valid RR whose RDLENGTH is
  ///   naturally zero (0) (for example, the NULL RR).  TTL must be specified
  ///   as zero (0).
  ///
  /// 2.5.1 - Add To An RRset
  ///
  ///    RRs are added to the Update Section whose NAME, TYPE, TTL, RDLENGTH
  ///    and RDATA are those being added, and CLASS is the same as the zone
  ///    class.  Any duplicate RRs will be silently ignored by the primary
  ///    master.
  /// ```
  ///
  /// # Arguments
  ///
  /// * `record` - the name of the record to create
  /// * `zone_origin` - the zone name to update, i.e. SOA name
  /// * `signer` - the signer, with private key, to use to sign the request
  ///
  /// The update must go to a zone authority (i.e. the server used in the ClientConnection)
  pub fn create(&self,
                record: Record,
                zone_origin: domain::Name,
                signer: &Signer) -> ClientResult<Message> {
    assert!(zone_origin.zone_of(record.get_name()));

    // for updates, the query section is used for the zone
    let mut zone: Query = Query::new();
    zone.name(zone_origin).query_class(record.get_dns_class()).query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message.id(rand::random()).message_type(MessageType::Query).op_code(OpCode::Update).recursion_desired(false);
    message.add_zone(zone);

    let mut prerequisite = Record::with(record.get_name().clone(), record.get_rr_type(), 0);
    prerequisite.dns_class(DNSClass::NONE);
    message.add_pre_requisite(prerequisite);
    message.add_update(record);

    // Extended dns
    {
      let edns = message.get_edns_mut();

      edns.set_max_payload(1500);
      edns.set_version(0);
    }

    // after all other updates to the message, sign it.
    try!(message.sign(signer, UTC::now().timestamp() as u32));

    self.send_message(&message)
  }

  /// Appends a record to an existing rrset, optionally require the rrset to exis (atomicity
  ///  depends on the server)
  ///
  /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
  ///
  /// ```text
  /// 2.4.1 - RRset Exists (Value Independent)
  ///
  ///   At least one RR with a specified NAME and TYPE (in the zone and class
  ///   specified in the Zone Section) must exist.
  ///
  ///   For this prerequisite, a requestor adds to the section a single RR
  ///   whose NAME and TYPE are equal to that of the zone RRset whose
  ///   existence is required.  RDLENGTH is zero and RDATA is therefore
  ///   empty.  CLASS must be specified as ANY to differentiate this
  ///   condition from that of an actual RR whose RDLENGTH is naturally zero
  ///   (0) (e.g., NULL).  TTL is specified as zero (0).
  ///
  /// 2.5.1 - Add To An RRset
  ///
  ///    RRs are added to the Update Section whose NAME, TYPE, TTL, RDLENGTH
  ///    and RDATA are those being added, and CLASS is the same as the zone
  ///    class.  Any duplicate RRs will be silently ignored by the primary
  ///    master.
  /// ```
  ///
  /// # Arguments
  ///
  /// * `record` - the record to append to an RRSet
  /// * `zone_origin` - the zone name to update, i.e. SOA name
  /// * `must_exist` - if true, the request will fail if the record does not exist
  /// * `signer` - the signer, with private key, to use to sign the request
  ///
  /// The update must go to a zone authority (i.e. the server used in the ClientConnection). If
  /// the rrset does not exist and must_exist is false, then the RRSet will be created.
  pub fn append(&self,
                record: Record,
                zone_origin: domain::Name,
                must_exist: bool,
                signer: &Signer) -> ClientResult<Message> {
    assert!(zone_origin.zone_of(record.get_name()));

    // for updates, the query section is used for the zone
    let mut zone: Query = Query::new();
    zone.name(zone_origin).query_class(record.get_dns_class()).query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message.id(rand::random()).message_type(MessageType::Query).op_code(OpCode::Update).recursion_desired(false);
    message.add_zone(zone);

    if must_exist {
      let mut prerequisite = Record::with(record.get_name().clone(), record.get_rr_type(), 0);
      prerequisite.dns_class(DNSClass::ANY);
      message.add_pre_requisite(prerequisite);
    }

    message.add_update(record);

    // Extended dns
    {
      let edns = message.get_edns_mut();

      edns.set_max_payload(1500);
      edns.set_version(0);
    }

    // after all other updates to the message, sign it.
    try!(message.sign(signer, UTC::now().timestamp() as u32));

    self.send_message(&message)
  }

  /// Compares and if it matches, swaps it for the new value (atomicity depends on the server)
  ///
  /// ```text
  ///  2.4.2 - RRset Exists (Value Dependent)
  ///
  ///   A set of RRs with a specified NAME and TYPE exists and has the same
  ///   members with the same RDATAs as the RRset specified here in this
  ///   section.  While RRset ordering is undefined and therefore not
  ///   significant to this comparison, the sets be identical in their
  ///   extent.
  ///
  ///   For this prerequisite, a requestor adds to the section an entire
  ///   RRset whose preexistence is required.  NAME and TYPE are that of the
  ///   RRset being denoted.  CLASS is that of the zone.  TTL must be
  ///   specified as zero (0) and is ignored when comparing RRsets for
  ///   identity.
  ///
  ///  2.5.4 - Delete An RR From An RRset
  ///
  ///   RRs to be deleted are added to the Update Section.  The NAME, TYPE,
  ///   RDLENGTH and RDATA must match the RR being deleted.  TTL must be
  ///   specified as zero (0) and will otherwise be ignored by the primary
  ///   master.  CLASS must be specified as NONE to distinguish this from an
  ///   RR addition.  If no such RRs exist, then this Update RR will be
  ///   silently ignored by the primary master.
  ///
  ///  2.5.1 - Add To An RRset
  ///
  ///   RRs are added to the Update Section whose NAME, TYPE, TTL, RDLENGTH
  ///   and RDATA are those being added, and CLASS is the same as the zone
  ///   class.  Any duplicate RRs will be silently ignored by the primary
  ///   master.
  /// ```
  ///
  /// # Arguements
  ///
  /// * `current` - the current current which must exist for the swap to complete
  /// * `new` - the new record with which to replace the current record
  /// * `zone_origin` - the zone name to update, i.e. SOA name
  /// * `signer` - the signer, with private key, to use to sign the request
  ///
  /// The update must go to a zone authority (i.e. the server used in the ClientConnection).
  pub fn compare_and_swap(&self,
                          current: Record,
                          new: Record,
                          zone_origin: domain::Name,
                          signer: &Signer) -> ClientResult<Message> {
    assert!(zone_origin.zone_of(current.get_name()));
    assert!(zone_origin.zone_of(new.get_name()));

    // for updates, the query section is used for the zone
    let mut zone: Query = Query::new();
    zone.name(zone_origin).query_class(new.get_dns_class()).query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message.id(rand::random()).message_type(MessageType::Query).op_code(OpCode::Update).recursion_desired(false);
    message.add_zone(zone);

    // make sure the record is what is expected
    let mut prerequisite = current.clone();
    prerequisite.ttl(0);
    message.add_pre_requisite(prerequisite);

    // add the delete for the old record
    let mut delete = current;
    // the class must be none for delete
    delete.dns_class(DNSClass::NONE);
    // the TTL shoudl be 0
    delete.ttl(0);
    message.add_update(delete);

    // insert the new record...
    message.add_update(new);

    // Extended dns
    {
      let edns = message.get_edns_mut();

      edns.set_max_payload(1500);
      edns.set_version(0);
    }

    // after all other updates to the message, sign it.
    try!(message.sign(signer, UTC::now().timestamp() as u32));

    self.send_message(&message)
  }

  /// Deletes a record (by rdata) from an rrset, optionally require the rrset to exist.
  ///
  /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
  ///
  /// ```text
  /// 2.4.1 - RRset Exists (Value Independent)
  ///
  ///   At least one RR with a specified NAME and TYPE (in the zone and class
  ///   specified in the Zone Section) must exist.
  ///
  ///   For this prerequisite, a requestor adds to the section a single RR
  ///   whose NAME and TYPE are equal to that of the zone RRset whose
  ///   existence is required.  RDLENGTH is zero and RDATA is therefore
  ///   empty.  CLASS must be specified as ANY to differentiate this
  ///   condition from that of an actual RR whose RDLENGTH is naturally zero
  ///   (0) (e.g., NULL).  TTL is specified as zero (0).
  ///
  /// 2.5.4 - Delete An RR From An RRset
  ///
  ///   RRs to be deleted are added to the Update Section.  The NAME, TYPE,
  ///   RDLENGTH and RDATA must match the RR being deleted.  TTL must be
  ///   specified as zero (0) and will otherwise be ignored by the primary
  ///   master.  CLASS must be specified as NONE to distinguish this from an
  ///   RR addition.  If no such RRs exist, then this Update RR will be
  ///   silently ignored by the primary master.
  /// ```
  ///
  /// # Arguments
  ///
  /// * `record` - the record to delete from a RRSet, the name, type and rdata must match the
  ///              record to delete
  /// * `zone_origin` - the zone name to update, i.e. SOA name
  /// * `signer` - the signer, with private key, to use to sign the request
  ///
  /// The update must go to a zone authority (i.e. the server used in the ClientConnection). If
  /// the rrset does not exist and must_exist is false, then the RRSet will be deleted.
  pub fn delete_by_rdata(&self,
                         mut record: Record,
                         zone_origin: domain::Name,
                         signer: &Signer) -> ClientResult<Message> {
    assert!(zone_origin.zone_of(record.get_name()));

    // for updates, the query section is used for the zone
    let mut zone: Query = Query::new();
    zone.name(zone_origin).query_class(record.get_dns_class()).query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message.id(rand::random()).message_type(MessageType::Query).op_code(OpCode::Update).recursion_desired(false);
    message.add_zone(zone);

    // the class must be none for delete
    record.dns_class(DNSClass::NONE);
    // the TTL shoudl be 0
    record.ttl(0);
    message.add_update(record);

    // Extended dns
    {
      let edns = message.get_edns_mut();
      edns.set_max_payload(1500);
      edns.set_version(0);
    }

    // after all other updates to the message, sign it.
    try!(message.sign(signer, UTC::now().timestamp() as u32));

    self.send_message(&message)
  }

  /// Deletes an entire rrset, optionally require the rrset to exist.
  ///
  /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
  ///
  /// ```text
  /// 2.4.1 - RRset Exists (Value Independent)
  ///
  ///   At least one RR with a specified NAME and TYPE (in the zone and class
  ///   specified in the Zone Section) must exist.
  ///
  ///   For this prerequisite, a requestor adds to the section a single RR
  ///   whose NAME and TYPE are equal to that of the zone RRset whose
  ///   existence is required.  RDLENGTH is zero and RDATA is therefore
  ///   empty.  CLASS must be specified as ANY to differentiate this
  ///   condition from that of an actual RR whose RDLENGTH is naturally zero
  ///   (0) (e.g., NULL).  TTL is specified as zero (0).
  ///
  /// 2.5.2 - Delete An RRset
  ///
  ///   One RR is added to the Update Section whose NAME and TYPE are those
  ///   of the RRset to be deleted.  TTL must be specified as zero (0) and is
  ///   otherwise not used by the primary master.  CLASS must be specified as
  ///   ANY.  RDLENGTH must be zero (0) and RDATA must therefore be empty.
  ///   If no such RRset exists, then this Update RR will be silently ignored
  ///   by the primary master.
  /// ```
  ///
  /// # Arguments
  ///
  /// * `record` - the record to delete from a RRSet, the name, and type must match the
  ///              record set to delete
  /// * `zone_origin` - the zone name to update, i.e. SOA name
  /// * `signer` - the signer, with private key, to use to sign the request
  ///
  /// The update must go to a zone authority (i.e. the server used in the ClientConnection). If
  /// the rrset does not exist and must_exist is false, then the RRSet will be deleted.
  pub fn delete_rrset(&self,
                      mut record: Record,
                      zone_origin: domain::Name,
                      signer: &Signer) -> ClientResult<Message> {
    assert!(zone_origin.zone_of(record.get_name()));

    // for updates, the query section is used for the zone
    let mut zone: Query = Query::new();
    zone.name(zone_origin).query_class(record.get_dns_class()).query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message.id(rand::random()).message_type(MessageType::Query).op_code(OpCode::Update).recursion_desired(false);
    message.add_zone(zone);

    // the class must be none for an rrset delete
    record.dns_class(DNSClass::ANY);
    // the TTL shoudl be 0
    record.ttl(0);
    // the rdata must be null to delete all rrsets
    record.rdata(RData::NULL(NULL::new()));
    message.add_update(record);

    // Extended dns
    {
      let edns = message.get_edns_mut();
      edns.set_max_payload(1500);
      edns.set_version(0);
    }

    // after all other updates to the message, sign it.
    try!(message.sign(signer, UTC::now().timestamp() as u32));

    self.send_message(&message)
  }

  /// Deletes all records at the specified name
  ///
  /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
  ///
  /// ```text
  /// 2.5.3 - Delete All RRsets From A Name
  ///
  ///   One RR is added to the Update Section whose NAME is that of the name
  ///   to be cleansed of RRsets.  TYPE must be specified as ANY.  TTL must
  ///   be specified as zero (0) and is otherwise not used by the primary
  ///   master.  CLASS must be specified as ANY.  RDLENGTH must be zero (0)
  ///   and RDATA must therefore be empty.  If no such RRsets exist, then
  ///   this Update RR will be silently ignored by the primary master.
  /// ```
  ///
  /// # Arguments
  ///
  /// * `name_of_records` - the name of all the record sets to delete
  /// * `zone_origin` - the zone name to update, i.e. SOA name
  /// * `dns_class` - the class of the SOA
  /// * `signer` - the signer, with private key, to use to sign the request
  ///
  /// The update must go to a zone authority (i.e. the server used in the ClientConnection). This
  /// operation attempts to delete all resource record sets the the specified name reguardless of
  /// the record type.
  pub fn delete_all(&self,
                    name_of_records: domain::Name,
                    zone_origin: domain::Name,
                    dns_class: DNSClass,
                    signer: &Signer) -> ClientResult<Message> {
    assert!(zone_origin.zone_of(&name_of_records));

    // for updates, the query section is used for the zone
    let mut zone: Query = Query::new();
    zone.name(zone_origin).query_class(dns_class).query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message.id(rand::random()).message_type(MessageType::Query).op_code(OpCode::Update).recursion_desired(false);
    message.add_zone(zone);

    // the TTL shoudl be 0
    // the rdata must be null to delete all rrsets
    // the record type must be any
    let mut record = Record::with(name_of_records, RecordType::ANY, 0);

    // the class must be none for an rrset delete
    record.dns_class(DNSClass::ANY);

    message.add_update(record);

    // Extended dns
    {
      let edns = message.get_edns_mut();
      edns.set_max_payload(1500);
      edns.set_version(0);
    }

    // after all other updates to the message, sign it.
    try!(message.sign(signer, UTC::now().timestamp() as u32));

    self.send_message(&message)
  }

  /// Sends a message to the server for which this client was defined
  ///
  /// # Arguments
  ///
  /// * `message` - the message to deliver
  fn send_message(&self, message: &Message) -> ClientResult<Message> {
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

    if response.get_id() != message.get_id() { return Err(ClientErrorKind::IncorrectMessageId(response.get_id(), message.get_id()).into()); }

    Ok(response)
  }
}
