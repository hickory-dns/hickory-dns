//! Throughout this module several NSEC3 specific terms are used.
//!
//! "closest_encloser" - a name that is a longest parent / grandparent /
//!     great-grandparent, etc. of a `query_name`, that DOES exist.
//!
//! "next_closer" - a name that is one level deeper in the hierarchy from
//!     `closest_encloser`, that DOES NOT exist in the zone.
//!
//! "wildcard of closest encloser" - a name in a form of `*.closest_encloser`.
//!     If it exists then `query_name` would be serviced by the wildcard.
//!
//! "covering NSEC3 record" - NSEC3 record name has a hash (`hashed_owner_name`),
//!     and inside the record data there's `next_hashed_owner_name`.
//!     If the hash of `query_name` fits between the two hashes then the record
//!     "covers" `query_name`
//!
//! "matching NSEC3 record" - exists for *existing* names only.
//!     The `hashed_owner_name` would match one of the names *exactly*.
//!
//! In general:
//! * if a name exists we would expect to see its "matching" NSEC3 record,
//! * if the name doesn't exist we would expect to see a "covering" NSEC3 record.
//!
//! A various combinations of matching and covering records for `closest_encloser`,
//! `next_closer`, and `wildcard_encloser` can tell us whether `query_name`
//! exists, whether `wildcard_encloser` exists, and whether its own or
//! `wildcard_encloser`'s records have a record of a requested type.
//!
//! NOTE: A single NSEC3 record can in theory address multiple situations.
//! Thus, the number of records is not important as long as all
//! conditions are represented by them.
//!
//! NOTE: Normally, when there exist a wildcard that a given name fits into,
//! it is said that the wildcard "covers" the name. But since the wording
//! around NSEC3 records uses "cover" in a specific sense we use the word
//! "service" instead:
//! `*.w.soa.name` *services* `x.w.soa.name`
//!
//! In general, avoid using the word "cover" for anything not related to
//! "covering NSEC3 record"
//!
//! ## Examples
//!
//! To explain them let's use the following example zone:
//!
//! soa.name
//! *.w.soa.name
//! c.e.soa.name
//!
//! if we request:
//!     `query_name` = `x.y.z.nc.c.e.soa.name`
//! then:
//!     `closest_encloser` == `c.e.soa.name` (the first existing ancestor)
//!     `next_closer`      == `nc.c.e.soa.name` (doesn't exist in the zone)
//!     `wildcard_encloser` == `*.c.e.soa.name`
//!
//! if we request:
//!     `query_name` = `x.y.z.nc.w.soa.name`
//! then:
//!     `closest_encloser` == `w.soa.name`
//!     `next_closer`      == `nc.w.soa.name`
//!     `wildcard_encloser` == `*.w.soa.name`
//!
//! if we request:
//!     `query_name` = `x.soa.name`
//! then:
//!     `closest_encloser` == `soa.name`
//!     `next_closer`      == `x.soa.name`
//!     `wildcard_encloser` == `*.soa.name`
//!
//! if we request:
//!     `query_name` = `e.soa.name`
//! then:
//!     `closest_encloser` == `e.soa.name`
//!     `next_closer`      == doesn't exist
//!     `wildcard_encloser` == `*.soa.name`
//!

/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 * Copyright (C) 2017 Google LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use alloc::vec::Vec;
use core::fmt::Display;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{DigestType, Proof, crypto::Digest, handle::proof_log_yield, rdata::NSEC3};
use crate::{
    error::ProtoResult,
    op::{Query, ResponseCode},
    rr::{Name, Record, RecordType, domain::Label},
    serialize::binary::{BinEncodable, BinEncoder, DecodeError, NameEncoding},
};

pub(super) fn verify_nsec3(
    query: &Query,
    soa: Option<&Name>,
    response_code: ResponseCode,
    answers: &[Record],
    nsec3s: &[(&Name, &NSEC3)],
    nsec3_soft_iteration_limit: u16,
    nsec3_hard_iteration_limit: u16,
) -> Proof {
    debug_assert!(!nsec3s.is_empty()); // checked in the caller

    // For every NSEC3 record that in text form looks like:
    // <base32-hash>.soa.name NSEC3 <data>
    // we extract (<base32-hash>, <data>) pair from deeply nested structures
    let mut pairs = Vec::with_capacity(nsec3s.len());
    for (name, data) in nsec3s {
        let Some((base32_hashed_name, base)) = split_first_label(name) else {
            return nsec3_yield(Proof::Bogus, query, "record name format is invalid");
        };

        // If the SOA record is present, the base name of any NSEC3 records must match it.
        if soa.is_some_and(|soa| &base != soa) {
            return nsec3_yield(Proof::Bogus, query, "record name is not in the zone");
        }

        let Ok(base32_hashed_name) = Label::from_raw_bytes(base32_hashed_name) else {
            return nsec3_yield(Proof::Bogus, query, "base32-hashed name is invalid");
        };

        pairs.push(Nsec3RecordPair {
            base32_hashed_name,
            nsec3_data: data,
        });
    }

    debug_assert!(!pairs.is_empty()); // `nsec3s` was not empty, and we returned on any invalid values

    // RFC 5155 8.2 - all NSEC3 records share the same NSEC3 params
    let first = &pairs[0];
    let hash_algorithm = first.nsec3_data.hash_algorithm();
    let salt = first.nsec3_data.salt();
    let iterations = first.nsec3_data.iterations();
    if pairs.iter().any(|r| {
        r.nsec3_data.hash_algorithm() != hash_algorithm
            || r.nsec3_data.salt() != salt
            || r.nsec3_data.iterations() != iterations
    }) {
        return nsec3_yield(Proof::Bogus, query, "parameter mismatch");
    }

    // Protect against high iteration counts by returning Proof::Bogus (triggering a SERVFAIL
    // response) if iterations > than the hard limit, or an insecure response if iterations > the
    // soft limit.
    //
    // [RFC 9276 3.2](https://www.rfc-editor.org/rfc/rfc9276.html#name-recommendation-for-validati).
    if iterations > nsec3_hard_iteration_limit {
        return nsec3_yield(
            Proof::Bogus,
            query,
            format_args!("iteration count {iterations} is over {nsec3_hard_iteration_limit}"),
        );
    } else if iterations > nsec3_soft_iteration_limit {
        return nsec3_yield(
            Proof::Insecure,
            query,
            format_args!("iteration count {iterations} is over {nsec3_soft_iteration_limit}"),
        );
    }

    // Basic sanity checks are done.
    let cx = Context {
        query,
        soa,
        nsec3s: &pairs,
        hash_algorithm,
        salt,
        iterations,
    };

    // From here on 4 big situations are possible:
    // 1. No such name, and no servicing wildcard
    // 2. Name exists but there's no record of this type
    // 3. Name is serviced by wildcard that has a record of this type
    // 4. Name is serviced by wildcard that doesn't have a record of this type

    match response_code {
        // Case 1:
        ResponseCode::NXDomain => validate_nxdomain_response(&cx),

        // RFC 5155: NoData
        // Cases 2, 3, and 4:
        ResponseCode::NoError => {
            // Let's see if we received any answers.
            // This would signal that we have a wildcard servicing our `query_name`.
            // `num_labels` will show how many labels are there
            // in the wildcard that services the `query_name`
            let wildcard_num_labels = answers.iter().find_map(|record| {
                record
                    .data()
                    .as_dnssec()?
                    .as_rrsig()
                    .map(|data| data.input.num_labels)
            });
            validate_nodata_response(query.query_type(), wildcard_num_labels, &cx)
        }
        _ => cx.proof(
            Proof::Bogus,
            format_args!("unsupported response code ({response_code})"),
        ),
    }
}

/// There is no such `query_name` in the zone and there's no wildcard that
/// can be expanded to service this `query_name`.
///
/// Expecting the following records:
/// * closest encloser - *matching* NSEC3 record
/// * next closer - *covering* NSEC3 record
/// * wildcard of closest encloser - *covering* NSEC3 record
fn validate_nxdomain_response(cx: &Context<'_>) -> Proof {
    // The response is NXDomain but there's a record for query_name
    let (_, base32_hashed_query_name) = cx.hash_and_label(cx.query.name());
    if cx
        .nsec3s
        .iter()
        .any(|r| r.base32_hashed_name == base32_hashed_query_name)
    {
        return cx.proof(Proof::Bogus, "NXDomain response with record for query name");
    }

    // Note that the three fields may hold references to the same NSEC3
    // record, because the interval of base32_hashed_name
    // and next_hashed_owner_name happen to match / cover all three components
    // of closest encloser proof.
    let (
        ClosestEncloserProofInfo {
            closest_encloser,
            next_closer,
        },
        closest_encloser_wildcard,
    ) = cx.closest_encloser_proof_with_wildcard(false);

    if closest_encloser.is_none() && next_closer.is_none() {
        return cx.proof(Proof::Bogus, "returning early proof");
    }

    match (closest_encloser, next_closer, closest_encloser_wildcard) {
        // Got all three components - we proved that there's no `query_name`
        // in the zone
        (Some(_), Some(_), Some(_)) => cx.proof(Proof::Secure, "direct proof"),
        // `query_name`'s parent is the `soa_name` itself, so there's no need
        // to send `soa_name`'s NSEC3 record. Still we have to show that
        // both `query_name` doesn't exist and there's no wildcard to service it
        (None, Some(_), Some(_)) if Some(&cx.query.name().base_name()) == cx.soa => cx.proof(
            Proof::Secure,
            "no direct or wildcard proof, but parent name of query is SOA",
        ),
        _ => cx.proof(Proof::Bogus, "no proof of non-existence"),
    }
}

/// This function addresses three situations:
///
/// Case 2. Name exists but there's no record of this type
/// Case 3. Opt-out proof for Name exists
/// Case 4. Name is serviced by wildcard that has a record of this type
/// Case 5. Name is serviced by wildcard that doesn't have a record of this type
fn validate_nodata_response(
    query_type: RecordType,
    wildcard_encloser_num_labels: Option<u8>,
    cx: &Context<'_>,
) -> Proof {
    // 2. Name exists but there's no record of this type
    // 3. Opt-out proof for Name exists
    // 4. Name is serviced by wildcard that has a record of this type
    // 5. Name is serviced by wildcard that doesn't have a record of this type

    let (hashed_query_name, base32_hashed_query_name) = cx.hash_and_label(cx.query.name());
    let query_name_record = cx
        .nsec3s
        .iter()
        .find(|record| record.base32_hashed_name == base32_hashed_query_name);

    // Case 2:
    // Name exists but there's no record of this type
    //
    // RFC 5155 § 8.5 et seq.
    //
    //   8.5.  Validating No Data Responses, QTYPE is not DS
    //
    //   The validator MUST verify that an NSEC3 RR that matches QNAME is
    //   present and that both the QTYPE and the CNAME type are not set in its
    //   Type Bit Maps field.
    //
    //   Note that this test also covers the case where the NSEC3 RR exists
    //   because it corresponds to an empty non-terminal, in which case the
    //   NSEC3 RR will have an empty Type Bit Maps field.
    //
    //   8.6.  Validating No Data Responses, QTYPE is DS
    //
    //   If there is an NSEC3 RR that matches QNAME present in the response,
    //   then that NSEC3 RR MUST NOT have the bits corresponding to DS and
    //   CNAME set in its Type Bit Maps field.
    //
    //   If there is no such NSEC3 RR, then the validator MUST verify that a
    //   closest provable encloser proof for QNAME is present in the response,
    //   and that the NSEC3 RR that covers the "next closer" name has the Opt-
    //   Out bit set.
    if let Some(query_record) = query_name_record {
        if query_record.nsec3_data.type_set().contains(query_type)
            || query_record
                .nsec3_data
                .type_set()
                .contains(RecordType::CNAME)
        {
            return cx.proof(
                Proof::Bogus,
                format_args!("nsec3 type map covers {query_type} or CNAME"),
            );
        } else {
            return cx.proof(
                Proof::Secure,
                format_args!("type map does not cover {query_type} or CNAME"),
            );
        }
    }

    // Case 3:
    // Query type is DS, records for name exist, but there are no DS records (opt-out proof)
    //
    // RFC 5155 § 6
    //
    //   In this specification, as in [RFC4033], [RFC4034] and [RFC4035], NS
    //   RRSets at delegation points are not signed and may be accompanied by
    //   a DS RRSet.  With the Opt-Out bit clear, the security status of the
    //   child zone is determined by the presence or absence of this DS RRSet,
    //   cryptographically proven by the signed NSEC3 RR at the hashed owner
    //   name of the delegation.  Setting the Opt-Out flag modifies this by
    //   allowing insecure delegations to exist within the signed zone without
    //   a corresponding NSEC3 RR at the hashed owner name of the delegation.
    //
    //   An Opt-Out NSEC3 RR is said to cover a delegation if the hash of the
    //   owner name or "next closer" name of the delegation is between the
    //   owner name of the NSEC3 RR and the next hashed owner name.
    //
    //   An Opt-Out NSEC3 RR does not assert the existence or non-existence of
    //   the insecure delegations that it may cover.  This allows for the
    //   addition or removal of these delegations without recalculating or re-
    //   signing RRs in the NSEC3 RR chain.  However, Opt-Out NSEC3 RRs do
    //   assert the (non)existence of other, authoritative RRSets.
    //
    //   An Opt-Out NSEC3 RR MAY have the same original owner name as an
    //   insecure delegation.  In this case, the delegation is proven insecure
    //   by the lack of a DS bit in the type map and the signed NSEC3 RR does
    //   assert the existence of the delegation.
    //
    //   Zones using Opt-Out MAY contain a mixture of Opt-Out NSEC3 RRs and
    //   non-Opt-Out NSEC3 RRs.  If an NSEC3 RR is not Opt-Out, there MUST NOT
    //   be any hashed owner names of insecure delegations (nor any other RRs)
    //   between it and the name indicated by the next hashed owner name in
    //   the NSEC3 RDATA.  If it is Opt-Out, it MUST only cover hashed owner
    //   names or hashed "next closer" names of insecure delegations.
    //
    //   The effects of the Opt-Out flag on signing, serving, and validating
    //   responses are covered in following sections.
    //
    // *Note*: the case of an opt-out NSEC3 record having the same original owner
    // name as the hashed query name and not having the DS bit set in the type flags
    // is covered here by case 2.
    if query_type == RecordType::DS
        && find_covering_record(cx.nsec3s, &hashed_query_name, &base32_hashed_query_name)
            .is_some_and(|x| x.nsec3_data.opt_out())
    {
        return cx.proof(Proof::Secure, "DS query covered by opt-out proof");
    }

    let (proof, reason) = match wildcard_encloser_num_labels {
        // Case 4:
        // Name is serviced by wildcard that has a record of this type
        Some(wildcard_encloser_num_labels) => {
            if cx.query.name().num_labels() <= wildcard_encloser_num_labels {
                return cx.proof(
                    Proof::Bogus,
                    format_args!(
                        "query labels ({}) <= wildcard encloser labels ({})",
                        cx.query.name().num_labels(),
                        wildcard_encloser_num_labels,
                    ),
                );
            }
            // There should be an NSEC3 record *covering* `next_closer`
            let next_closer_labels = cx
                .query
                .name()
                .into_iter()
                .rev()
                .take(wildcard_encloser_num_labels as usize + 1)
                .rev()
                .collect::<Vec<_>>();
            let next_closer_name = Name::from_labels(next_closer_labels)
                .expect("next closer is `query_name` or its ancestor");
            let next_closer_name_info = HashedNameInfo::new(next_closer_name, cx);
            let next_closer_record = find_covering_record(
                cx.nsec3s,
                &next_closer_name_info.hashed_name,
                &next_closer_name_info.base32_hashed_name,
            );
            match next_closer_record {
                Some(_) => (Proof::Secure, "covering next closer record"),
                None => (Proof::Bogus, "no covering next closer record"),
            }
        }

        // Case 5:
        // Name is serviced by wildcard that doesn't have a record of this type
        // Verify the wildcard type set does not match the query type (or CNAME) - RFC 5155 8.7.
        None => {
            let (
                ClosestEncloserProofInfo {
                    closest_encloser,
                    next_closer,
                },
                closest_encloser_wildcard,
            ) = cx.closest_encloser_proof_with_wildcard(true);
            match (closest_encloser, next_closer, closest_encloser_wildcard) {
                (Some(_), Some(_), Some((_, wildcard)))
                    if !wildcard.nsec3_data.type_set().contains(query_type)
                        && !wildcard.nsec3_data.type_set().contains(RecordType::CNAME) =>
                {
                    (
                        Proof::Secure,
                        "servicing wildcard with closest encloser proof",
                    )
                }
                (None, Some(_), Some(_)) if Some(&cx.query.name().base_name()) == cx.soa => (
                    Proof::Secure,
                    "servicing wildcard without closest encloser proof, but query parent name == SOA",
                ),
                (None, None, None) if Some(cx.query.name()) == cx.soa => (
                    Proof::Secure,
                    "no servicing wildcard, but query name == SOA",
                ),
                _ => (Proof::Bogus, "no valid servicing wildcard proof"),
            }
        }
    };

    cx.proof(proof, reason)
}

fn split_first_label(name: &Name) -> Option<(&[u8], Name)> {
    let first_label = name.iter().next()?;
    let base = name.base_name();
    Some((first_label, base))
}

#[derive(Default)]
struct ClosestEncloserProofInfo<'a> {
    closest_encloser: Option<(HashedNameInfo, &'a Nsec3RecordPair<'a>)>,
    next_closer: Option<(HashedNameInfo, &'a Nsec3RecordPair<'a>)>,
}

struct Context<'a> {
    query: &'a Query,
    soa: Option<&'a Name>,
    nsec3s: &'a [Nsec3RecordPair<'a>],
    hash_algorithm: Nsec3HashAlgorithm,
    salt: &'a [u8],
    iterations: u16,
}

impl<'a> Context<'a> {
    /// Return a closest encloser proof and a proof of non-existence for the wildcard at the closest encloser.
    ///
    /// For example, if the closest encloser is `w.example.`, the wildcard at the closest encloser is `*.w.example`.
    ///
    /// If matching is set to true, look for an NSEC3 that matches the wildcard name (used in wildcard no data responses.)
    /// If matching is set to false, look for an NSEC3 that covers the wildcard name (used in name error responses.)
    fn closest_encloser_proof_with_wildcard(
        &'a self,
        matching: bool,
    ) -> (
        ClosestEncloserProofInfo<'a>,
        Option<(HashedNameInfo, &'a Nsec3RecordPair<'a>)>,
    ) {
        let closest_encloser_proof = self.closest_encloser_proof();

        let closest_encloser_name = match closest_encloser_proof.closest_encloser.as_ref() {
            Some((name_info, _)) => name_info.name.clone(),
            None => return (closest_encloser_proof, None),
        };

        let Ok(wildcard_encloser_name) = closest_encloser_name.prepend_label("*") else {
            return (closest_encloser_proof, None);
        };

        let wildcard_name_info = HashedNameInfo::new(wildcard_encloser_name, self);
        let wildcard_record = if matching {
            self.nsec3s
                .iter()
                .find(|record| record.base32_hashed_name == wildcard_name_info.base32_hashed_name)
        } else {
            find_covering_record(
                self.nsec3s,
                &wildcard_name_info.hashed_name,
                &wildcard_name_info.base32_hashed_name,
            )
        };

        (
            closest_encloser_proof,
            wildcard_record.map(|record| (wildcard_name_info, record)),
        )
    }

    /// Find the NSEC3 record(s) constituting the closest encloser proof (RFC 5155 7.2.1) consisting of:
    ///
    /// * closest encloser - *matching* NSEC3 record
    /// * next closer - *covering* NSEC3 record
    ///
    /// Example: for `a.z.w.example.`, the closest encloser might be `w.example.` in which case the next closer name
    /// would be `z.w.example.`
    fn closest_encloser_proof(&'a self) -> ClosestEncloserProofInfo<'a> {
        // For `a.b.c.soa.name` the `closest_encloser_candidates` will have:
        // [
        //     (a.b.c.soa.name, h(a.b.c.soa.name), b32h(a.b.c.soa.name)),
        //     (b.c.soa.name, h(b.c.soa.name), b32h(b.c.soa.name)),
        //     (c.soa.name, h(c.soa.name), b32h(c.soa.name)),
        //     (soa.name, h(soa.name), b32h(soa.name)),
        // ]
        let mut closest_encloser_candidates = self
            .encloser_candidates()
            .map(|name| HashedNameInfo::new(name, self))
            .collect::<Vec<_>>();

        // Find the longest candidate name, if any, with a matching NSEC3 record and get the record.
        let Some(closest_encloser_matching_record) =
            closest_encloser_candidates.iter().find_map(|candidate| {
                self.nsec3s
                    .iter()
                    .find(|nsec| nsec.base32_hashed_name == candidate.base32_hashed_name)
            })
        else {
            return ClosestEncloserProofInfo::default();
        };

        // Find the index in the candidate list associated with the closest encloser name.
        let Some(closest_encloser_index) = closest_encloser_candidates
            .iter()
            .enumerate()
            .skip(1) // The closest encloser name can't be at index 0 (it cannot be the longest name)
            .find(|(_, candidate)| {
                candidate.base32_hashed_name == closest_encloser_matching_record.base32_hashed_name
            })
            .map(|(i, _)| i)
        else {
            return ClosestEncloserProofInfo::default();
        };

        let closest_encloser_name_info =
            closest_encloser_candidates.swap_remove(closest_encloser_index);
        let next_closer_name_info =
            closest_encloser_candidates.swap_remove(closest_encloser_index - 1);

        // Now find a covering record for the next closer, which is one label longer than the closest encloser
        let next_closer_covering_record = find_covering_record(
            self.nsec3s,
            &next_closer_name_info.hashed_name,
            &next_closer_name_info.base32_hashed_name,
        );

        ClosestEncloserProofInfo {
            closest_encloser: Some((closest_encloser_name_info, closest_encloser_matching_record)),
            next_closer: next_closer_covering_record.map(|record| (next_closer_name_info, record)),
        }
    }

    /// Hashes a name and returns both both the hash digest and the base32-encoded form.
    fn hash_and_label(&self, name: &Name) -> (Vec<u8>, Label) {
        let hash = self
            .hash_algorithm
            .hash(self.salt, name, self.iterations)
            // We only compute hashes of names between `query_name` and `soa_name`
            // and wildcards between `*.query_name.base_name()` and `*.soa_name`.
            // All of them are guaranteed to be valid names.
            .unwrap()
            .as_ref()
            .to_vec();

        let base32_encoded = data_encoding::BASE32_DNSSEC.encode(&hash);
        // Unwrap safety: The length of the hashed name is valid because it is the output of the above
        // hash function. The input is all alphanumeric ASCII characters by construction.
        let label = Label::from_ascii(&base32_encoded).unwrap();
        (hash, label)
    }

    fn encloser_candidates(&self) -> EncloserCandidates<'a> {
        EncloserCandidates {
            cur: Some(self.query.name().clone()),
            soa: self.soa,
        }
    }

    fn proof(&self, proof: Proof, msg: impl Display) -> Proof {
        nsec3_yield(proof, self.query, msg)
    }
}

fn find_covering_record<'a>(
    nsec3s: &'a [Nsec3RecordPair<'a>],
    target_hashed_name: &[u8],
    // Strictly speaking we don't need this parameter, we can calculate
    // base32(target_hashed_name) inside the function.
    // However, we already have it available at call sites, may as well use
    // it and save on repeated base32 encodings.
    target_base32_hashed_name: &Label,
) -> Option<&'a Nsec3RecordPair<'a>> {
    nsec3s.iter().find(|record| {
        let Some(record_next_hashed_owner_name_base32) =
            record.nsec3_data.next_hashed_owner_name_base32()
        else {
            return false;
        };

        // Matching records don't count as covering records
        if record.base32_hashed_name == *target_base32_hashed_name {
            return false;
        }

        if record.base32_hashed_name < *record_next_hashed_owner_name_base32 {
            // Normal case: target must be between the hashed owner name and the next hashed owner
            // name.
            record.base32_hashed_name < *target_base32_hashed_name
                && target_hashed_name < record.nsec3_data.next_hashed_owner_name()
        } else {
            // Wraparound case: target must be less than the hashed owner name or greater than the
            // next hashed owner name.
            record.base32_hashed_name > *target_base32_hashed_name
                || target_hashed_name > record.nsec3_data.next_hashed_owner_name()
        }
    })
}

// NSEC3 records use a base32 hashed name as a record name component.
// But within the record body the hash is stored as a binary blob.
// Thus we need both for comparisons.
#[derive(Clone, Debug)]
struct HashedNameInfo {
    name: Name,
    hashed_name: Vec<u8>,
    base32_hashed_name: Label,
}

impl HashedNameInfo {
    /// Hash a query name and store all representations of it.
    fn new(name: Name, cx: &Context<'_>) -> Self {
        let (hashed_name, base32_hashed_name) = cx.hash_and_label(&name);
        Self {
            name,
            hashed_name,
            base32_hashed_name,
        }
    }
}

struct EncloserCandidates<'a> {
    cur: Option<Name>,
    soa: Option<&'a Name>,
}

impl Iterator for EncloserCandidates<'_> {
    type Item = Name;

    fn next(&mut self) -> Option<Self::Item> {
        let cur = self.cur.take()?;
        let soa = self.soa?;

        if &cur != soa {
            let next = cur.base_name();
            // TODO: can `query_name` *not* be a sub-name of `soa_name`?
            debug_assert_ne!(next, Name::root());
            self.cur = Some(next);
        }

        Some(cur)
    }
}

/// Logs a debug message and returns a [`Proof`]. This is specific to NSEC3 validation.
fn nsec3_yield(proof: Proof, query: &Query, msg: impl Display) -> Proof {
    proof_log_yield(proof, query, "nsec3", msg)
}

struct Nsec3RecordPair<'a> {
    base32_hashed_name: Label,
    nsec3_data: &'a NSEC3,
}

/// ```text
/// RFC 5155                         NSEC3                        March 2008
///
/// 11.  IANA Considerations
///
///    Although the NSEC3 and NSEC3PARAM RR formats include a hash algorithm
///    parameter, this document does not define a particular mechanism for
///    safely transitioning from one NSEC3 hash algorithm to another.  When
///    specifying a new hash algorithm for use with NSEC3, a transition
///    mechanism MUST also be defined.
///
///    This document updates the IANA registry "DOMAIN NAME SYSTEM
///    PARAMETERS" (https://www.iana.org/assignments/dns-parameters) in sub-
///    registry "TYPES", by defining two new types.  Section 3 defines the
///    NSEC3 RR type 50.  Section 4 defines the NSEC3PARAM RR type 51.
///
///    This document updates the IANA registry "DNS SECURITY ALGORITHM
///    NUMBERS -- per [RFC4035]"
///    (https://www.iana.org/assignments/dns-sec-alg-numbers).  Section 2
///    defines the aliases DSA-NSEC3-SHA1 (6) and RSASHA1-NSEC3-SHA1 (7) for
///    respectively existing registrations DSA and RSASHA1 in combination
///    with NSEC3 hash algorithm SHA1.
///
///    Since these algorithm numbers are aliases for existing DNSKEY
///    algorithm numbers, the flags that exist for the original algorithm
///    are valid for the alias algorithm.
///
///    This document creates a new IANA registry for NSEC3 flags.  This
///    registry is named "DNSSEC NSEC3 Flags".  The initial contents of this
///    registry are:
///
///      0   1   2   3   4   5   6   7
///    +---+---+---+---+---+---+---+---+
///    |   |   |   |   |   |   |   |Opt|
///    |   |   |   |   |   |   |   |Out|
///    +---+---+---+---+---+---+---+---+
///
///       bit 7 is the Opt-Out flag.
///
///       bits 0 - 6 are available for assignment.
///
///    Assignment of additional NSEC3 Flags in this registry requires IETF
///    Standards Action [RFC2434].
///
///    This document creates a new IANA registry for NSEC3PARAM flags.  This
///    registry is named "DNSSEC NSEC3PARAM Flags".  The initial contents of
///    this registry are:
///
///      0   1   2   3   4   5   6   7
///    +---+---+---+---+---+---+---+---+
///    |   |   |   |   |   |   |   | 0 |
///    +---+---+---+---+---+---+---+---+
///
///       bit 7 is reserved and must be 0.
///
///       bits 0 - 6 are available for assignment.
///
///    Assignment of additional NSEC3PARAM Flags in this registry requires
///    IETF Standards Action [RFC2434].
///
///    Finally, this document creates a new IANA registry for NSEC3 hash
///    algorithms.  This registry is named "DNSSEC NSEC3 Hash Algorithms".
///    The initial contents of this registry are:
///
///       0 is Reserved.
///
///       1 is SHA-1.
///
///       2-255 Available for assignment.
///
///    Assignment of additional NSEC3 hash algorithms in this registry
///    requires IETF Standards Action [RFC2434].
/// ```
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Default)]
pub enum Nsec3HashAlgorithm {
    /// Hash for the Nsec3 records
    #[default]
    #[cfg_attr(feature = "serde", serde(rename = "SHA-1"))]
    SHA1,
}

impl Nsec3HashAlgorithm {
    /// ```text
    /// Laurie, et al.              Standards Track                    [Page 14]
    ///
    /// RFC 5155                         NSEC3                        March 2008
    ///
    /// Define H(x) to be the hash of x using the Hash Algorithm selected by
    ///    the NSEC3 RR, k to be the number of Iterations, and || to indicate
    ///    concatenation.  Then define:
    ///
    ///       IH(salt, x, 0) = H(x || salt), and
    ///
    ///       IH(salt, x, k) = H(IH(salt, x, k-1) || salt), if k > 0
    ///
    ///    Then the calculated hash of an owner name is
    ///
    ///       IH(salt, owner name, iterations),
    ///
    ///    where the owner name is in the canonical form, defined as:
    ///
    ///    The wire format of the owner name where:
    ///
    ///    1.  The owner name is fully expanded (no DNS name compression) and
    ///        fully qualified;
    ///
    ///    2.  All uppercase US-ASCII letters are replaced by the corresponding
    ///        lowercase US-ASCII letters;
    ///
    ///    3.  If the owner name is a wildcard name, the owner name is in its
    ///        original unexpanded form, including the "*" label (no wildcard
    ///        substitution);
    /// ```
    pub fn hash(self, salt: &[u8], name: &Name, iterations: u16) -> ProtoResult<Digest> {
        match self {
            // if there ever is more than just SHA1 support, this should be a genericized method
            Self::SHA1 => {
                let mut buf: Vec<u8> = Vec::new();
                {
                    let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut buf);
                    let mut encoder =
                        encoder.with_name_encoding(NameEncoding::UncompressedLowercase);
                    name.emit(&mut encoder)?;
                }

                Ok(Digest::iterated(salt, &buf, DigestType::SHA1, iterations)?)
            }
        }
    }
}

impl TryFrom<u8> for Nsec3HashAlgorithm {
    type Error = DecodeError;

    /// <https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml>
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::SHA1),
            // TODO: where/when is SHA2?
            _ => Err(DecodeError::UnknownNsec3HashAlgorithm(value)),
        }
    }
}

impl From<Nsec3HashAlgorithm> for u8 {
    fn from(a: Nsec3HashAlgorithm) -> Self {
        match a {
            Nsec3HashAlgorithm::SHA1 => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use core::str::FromStr;

    use super::*;
    use crate::{
        ProtoError,
        dnssec::{
            Algorithm,
            rdata::{DNSSECRData, RRSIG as rdataRRSIG, SigInput},
        },
        rr::{
            RData, SerialNumber, rdata,
            record_type::RecordType::{A, AAAA, DNSKEY, DS, MX, NS, NSEC3PARAM, RRSIG, SOA},
        },
    };

    use test_support::subscribe;

    #[test]
    fn test_hash() {
        let name = Name::from_str("www.example.com").unwrap();
        let salt: Vec<u8> = vec![1, 2, 3, 4];

        assert_eq!(
            Nsec3HashAlgorithm::SHA1
                .hash(&salt, &name, 0)
                .unwrap()
                .as_ref()
                .len(),
            20
        );
        assert_eq!(
            Nsec3HashAlgorithm::SHA1
                .hash(&salt, &name, 1)
                .unwrap()
                .as_ref()
                .len(),
            20
        );
        assert_eq!(
            Nsec3HashAlgorithm::SHA1
                .hash(&salt, &name, 3)
                .unwrap()
                .as_ref()
                .len(),
            20
        );
    }

    #[test]
    fn test_known_hashes() {
        // H(example)       = 0p9mhaveqvm6t7vbl5lop2u3t2rp3tom
        assert_eq!(
            hash_with_base32("example"),
            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"
        );
        assert_eq!(
            hash_with_base32("EXAMPLE"),
            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"
        );

        // H(a.example)     = 35mthgpgcu1qg68fab165klnsnk3dpvl
        assert_eq!(
            hash_with_base32("a.example"),
            "35mthgpgcu1qg68fab165klnsnk3dpvl"
        );

        // H(ai.example)    = gjeqe526plbf1g8mklp59enfd789njgi
        assert_eq!(
            hash_with_base32("ai.example"),
            "gjeqe526plbf1g8mklp59enfd789njgi"
        );

        // H(ns1.example)   = 2t7b4g4vsa5smi47k61mv5bv1a22bojr
        assert_eq!(
            hash_with_base32("ns1.example"),
            "2t7b4g4vsa5smi47k61mv5bv1a22bojr"
        );

        // H(ns2.example)   = q04jkcevqvmu85r014c7dkba38o0ji5r
        assert_eq!(
            hash_with_base32("ns2.example"),
            "q04jkcevqvmu85r014c7dkba38o0ji5r"
        );

        // H(w.example)     = k8udemvp1j2f7eg6jebps17vp3n8i58h
        assert_eq!(
            hash_with_base32("w.example"),
            "k8udemvp1j2f7eg6jebps17vp3n8i58h"
        );

        // H(*.w.example)   = r53bq7cc2uvmubfu5ocmm6pers9tk9en
        assert_eq!(
            hash_with_base32("*.w.example"),
            "r53bq7cc2uvmubfu5ocmm6pers9tk9en"
        );

        // H(x.w.example)   = b4um86eghhds6nea196smvmlo4ors995
        assert_eq!(
            hash_with_base32("x.w.example"),
            "b4um86eghhds6nea196smvmlo4ors995"
        );

        // H(y.w.example)   = ji6neoaepv8b5o6k4ev33abha8ht9fgc
        assert_eq!(
            hash_with_base32("y.w.example"),
            "ji6neoaepv8b5o6k4ev33abha8ht9fgc"
        );

        // H(x.y.w.example) = 2vptu5timamqttgl4luu9kg21e0aor3s
        assert_eq!(
            hash_with_base32("x.y.w.example"),
            "2vptu5timamqttgl4luu9kg21e0aor3s"
        );

        // H(xx.example)    = t644ebqk9bibcna874givr6joj62mlhv
        assert_eq!(
            hash_with_base32("xx.example"),
            "t644ebqk9bibcna874givr6joj62mlhv"
        );
    }

    #[test]
    fn nsec3_name_error_tests() -> Result<(), ProtoError> {
        subscribe();

        // Based on RFC 5155 B.1 - Name Error
        assert_eq!(
            verify_nsec3(
                &Query::query(Name::from_ascii("a.c.x.w.example.")?, RecordType::A),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NXDomain,
                &[],
                &[
                    // Covers the next closer name (c.x.w.example.)
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?.prepend_label(hash_with_base32("example"))?,
                        hash("ns1.example."),
                        [MX, DNSKEY, NS, SOA, NSEC3PARAM, RRSIG],
                    )
                    .as_ref(),
                    // Matches the closest encloser (x.w.example.)
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?.prepend_label(hash_with_base32("x.w"))?,
                        hash("ai.example."),
                        [MX, RRSIG],
                    )
                    .as_ref(),
                    // Covers the wildcard at the closest encloser (*.x.w.example.)
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?.prepend_label(hash_with_base32("a"))?,
                        hash("x.w.example."),
                        [DS, NS, RRSIG],
                    )
                    .as_ref(),
                ],
                200,
                500,
            ),
            Proof::Secure,
        );

        // Missing wildcard at the closest encloser
        assert_eq!(
            verify_nsec3(
                &Query::query(Name::from_ascii("a.c.x.w.example.")?, RecordType::A),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NXDomain,
                &[],
                &[
                    // Covers the next closer name (c.x.w.example.)
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?.prepend_label(hash_with_base32("example"))?,
                        hash("ns1.example."),
                        [MX, DNSKEY, NS, SOA, NSEC3PARAM, RRSIG],
                    )
                    .as_ref(),
                    // Matches the closest encloser (x.w.example.)
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?.prepend_label(hash_with_base32("x.w"))?,
                        hash("ai.example."),
                        [MX, RRSIG],
                    )
                    .as_ref(),
                ],
                200,
                500,
            ),
            Proof::Bogus,
        );

        // No record matching the next closer name
        assert_eq!(
            verify_nsec3(
                &Query::query(Name::from_ascii("a.c.x.w.example.")?, RecordType::A),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NXDomain,
                &[],
                &[
                    // Matches the closest encloser (x.w.example.)
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?.prepend_label(hash_with_base32("x.w"))?,
                        hash("ai.example."),
                        [MX, RRSIG],
                    )
                    .as_ref(),
                    // Covers the wildcard at the closest encloser (*.x.w.example.)
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?.prepend_label(hash_with_base32("a"))?,
                        hash("x.w.example."),
                        [DS, NS, RRSIG],
                    )
                    .as_ref(),
                ],
                200,
                500,
            ),
            Proof::Bogus,
        );

        // Invalid SOA
        assert_eq!(
            verify_nsec3(
                &Query::query(Name::from_ascii("a.c.x.w.example.")?, RecordType::A),
                Some(&Name::from_ascii("x.w.example.")?),
                ResponseCode::NXDomain,
                &[],
                &[
                    // Covers the next closer name (c.x.w.example.)
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?.prepend_label(hash_with_base32("example"))?,
                        hash("ns1.example."),
                        [MX, DNSKEY, NS, SOA, NSEC3PARAM, RRSIG],
                    )
                    .as_ref(),
                    // Matches the closest encloser (x.w.example.)
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?.prepend_label(hash_with_base32("x.w"))?,
                        hash("ai.example."),
                        [MX, RRSIG],
                    )
                    .as_ref(),
                    // Covers the wildcard at the closest encloser (*.x.w.example.)
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?.prepend_label(hash_with_base32("a"))?,
                        hash("x.w.example."),
                        [DS, NS, RRSIG],
                    )
                    .as_ref(),
                ],
                200,
                500,
            ),
            Proof::Bogus,
        );

        Ok(())
    }

    #[test]
    fn nsec3_no_data_error_tests() -> Result<(), ProtoError> {
        subscribe();

        // Based on RFC 5155 B.2 - No Data Error
        assert_eq!(
            verify_nsec3(
                &Query::query(Name::from_ascii("ns1.example.")?, MX),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[],
                &[
                    // Matches the query name and proves the record type does not exist.
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?
                            .prepend_label(hash_with_base32("ns1.example"))?,
                        hash("x.y.w.example."),
                        [A, RRSIG],
                    )
                    .as_ref(),
                ],
                200,
                500,
            ),
            Proof::Secure,
        );

        // Based on RFC 5155 B.2.1 - No Data Error, Empty Non-Terminal
        assert_eq!(
            verify_nsec3(
                &Query::query(Name::from_ascii("y.w.example.")?, A),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[],
                &[
                    // Matches the query name and proves the record type does not exist.
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?
                            .prepend_label(hash_with_base32("y.w.example"))?,
                        hash("w.example."),
                        [],
                    )
                    .as_ref(),
                ],
                200,
                500,
            ),
            Proof::Secure,
        );

        // NSEC Type map doesn't disprove the queried record type
        assert_eq!(
            verify_nsec3(
                &Query::query(Name::from_ascii("ns1.example.")?, MX),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[],
                &[
                    // Matches the query name and proves the record type does not exist.
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?
                            .prepend_label(hash_with_base32("ns1.example"))?,
                        hash("x.y.w.example."),
                        [A, RRSIG, MX],
                    )
                    .as_ref(),
                ],
                200,
                500,
            ),
            Proof::Bogus,
        );

        // NSEC3 doesn't match the query name.
        assert_eq!(
            verify_nsec3(
                &Query::query(Name::from_ascii("ns1.example.")?, MX),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[],
                &[Nsec3Pair::new(
                    Name::from_ascii("example.")?.prepend_label(hash_with_base32("ns2.example"))?,
                    hash("x.y.w.example."),
                    [A, RRSIG],
                )
                .as_ref(),],
                200,
                500,
            ),
            Proof::Bogus,
        );

        // NSEC3 covers the query name.
        assert_eq!(
            verify_nsec3(
                &Query::query(Name::from_ascii("ns1.example.")?, MX),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[],
                &[Nsec3Pair::new(
                    Name::from_ascii("example.")?.prepend_label(hash_with_base32("example"))?,
                    hash("a.example."),
                    [A, SOA, DNSKEY, RRSIG],
                )
                .as_ref(),],
                200,
                500,
            ),
            Proof::Bogus,
        );

        Ok(())
    }

    #[test]
    fn nsec3_wildcard_expansion_tests() -> Result<(), ProtoError> {
        subscribe();

        let input = SigInput {
            type_covered: MX,
            algorithm: Algorithm::ED25519,
            num_labels: 2,
            original_ttl: 0,
            sig_expiration: SerialNumber(0),
            sig_inception: SerialNumber(0),
            key_tag: 0,
            signer_name: Name::root(),
        };

        let rrsig = rdataRRSIG::from_sig(input, vec![]);
        let rrsig_record = Record::from_rdata(
            Name::from_ascii("a.z.w.example.")?,
            3600,
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
        );

        let answers = [
            Record::from_rdata(
                Name::from_ascii("a.z.w.example.")?,
                3600,
                RData::MX(rdata::MX::new(10, Name::from_ascii("a.z.w.example.")?)),
            ),
            rrsig_record,
        ];

        // Based on RFC 5155 B.4 - Wildcard Expansion
        assert_eq!(
            verify_nsec3(
                &Query::query(Name::from_ascii("a.z.w.example.")?, MX),
                None,
                ResponseCode::NoError,
                &answers,
                &[
                    // Covers the next-closer name
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?
                            .prepend_label(hash_with_base32("ns2.example"))?,
                        hash("*.w.example."),
                        [A, RRSIG],
                    )
                    .as_ref(),
                ],
                200,
                500,
            ),
            Proof::Secure,
        );

        assert_eq!(
            verify_nsec3(
                &Query::query(Name::from_ascii("a.z.w.example.")?, MX),
                None,
                ResponseCode::NoError,
                &answers,
                &[
                    // Fails to cover the next-closer name
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?.prepend_label(hash_with_base32("example"))?,
                        hash("a.example."),
                        [A, RRSIG],
                    )
                    .as_ref(),
                ],
                200,
                500,
            ),
            Proof::Bogus,
        );

        assert_eq!(
            verify_nsec3(
                &Query::query(Name::from_ascii("a.z.w.example.")?, MX),
                None,
                ResponseCode::NoError,
                &answers,
                &[
                    // Matches the next-closer name.
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?
                            .prepend_label(hash_with_base32("z.w.example"))?,
                        hash("a.example."),
                        [A, RRSIG],
                    )
                    .as_ref(),
                ],
                200,
                500,
            ),
            Proof::Bogus,
        );

        Ok(())
    }

    #[test]
    fn nsec3_wildcard_no_data_error_tests() -> Result<(), ProtoError> {
        subscribe();

        // Based on RFC 5155 B.5 - Wildcard No Data Error
        assert_eq!(
            verify_nsec3(
                &Query::query(Name::from_ascii("a.z.w.example.")?, AAAA),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[],
                &[
                    // Matches the closest encloser
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?
                            .prepend_label(hash_with_base32("w.example"))?,
                        hash("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example"),
                        [],
                    )
                    .as_ref(),
                    // Covers the next-closer name (z.w.example)
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?
                            .prepend_label(hash_with_base32("ns2.example"))?,
                        hash("*.w.example"),
                        [A, RRSIG],
                    )
                    .as_ref(),
                    // Matches the wildcard at the closest encloser (*.w.example)
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?
                            .prepend_label(hash_with_base32("*.w.example"))?,
                        hash("xx.example"),
                        [MX, RRSIG],
                    )
                    .as_ref(),
                ],
                200,
                500,
            ),
            Proof::Secure,
        );

        // Missing an NSEC matching the closest encloser.
        assert_eq!(
            verify_nsec3(
                &Query::query(Name::from_ascii("a.z.w.example.")?, AAAA),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[],
                &[
                    // Covers the next-closer name (z.w.example)
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?
                            .prepend_label(hash_with_base32("ns2.example"))?,
                        hash("*.w.example"),
                        [A, RRSIG],
                    )
                    .as_ref(),
                    // Matches the wildcard at the closest encloser (*.w.example)
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?
                            .prepend_label(hash_with_base32("*.w.example"))?,
                        hash("xx.example"),
                        [MX, RRSIG],
                    )
                    .as_ref(),
                ],
                200,
                500,
            ),
            Proof::Bogus,
        );

        // No record covering the next-closer
        assert_eq!(
            verify_nsec3(
                &Query::query(Name::from_ascii("a.z.w.example.")?, AAAA),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[],
                &[
                    // Matches the closest encloser
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?
                            .prepend_label(hash_with_base32("w.example"))?,
                        hash("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example"),
                        [],
                    )
                    .as_ref(),
                    // Matches the wildcard at the closest encloser (*.w.example)
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?
                            .prepend_label(hash_with_base32("*.w.example"))?,
                        hash("xx.example"),
                        [MX, RRSIG],
                    )
                    .as_ref(),
                ],
                200,
                500,
            ),
            Proof::Bogus,
        );

        // No record matching the wildcard at the closest encloser.
        assert_eq!(
            verify_nsec3(
                &Query::query(Name::from_ascii("a.z.w.example.")?, AAAA),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[],
                &[
                    // Matches the closest encloser
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?
                            .prepend_label(hash_with_base32("w.example"))?,
                        hash("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example"),
                        [],
                    )
                    .as_ref(),
                    // Covers the next-closer name (z.w.example)
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?
                            .prepend_label(hash_with_base32("ns2.example"))?,
                        hash("*.w.example"),
                        [A, RRSIG],
                    )
                    .as_ref(),
                ],
                200,
                500,
            ),
            Proof::Bogus,
        );

        // No SOA record
        assert_eq!(
            verify_nsec3(
                &Query::query(Name::from_ascii("a.z.w.example.")?, AAAA),
                None,
                ResponseCode::NoError,
                &[],
                &[
                    // Matches the closest encloser
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?
                            .prepend_label(hash_with_base32("w.example"))?,
                        hash("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example"),
                        [],
                    )
                    .as_ref(),
                    // Covers the next-closer name (z.w.example)
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?
                            .prepend_label(hash_with_base32("ns2.example"))?,
                        hash("*.w.example"),
                        [A, RRSIG],
                    )
                    .as_ref(),
                    // Matches the wildcard at the closest encloser (*.w.example)
                    Nsec3Pair::new(
                        Name::from_ascii("example.")?
                            .prepend_label(hash_with_base32("*.w.example"))?,
                        hash("xx.example"),
                        [MX, RRSIG],
                    )
                    .as_ref(),
                ],
                200,
                500,
            ),
            Proof::Bogus
        );

        Ok(())
    }

    #[derive(Debug)]
    struct Nsec3Pair(Name, NSEC3);

    impl Nsec3Pair {
        fn new(
            rr_name: Name,
            next_name: Vec<u8>,
            rrset: impl IntoIterator<Item = RecordType>,
        ) -> Self {
            Self(
                rr_name,
                NSEC3::new(
                    Nsec3HashAlgorithm::SHA1,
                    false,
                    12,
                    KNOWN_SALT.to_vec(),
                    next_name,
                    rrset,
                ),
            )
        }

        fn as_ref(&self) -> (&Name, &NSEC3) {
            (&self.0, &self.1)
        }
    }

    fn hash(name: &str) -> Vec<u8> {
        // NSEC3PARAM 1 0 12 aabbccdd
        let known_name = Name::from_ascii(name).unwrap();
        Nsec3HashAlgorithm::SHA1
            .hash(KNOWN_SALT, &known_name, 12)
            .unwrap()
            .as_ref()
            .to_vec()
    }

    #[cfg(test)]
    fn hash_with_base32(name: &str) -> String {
        use data_encoding::BASE32_DNSSEC;

        BASE32_DNSSEC.encode(&hash(name))
    }

    const KNOWN_SALT: &[u8] = &[0xAAu8, 0xBBu8, 0xCCu8, 0xDDu8];
}
