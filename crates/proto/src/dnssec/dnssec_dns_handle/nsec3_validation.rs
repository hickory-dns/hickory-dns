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

use alloc::vec::Vec;

use super::proof_log_yield;
use crate::{
    dnssec::{Nsec3HashAlgorithm, Proof, rdata::NSEC3},
    op::{Query, ResponseCode},
    rr::{Name, Record, RecordType, domain::Label},
};

pub(super) fn verify_nsec3(
    query: &Query,
    soa: &Name,
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

        if &base != soa {
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
            &format!(
                "iteration count {iterations} is over {nsec3_hard_iteration_limit}; returning Proof::Bogus"
            ),
        );
    } else if iterations > nsec3_soft_iteration_limit {
        return nsec3_yield(
            Proof::Insecure,
            query,
            &format!(
                "iteration count {iterations} is over {nsec3_soft_iteration_limit}; returning Proof::Insecure"
            ),
        );
    }

    // Basic sanity checks are done.
    let cx = Context {
        query,
        soa,
        nsec3s: &pairs,
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
            &format!("unsupported response code ({response_code})")[..],
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

    let (closest_encloser_proof_info, early_proof) = closest_encloser_proof(cx);

    if let Some(proof) = early_proof {
        return cx.proof(proof, "returning early proof");
    }

    // Note that the three fields may hold references to the same NSEC3
    // record, because the interval of base32_hashed_name
    // and next_hashed_owner_name happen to match / cover all three components
    // of closest encloser proof.
    let ClosestEncloserProofInfo {
        closest_encloser,
        next_closer,
        closest_encloser_wildcard,
    } = closest_encloser_proof_info;

    match (closest_encloser, next_closer, closest_encloser_wildcard) {
        // Got all three components - we proved that there's no `query_name`
        // in the zone
        (Some(_), Some(_), Some(_)) => cx.proof(Proof::Secure, "direct proof"),
        // `query_name`'s parent is the `soa_name` itself, so there's no need
        // to send `soa_name`'s NSEC3 record. Still we have to show that
        // both `query_name` doesn't exist and there's no wildcard to service it
        (None, Some(_), Some(_)) if &cx.query.name().base_name() == cx.soa => cx.proof(
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
                &format!("nsec3 type map covers {query_type} or CNAME")[..],
            );
        } else {
            return cx.proof(
                Proof::Secure,
                &format!("type map does not cover {query_type} or CNAME")[..],
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
                    &format!(
                        "query labels ({}) <= wildcard encloser labels ({})",
                        cx.query.name().num_labels(),
                        wildcard_encloser_num_labels,
                    )[..],
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
                Some(_) => (Proof::Secure, "matching next closer record"),
                None => (Proof::Bogus, "no matching next closer record"),
            }
        }

        // Case 5:
        // Name is serviced by wildcard that doesn't have a record of this type
        None => {
            let ClosestEncloserProofInfo {
                closest_encloser,
                next_closer,
                closest_encloser_wildcard,
            } = ClosestEncloserProofInfo::from_wildcard(cx);
            match (closest_encloser, next_closer, closest_encloser_wildcard) {
                (Some(_), Some(_), Some(_)) => (
                    Proof::Secure,
                    "servicing wildcard with closest encloser proof",
                ),
                (None, Some(_), Some(_)) if &cx.query.name().base_name() == cx.soa => (
                    Proof::Secure,
                    "servicing wildcard without closest encloser proof, but query parent name == SOA",
                ),
                (None, None, None) if cx.query.name() == cx.soa => (
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

/// Expecting the following records:
/// * closest encloser - *matching* NSEC3 record
/// * next closer - *covering* NSEC3 record
/// * wildcard of closest encloser - *covering* NSEC3 record
fn closest_encloser_proof<'a>(cx: &Context<'a>) -> (ClosestEncloserProofInfo<'a>, Option<Proof>) {
    let mut closest_encloser_candidates = cx
        .encloser_candidates()
        .map(|name| HashedNameInfo::new(name, cx))
        .collect::<Vec<_>>();

    // Search for *matching* closing encloser record, i.e.
    // An NSEC3 record those name matches one of the names in
    // candidate list
    let closest_encloser_in_candidates = closest_encloser_candidates.iter().enumerate().find_map(
        |(candidate_index, candidate_name_info)| {
            let nsec3 = cx
                .nsec3s
                .iter()
                .find(|r| r.base32_hashed_name == candidate_name_info.base32_hashed_name);
            nsec3.map(|record| (candidate_index, record))
        },
    );

    match closest_encloser_in_candidates {
        // General flow - there's a record for closest encloser
        Some((closest_encloser_index @ 1.., closest_encloser_record)) => {
            let closest_encloser_hash_info =
                closest_encloser_candidates.swap_remove(closest_encloser_index);
            let closest_encloser_wildcard_name =
                closest_encloser_hash_info.name.prepend_label("*").unwrap();
            let closest_encloser = Some((closest_encloser_hash_info, closest_encloser_record));

            let next_closer_hash_info =
                closest_encloser_candidates.swap_remove(closest_encloser_index - 1);
            let next_closer = find_covering_record(
                cx.nsec3s,
                &next_closer_hash_info.hashed_name,
                &next_closer_hash_info.base32_hashed_name,
            )
            .map(|record| (next_closer_hash_info, record));

            let wildcard_name_info = HashedNameInfo::new(closest_encloser_wildcard_name, cx);
            let wildcard = find_covering_record(
                cx.nsec3s,
                &wildcard_name_info.hashed_name,
                &wildcard_name_info.base32_hashed_name,
            )
            .map(|record| (wildcard_name_info, record));

            (
                ClosestEncloserProofInfo {
                    closest_encloser,
                    next_closer,
                    closest_encloser_wildcard: wildcard,
                },
                None,
            )
        }
        Some((0, _)) => {
            // Closest encloser at index 0 corresponds to an NSEC3 record
            // with the key = base32(hash(`query_name`)), which should not be
            // possible because that would mean `query_name` exists in the zone,
            // but the response code is NXDomain.
            (
                ClosestEncloserProofInfo {
                    closest_encloser: None,
                    next_closer: None,
                    closest_encloser_wildcard: None,
                },
                Some(Proof::Bogus),
            )
        }
        None if &cx.query.name().base_name() == cx.soa => {
            // There's no record for closest encloser.
            // It may not be present since the encloser is `soa_name` which
            // is *known to exist*.
            //
            // Next closer *is* `query_name`, hence index 0
            let next_encloser_hash_info = closest_encloser_candidates.swap_remove(0);
            let next_closer = find_covering_record(
                cx.nsec3s,
                &next_encloser_hash_info.hashed_name,
                &next_encloser_hash_info.base32_hashed_name,
            )
            .map(|record| (next_encloser_hash_info, record));

            // Additionally there should be an NSEC3 record *covering*
            // `*.soa_name` wildcard.
            // If the wildcard existed then the response code would be NoError
            // but we received `NXDomain`
            let closest_encloser_wildcard_name = cx.soa.prepend_label("*").unwrap();
            let wildcard_name_info = HashedNameInfo::new(closest_encloser_wildcard_name, cx);
            let wildcard = find_covering_record(
                cx.nsec3s,
                &wildcard_name_info.hashed_name,
                &wildcard_name_info.base32_hashed_name,
            )
            .map(|record| (wildcard_name_info, record));

            (
                ClosestEncloserProofInfo {
                    closest_encloser: None,
                    next_closer,
                    closest_encloser_wildcard: wildcard,
                },
                None,
            )
        }
        None => {
            // Problematic case: a.b.soa.name doesn't exist
            // but there's no NSEC3 record for any of the ancestors
            //
            // If `b.soa.name` existed we should have its *matching* NSEC3 record
            // and a record *covering* `a.b.soa.name` in `next_closer`
            //
            // If `b.soa.name` didn't exist we would get a record *covering* it
            // in `next_closer`.
            (
                ClosestEncloserProofInfo {
                    closest_encloser: None,
                    next_closer: None,
                    closest_encloser_wildcard: None,
                },
                Some(Proof::Bogus),
            )
        }
    }
}

#[derive(Default)]
struct ClosestEncloserProofInfo<'a> {
    closest_encloser: Option<(HashedNameInfo, &'a Nsec3RecordPair<'a>)>,
    next_closer: Option<(HashedNameInfo, &'a Nsec3RecordPair<'a>)>,
    closest_encloser_wildcard: Option<(HashedNameInfo, &'a Nsec3RecordPair<'a>)>,
}

impl<'a> ClosestEncloserProofInfo<'a> {
    /// Expecting the following records:
    /// * closest encloser - *matching* NSEC3 record
    /// * next closer - *covering* NSEC3 record
    /// * wildcard of closest encloser - *matching* NSEC3 record
    ///   NOTE: this is the difference between this and NXDomain case
    ///
    /// Unlike non-wildcard version this cannot produce the early `Proof`
    fn from_wildcard(cx: &'a Context<'a>) -> Self {
        let mut closest_encloser_candidates = cx
            .encloser_candidates()
            .map(|name| HashedNameInfo::new(name, cx))
            .collect::<Vec<_>>();

        // For `a.b.c.soa.name` the `closest_encloser_candidates` will have:
        // [
        //     (a.b.c.soa.name, h(a.b.c.soa.name), b32h(a.b.c.soa.name)),
        //     (b.c.soa.name, h(b.c.soa.name), b32h(b.c.soa.name)),
        //     (c.soa.name, h(c.soa.name), b32h(c.soa.name)),
        //     (soa.name, h(soa.name), b32h(soa.name)),
        // ]
        //
        // `wildcard_encloser_candidates` will have:
        // [
        //     (*.b.c.soa.name, h(*.b.c.soa.name), b32h(*.b.c.soa.name)),
        //     (*.c.soa.name, h(*.c.soa.name), b32h(*.c.soa.name)),
        //     (*.soa.name, h(*.soa.name), b32h(*.soa.name)),
        // ]
        //
        let mut wildcard_encloser_candidates = closest_encloser_candidates
            .iter()
            .filter(|HashedNameInfo { name, .. }| name != cx.soa)
            .map(|info| {
                let wildcard = info.name.clone().into_wildcard();
                HashedNameInfo::new(wildcard, cx)
            })
            .collect::<Vec<_>>();

        let wildcard_encloser = wildcard_encloser_candidates
            .iter()
            .enumerate()
            .find_map(|(index, wildcard)| {
                let wildcard_nsec3 = cx
                    .nsec3s
                    .iter()
                    .find(|record| record.base32_hashed_name == wildcard.base32_hashed_name);
                wildcard_nsec3.map(|record| (index, record))
            })
            .map(|(index, record)| {
                let wildcard_name_info = wildcard_encloser_candidates.swap_remove(index);
                (wildcard_name_info, record)
            });

        let Some((wildcard_encloser_name_info, _)) = &wildcard_encloser else {
            return Self::default();
        };

        // Wildcard record exists. Within the wildcard there should be
        // a next_closer with a name <unknown>.<wildcard_base_name>.

        let closest_encloser_name = wildcard_encloser_name_info.name.base_name();

        // the shortest `wildcard_encloser` would be `*.soa.name`,
        // and its `.base_name()` would be `soa.name` itself, which is
        // guaranteed to be in the `closest_encloser_candidates`.
        // all other, longer, wildcards would have their base_names from
        // `query_name.base_name()` to `soa.name` and thus are guaranteed
        // to be in the `closest_encloser_candidates`, too.
        let closest_encloser_index = closest_encloser_candidates
            .iter()
            .position(|name_info| name_info.name == closest_encloser_name)
            .expect("cannot fail, always > 0");

        // `closest_encloser_candidates` starts with query_name itself, index 0.
        // The *closest* name a `closest_encloser` can be is
        // `query_name.base_name()`, because it's derived from a wildcard above.
        // Thus, `closest_encloser` would have an index 1 or bigger
        debug_assert!(closest_encloser_index >= 1);
        let closest_encloser_name_info =
            closest_encloser_candidates.swap_remove(closest_encloser_index);
        let closest_encloser_covering_record = find_covering_record(
            cx.nsec3s,
            &closest_encloser_name_info.hashed_name,
            &closest_encloser_name_info.base32_hashed_name,
        );

        // Since `closest_encloser_index` is >= 1, this is always valid.
        let next_closer_index = closest_encloser_index - 1;
        let next_closer_name_info = closest_encloser_candidates.swap_remove(next_closer_index);
        let next_closer_covering_record = find_covering_record(
            cx.nsec3s,
            &next_closer_name_info.hashed_name,
            &next_closer_name_info.base32_hashed_name,
        );

        Self {
            closest_encloser: closest_encloser_covering_record
                .map(|record| (closest_encloser_name_info, record)),
            next_closer: next_closer_covering_record.map(|record| (next_closer_name_info, record)),
            closest_encloser_wildcard: wildcard_encloser,
        }
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

struct Context<'a> {
    query: &'a Query,
    soa: &'a Name,
    nsec3s: &'a [Nsec3RecordPair<'a>],
    salt: &'a [u8],
    iterations: u16,
}

impl<'a> Context<'a> {
    /// Hashes a name and returns both both the hash digest and the base32-encoded form.
    fn hash_and_label(&self, name: &Name) -> (Vec<u8>, Label) {
        let hash = Nsec3HashAlgorithm::SHA1
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

    fn proof(&self, proof: Proof, msg: &str) -> Proof {
        nsec3_yield(proof, self.query, msg)
    }
}

struct EncloserCandidates<'a> {
    cur: Option<Name>,
    soa: &'a Name,
}

impl Iterator for EncloserCandidates<'_> {
    type Item = Name;

    fn next(&mut self) -> Option<Self::Item> {
        let cur = self.cur.take()?;
        if &cur != self.soa {
            let next = cur.base_name();
            // TODO: can `query_name` *not* be a sub-name of `soa_name`?
            debug_assert_ne!(next, Name::root());
            self.cur = Some(next);
        }

        Some(cur)
    }
}

/// Logs a debug message and returns a [`Proof`]. This is specific to NSEC3 validation.
fn nsec3_yield(proof: Proof, query: &Query, msg: &str) -> Proof {
    proof_log_yield(proof, query, "nsec3", msg)
}

struct Nsec3RecordPair<'a> {
    base32_hashed_name: Label,
    nsec3_data: &'a NSEC3,
}
