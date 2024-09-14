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

use crate::{
    op::{Query, ResponseCode},
    rr::{
        dnssec::{rdata::NSEC3, Nsec3HashAlgorithm, Proof},
        Name, Record, RecordType,
    },
};

pub(super) fn verify_nsec3(
    query: &Query,
    soa_name: &Name,
    response_code: ResponseCode,
    answers: &[Record],
    nsec3s: &[(&Name, &NSEC3)],
) -> Proof {
    debug_assert!(!nsec3s.is_empty());

    // For every NSEC3 record that in text form looks like:
    // <base32-hash>.soa.name NSEC3 <data>
    // we extract (<base32-hash>, <data>) pair from deeply nested structures
    let nsec3s: Option<Vec<Nsec3RecordPair<'_>>> = nsec3s
        .iter()
        .map(|(record_name, nsec3_data)| {
            split_first_label(record_name)
                .filter(|(_, base)| base == soa_name)
                .map(|(base32_hashed_name, _)| Nsec3RecordPair {
                    base32_hashed_name,
                    nsec3_data,
                })
        })
        .collect();

    // Some of record names were NOT in a form of `<base32hash>.soa.name`
    let Some(nsec3s) = nsec3s else {
        return Proof::Bogus;
    };

    debug_assert!(!nsec3s.is_empty());

    // RFC 5155 8.2 - all NSEC3 records share the same NSEC3 params
    let first = &nsec3s[0];
    let hash_algorithm = first.nsec3_data.hash_algorithm();
    let salt = first.nsec3_data.salt();
    let iterations = first.nsec3_data.iterations();
    if nsec3s.iter().any(|r| {
        r.nsec3_data.hash_algorithm() != hash_algorithm
            || r.nsec3_data.salt() != salt
            || r.nsec3_data.iterations() != iterations
    }) {
        return Proof::Bogus;
    }

    // Basic sanity checks are done.

    let query_name = query.name();

    // From here on 4 big situations are possible:
    // 1. No such name, and no servicing wildcard
    // 2. Name exists but there's no record of this type
    // 3. Name is serviced by wildcard that has a record of this type
    // 4. Name is serviced by wildcard that doesn't have a record of this type

    match response_code {
        // Case 1:
        ResponseCode::NXDomain => validate_nxdomain_response(query_name, soa_name, &nsec3s),

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
                    .map(|data| data.num_labels())
            });
            validate_nodata_response(
                query_name,
                soa_name,
                query.query_type(),
                wildcard_num_labels,
                &nsec3s,
            )
        }
        _ => Proof::Bogus,
    }
}

struct Nsec3RecordPair<'a> {
    base32_hashed_name: &'a [u8],
    nsec3_data: &'a NSEC3,
}

fn split_first_label(name: &Name) -> Option<(&[u8], Name)> {
    let first_label = name.iter().next()?;
    let base = name.base_name();
    Some((first_label, base))
}

fn nsec3hash(name: &Name, salt: &[u8], iterations: u16) -> Vec<u8> {
    Nsec3HashAlgorithm::SHA1
        .hash(salt, name, iterations)
        // We only compute hashes of names between `query_name` and `soa_name`
        // and wildcards between `*.query_name.base_name()` and `*.soa_name`.
        // All of them are guaranteed to be valid names.
        .unwrap()
        .as_ref()
        .to_vec()
}

// NSEC3 records use a base32 hashed name as a record name component.
// But within the record body the hash is stored as a binary blob.
// Thus we need both for comparisons.
struct HashedNameInfo {
    name: Name,
    hashed_name: Vec<u8>,
    base32_hashed_name: String,
}

fn find_covering_record<'a>(
    nsec3s: &'a [Nsec3RecordPair<'a>],
    target_hashed_name: &[u8],
    // Strictly speaking we don't need this parameter, we can calculate
    // base32(target_hashed_name) inside the function.
    // However, we already have it available at call sites, may as well use
    // it and save on repeated base32 encodings.
    target_base32_hashed_name: &str,
) -> Option<&'a Nsec3RecordPair<'a>> {
    nsec3s.iter().find(|record| {
        record.base32_hashed_name < target_base32_hashed_name.as_bytes()
            && target_hashed_name < record.nsec3_data.next_hashed_owner_name()
    })
}

/// There is no such `query_name` in the zone and there's no wildcard that
/// can be expanded to service this `query_name`.
///
/// Expecting the following records:
/// * closest encloser - *matching* NSEC3 record
/// * next closer - *covering* NSEC3 record
/// * wildcard of closest encloser - *covering* NSEC3 record
fn validate_nxdomain_response(
    query_name: &Name,
    soa_name: &Name,
    nsec3s: &[Nsec3RecordPair<'_>],
) -> Proof {
    debug_assert!(!nsec3s.is_empty());
    let salt = nsec3s[0].nsec3_data.salt();
    let iterations = nsec3s[0].nsec3_data.iterations();

    let hashed_query_name = nsec3hash(query_name, salt, iterations);
    let base32_hased_query_name = data_encoding::BASE32_DNSSEC.encode(&hashed_query_name);

    // The response is NXDomain but there's a record for query_name
    if nsec3s
        .iter()
        .any(|r| r.base32_hashed_name == base32_hased_query_name.as_bytes())
    {
        return Proof::Bogus;
    }

    let (closest_encloser_proof_info, early_proof) =
        closest_encloser_proof(query_name, soa_name, nsec3s);

    if let Some(proof) = early_proof {
        return proof;
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
        (Some(_), Some(_), Some(_)) => Proof::Secure,
        // `query_name`'s parent is the `soa_name` itself, so there's no need
        // to send `soa_name`'s NSEC3 record. Still we have to show that
        // both `query_name` doesn't exist and there's no wildcard to service it
        (None, Some(_), Some(_)) if &query_name.base_name() == soa_name => Proof::Secure,
        _ => Proof::Bogus,
    }
}

struct ClosestEncloserProofInfo<'a> {
    closest_encloser: Option<(HashedNameInfo, &'a Nsec3RecordPair<'a>)>,
    next_closer: Option<(HashedNameInfo, &'a Nsec3RecordPair<'a>)>,
    closest_encloser_wildcard: Option<(HashedNameInfo, &'a Nsec3RecordPair<'a>)>,
}

/// For each intermediary name from `query_name` to `soa_name` this function
/// constructs a triplet of (Name, HashedName, Base32EncodedHashedName)
///
/// For `a.b.c.soa.name` it will generate:
/// [
///     (a.b.c.soa.name, h(a.b.c.soa.name), b32h(a.b.c.soa.name)),
///     (b.c.soa.name, h(b.c.soa.name), b32h(b.c.soa.name)),
///     (c.soa.name, h(c.soa.name), b32h(c.soa.name)),
///     (soa.name, h(soa.name), b32h(soa.name)),
/// ]
///
/// The list *starts* with `query_name` and *ends* with `soa_name`. Other
/// code in this module exploits this invariant.
///
/// In simplest situations when `query_name` is `label.soa_name` it itself
/// will act as "next closer"
fn build_encloser_candidates_list(
    query_name: &Name,
    soa_name: &Name,
    salt: &[u8],
    iterations: u16,
) -> Vec<HashedNameInfo> {
    let mut candidates = Vec::with_capacity(query_name.num_labels() as usize);

    // `query_name` is our first candidate
    let mut name = query_name.clone();
    loop {
        let hashed_name = nsec3hash(&name, salt, iterations);
        let base32_hashed_name = data_encoding::BASE32_DNSSEC.encode(&hashed_name);
        candidates.push(HashedNameInfo {
            name: name.clone(),
            hashed_name,
            base32_hashed_name,
        });
        if &name == soa_name {
            // `soa_name` is the final candidate, we already added it.
            return candidates;
        }
        name = name.base_name();
        // TODO: can `query_name` *not* be a sub-name of `soa_name`?
        debug_assert_ne!(name, Name::root());
    }
}

/// Expecting the following records:
/// * closest encloser - *matching* NSEC3 record
/// * next closer - *covering* NSEC3 record
/// * wildcard of closest encloser - *covering* NSEC3 record
fn closest_encloser_proof<'a>(
    query_name: &Name,
    soa_name: &Name,
    nsec3s: &'a [Nsec3RecordPair<'a>],
) -> (ClosestEncloserProofInfo<'a>, Option<Proof>) {
    debug_assert!(!nsec3s.is_empty());
    let salt = nsec3s[0].nsec3_data.salt();
    let iterations = nsec3s[0].nsec3_data.iterations();

    let mut closest_encloser_candidates =
        build_encloser_candidates_list(query_name, soa_name, salt, iterations);

    // Search for *matching* closing encloser record, i.e.
    // An NSEC3 record those name matches one of the names in
    // candidate list
    let closest_encloser_in_candidates = closest_encloser_candidates.iter().enumerate().find_map(
        |(candidate_index, candidate_name_info)| {
            let nsec3 = nsec3s.iter().find(|r| {
                r.base32_hashed_name == candidate_name_info.base32_hashed_name.as_bytes()
            });
            nsec3.map(|record| (candidate_index, record))
        },
    );

    match closest_encloser_in_candidates {
        // General flow - there's a record for closest encloser
        Some((closest_encloser_index, closest_encloser_record)) if closest_encloser_index > 0 => {
            let closest_encloser_hash_info =
                closest_encloser_candidates.swap_remove(closest_encloser_index);
            let closest_encloser_wildcard_name = Name::new()
                .append_label("*")
                .unwrap()
                .append_name(&closest_encloser_hash_info.name)
                .expect("closest encloser name exists in the zone");
            let closest_encloser = Some((closest_encloser_hash_info, closest_encloser_record));

            let next_closer_hash_info =
                closest_encloser_candidates.swap_remove(closest_encloser_index - 1);
            let next_closer = find_covering_record(
                nsec3s,
                &next_closer_hash_info.hashed_name,
                &next_closer_hash_info.base32_hashed_name,
            )
            .map(|record| (next_closer_hash_info, record));

            let closest_encloser_wildcard_hashed_name =
                nsec3hash(&closest_encloser_wildcard_name, salt, iterations);
            let closest_encloser_wildcard_base32_hashed_name =
                data_encoding::BASE32_DNSSEC.encode(&closest_encloser_wildcard_hashed_name);
            let wildcard_name_info = HashedNameInfo {
                name: closest_encloser_wildcard_name,
                hashed_name: closest_encloser_wildcard_hashed_name,
                base32_hashed_name: closest_encloser_wildcard_base32_hashed_name,
            };
            let wildcard = find_covering_record(
                nsec3s,
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
        Some(_) => unreachable!(
            "the compiler is convinced the first two cases don't match all Some(_)s possible"
        ),
        None if &query_name.base_name() == soa_name => {
            // There's no record for closest encloser.
            // It may not be present since the encloser is `soa_name` which
            // is *known to exist*.
            //
            // Next closer *is* `query_name`, hence index 0
            let next_encloser_hash_info = closest_encloser_candidates.swap_remove(0);
            let next_closer = find_covering_record(
                nsec3s,
                &next_encloser_hash_info.hashed_name,
                &next_encloser_hash_info.base32_hashed_name,
            )
            .map(|record| (next_encloser_hash_info, record));

            // Additionally there should be an NSEC3 record *covering*
            // `*.soa_name` wildcard.
            // If the wildcard existed then the response code would be NoError
            // but we received `NXDomain`
            let closest_encloser_wildcard_name = Name::new()
                .append_label("*")
                .unwrap()
                .append_name(soa_name)
                .expect("`soa_name` is an existing domain with a valid name");
            let closest_encloser_wildcard_hashed_name =
                nsec3hash(&closest_encloser_wildcard_name, salt, iterations);
            let closest_encloser_wildcard_base32_hashed_name =
                data_encoding::BASE32_DNSSEC.encode(&closest_encloser_wildcard_hashed_name);
            let wildcard_name_info = HashedNameInfo {
                name: closest_encloser_wildcard_name,
                hashed_name: closest_encloser_wildcard_hashed_name,
                base32_hashed_name: closest_encloser_wildcard_base32_hashed_name,
            };
            let wildcard = find_covering_record(
                nsec3s,
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

/// This function addresses three situations:
///
/// Case 2. Name exists but there's no record of this type
/// Case 3. Name is serviced by wildcard that has a record of this type
/// Case 4. Name is serviced by wildcard that doesn't have a record of this type
fn validate_nodata_response(
    query_name: &Name,
    soa_name: &Name,
    query_type: RecordType,
    wildcard_encloser_num_labels: Option<u8>,
    nsec3s: &[Nsec3RecordPair<'_>],
) -> Proof {
    // 2. Name exists but there's no record of this type
    // 3. Name is serviced by wildcard that has a record of this type
    // 4. Name is serviced by wildcard that doesn't have a record of this type

    debug_assert!(!nsec3s.is_empty());
    let salt = nsec3s[0].nsec3_data.salt();
    let iterations = nsec3s[0].nsec3_data.iterations();

    let hashed_query_name = nsec3hash(query_name, salt, iterations);
    let base32_hashed_query_name = data_encoding::BASE32_DNSSEC.encode(&hashed_query_name);

    let query_name_record = nsec3s
        .iter()
        .find(|record| record.base32_hashed_name == base32_hashed_query_name.as_bytes());

    // Case 2:
    // Name exists but there's no record of this type
    if let Some(query_record) = query_name_record {
        if query_record
            .nsec3_data
            .type_bit_maps()
            .contains(&query_type)
        {
            return Proof::Bogus;
        } else {
            return Proof::Secure;
        }
    }

    match wildcard_encloser_num_labels {
        // Case 3:
        // Name is serviced by wildcard that has a record of this type
        Some(wildcard_encloser_num_labels) => {
            if query_name.num_labels() <= wildcard_encloser_num_labels {
                return Proof::Bogus;
            }
            // There should be an NSEC3 record *covering* `next_closer`
            let next_closer_labels = query_name
                .into_iter()
                .rev()
                .take(wildcard_encloser_num_labels as usize + 1)
                .rev()
                .collect::<Vec<_>>();
            let next_closer_name = Name::from_labels(next_closer_labels)
                .expect("next closer is `query_name` or its ancestor");
            let next_closer_hashed_name = nsec3hash(&next_closer_name, salt, iterations);
            let next_closer_base32_hashed_name =
                data_encoding::BASE32_DNSSEC.encode(&next_closer_hashed_name);
            let next_closer_record = find_covering_record(
                nsec3s,
                &next_closer_hashed_name,
                &next_closer_base32_hashed_name,
            );
            match next_closer_record {
                Some(_) => Proof::Secure,
                None => Proof::Bogus,
            }
        }

        // Case 4:
        // Name is serviced by wildcard that doesn't have a record of this type
        None => {
            let ClosestEncloserProofInfo {
                closest_encloser,
                next_closer,
                closest_encloser_wildcard,
            } = wildcard_based_encloser_proof(query_name, soa_name, nsec3s);
            match (closest_encloser, next_closer, closest_encloser_wildcard) {
                (Some(_), Some(_), Some(_)) => Proof::Secure,
                (None, Some(_), Some(_)) if &query_name.base_name() == soa_name => Proof::Secure,
                (None, None, None) if query_name == soa_name => Proof::Secure,
                _ => Proof::Bogus,
            }
        }
    }
}

/// Expecting the following records:
/// * closest encloser - *matching* NSEC3 record
/// * next closer - *covering* NSEC3 record
/// * wildcard of closest encloser - *matching* NSEC3 record
///     NOTE: this is the difference between this and NXDomain case
///
/// Unlike non-wildcard version this cannot produce the early `Proof`
fn wildcard_based_encloser_proof<'a>(
    query_name: &Name,
    soa_name: &Name,
    nsec3s: &'a [Nsec3RecordPair<'a>],
) -> ClosestEncloserProofInfo<'a> {
    debug_assert!(!nsec3s.is_empty());
    let salt = nsec3s[0].nsec3_data.salt();
    let iterations = nsec3s[0].nsec3_data.iterations();

    let mut closest_encloser_candidates =
        build_encloser_candidates_list(query_name, soa_name, salt, iterations);

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
        .filter(|HashedNameInfo { name, .. }| name != soa_name)
        .map(|info| {
            let wildcard = info.name.clone().into_wildcard();
            let hashed_name = nsec3hash(&wildcard, salt, iterations);
            let base32_hashed_name = data_encoding::BASE32_DNSSEC.encode(&hashed_name);
            HashedNameInfo {
                name: wildcard,
                hashed_name,
                base32_hashed_name,
            }
        })
        .collect::<Vec<_>>();

    let wildcard_encloser = wildcard_encloser_candidates
        .iter()
        .enumerate()
        .find_map(|(index, wildcard)| {
            let wildcard_nsec3 = nsec3s
                .iter()
                .find(|record| record.base32_hashed_name == wildcard.base32_hashed_name.as_bytes());
            wildcard_nsec3.map(|record| (index, record))
        })
        .map(|(index, record)| {
            let wildcard_name_info = wildcard_encloser_candidates.swap_remove(index);
            (wildcard_name_info, record)
        });

    let Some((wildcard_encloser_name_info, _)) = &wildcard_encloser else {
        return ClosestEncloserProofInfo {
            closest_encloser: None,
            next_closer: None,
            closest_encloser_wildcard: None,
        };
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
        nsec3s,
        &closest_encloser_name_info.hashed_name,
        &closest_encloser_name_info.base32_hashed_name,
    );

    // Since `closest_encloser_index` is >= 1, this is always valid.
    let next_closer_index = closest_encloser_index - 1;
    let next_closer_name_info = closest_encloser_candidates.swap_remove(next_closer_index);
    let next_closer_covering_record = find_covering_record(
        nsec3s,
        &next_closer_name_info.hashed_name,
        &next_closer_name_info.base32_hashed_name,
    );

    ClosestEncloserProofInfo {
        closest_encloser: closest_encloser_covering_record
            .map(|record| (closest_encloser_name_info, record)),
        next_closer: next_closer_covering_record.map(|record| (next_closer_name_info, record)),
        closest_encloser_wildcard: wildcard_encloser,
    }
}
