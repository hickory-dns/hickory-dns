use crate::{
    op::{Query, ResponseCode},
    rr::{
        dnssec::{rdata::NSEC3, Proof},
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

    Proof::Secure
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
