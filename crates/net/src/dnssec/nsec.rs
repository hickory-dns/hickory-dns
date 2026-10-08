use core::clone::Clone;

use tracing::debug;

use super::proof_log_yield;
use crate::proto::{
    dnssec::{Proof, rdata::NSEC},
    op::{Query, ResponseCode},
    rr::{LowerName, Name, RecordType},
};

/// Verifies NSEC records
pub(super) fn verify_nsec(
    query: &Query,
    soa_name: Option<&Name>,
    response_code: ResponseCode,
    nsecs: &[(&Name, &NSEC)],
) -> Proof {
    // TODO: consider converting this to Result, and giving explicit reason for the failure

    let nsec1_yield =
        |proof: Proof, msg: &str| -> Proof { proof_log_yield(proof, query, "nsec1", msg) };

    if response_code != ResponseCode::NXDomain && response_code != ResponseCode::NoError {
        return nsec1_yield(Proof::Bogus, "unsupported response code");
    }

    // The SOA name, if present, must be an ancestor of the query name.  If a SOA is present,
    // we'll use that as the starting value for next_closest_encloser, otherwise, fall back to
    // the parent of the query name.
    let mut next_closest_encloser = if let Some(soa_name) = soa_name {
        if !soa_name.zone_of(&query.name) {
            return nsec1_yield(Proof::Bogus, "SOA record is for the wrong zone");
        }
        soa_name.clone()
    } else {
        query.name.base_name()
    };

    // For a no data response with a directly matching NSEC record, we just need to verify the NSEC
    // type set does not contain the query type or CNAME.
    if let Some((_, nsec_data)) = nsecs.iter().find(|(name, _)| &query.name == *name) {
        let types = nsec_data.type_set();
        return if types.contains(query.query_type) || types.contains(RecordType::CNAME) {
            nsec1_yield(Proof::Bogus, "direct match, record type should be present")
        } else if query.query_type != RecordType::DS && nsec_data.is_ancestor_delegation() {
            // RFC 6840 §4.1: a parent-side NSEC at the cut only authenticates the
            // absence of DS at that owner; it cannot deny other types there.
            nsec1_yield(Proof::Bogus, "direct match is an ancestor-delegation NSEC")
        } else if query.query_type == RecordType::DS
            && nsec_data.type_set().contains(RecordType::SOA)
        {
            // RFC 4035 §5.2: "A security-aware resolver MUST use the parent NSEC RR when attempting
            // to prove that a DS RRset does not exist."
            nsec1_yield(
                Proof::Bogus,
                "direct match for DS query is an NSEC record from the child side of the zone cut",
            )
        } else if response_code == ResponseCode::NoError {
            nsec1_yield(Proof::Secure, "direct match")
        } else {
            nsec1_yield(
                Proof::Bogus,
                "nxdomain response or answers present when direct match exists",
            )
        };
    }

    let Some((covering_nsec_name, covering_nsec_data)) =
        find_nsec_covering_record(&query.name, nsecs)
    else {
        return nsec1_yield(
            Proof::Bogus,
            "no NSEC record matches or covers the query name",
        );
    };

    // RFC 4035 §3.1.3.2 / §5.4 / RFC 8020 §3.1: a next-domain below the
    // query name puts the query name on the path from owner to next, so
    // it exists as an empty non-terminal. NODATA is correct, NXDOMAIN
    // contradicts the proof. Skip the wrap-around NSEC (next is the
    // apex).
    let covering_next = covering_nsec_data.next_domain_name();
    if Some(covering_next) != soa_name && query.name.zone_of(covering_next) {
        return if response_code == ResponseCode::NXDomain {
            nsec1_yield(Proof::Bogus, "NXDOMAIN at proven empty non-terminal")
        } else {
            nsec1_yield(Proof::Secure, "empty non-terminal NODATA")
        };
    }

    // Identify the names that exist (including names of empty non terminals) that are parents of
    // the query name. Pick the longest such name, because wildcard synthesis would start looking
    // for a wildcard record there.
    for seed_name in [covering_nsec_name, covering_nsec_data.next_domain_name()] {
        let mut candidate_name = seed_name.clone();
        while candidate_name.num_labels() > next_closest_encloser.num_labels() {
            if candidate_name != query.name && candidate_name.zone_of(&query.name) {
                next_closest_encloser = candidate_name;
                break;
            }
            candidate_name = candidate_name.base_name();
        }
    }

    let Ok(wildcard_name) = next_closest_encloser.prepend_label("*") else {
        // This fails if the prepended label is invalid or if the wildcard name would be too long.
        // However, we already know that the query name is not too long. The next closest enclosing
        // name must be strictly shorter than the query name, since we know that there is no NSEC
        // record matching the query name. Thus the query name must be as long or longer than this
        // wildcard name we are trying to construct, because we removed at least one label from the
        // query name, and tried to add a single-byte label. This error condition should thus be
        // unreachable.
        return nsec1_yield(Proof::Bogus, "unreachable error constructing wildcard name");
    };

    debug!(%wildcard_name, "looking for NSEC for wildcard");

    // Identify the name of wildcard used to generate the no data response. We have to recover the
    // base name from a wildcard NSEC record as there are no answer RRSIGs present. This will be
    // used to prove that no closer matches exist between the query name and the wildcard.
    let wildcard_base_name = nsecs
        .iter()
        .filter(|(name, _)| name.is_wildcard() && name.base_name().zone_of(&query.name))
        .min_by_key(|(name, _)| name.num_labels())
        .map(|(name, _)| (*name).clone());

    match find_nsec_covering_record(&wildcard_name, nsecs) {
        // For NXDomain responses, we've already proved the record does not exist. Now we just need to prove
        // the wildcard name is covered.
        Some((_, _)) if response_code == ResponseCode::NXDomain => {
            nsec1_yield(Proof::Secure, "no direct match, no wildcard")
        }
        // For wildcard no data responses, we need to prove a wildcard matching wildcard_name does not contain
        // the requested record type and that no closer match exists. (RFC 4035 3.1.3.4 and B.7/C.7)
        None if response_code == ResponseCode::NoError
            && nsecs.iter().any(|(name, nsec_data)| {
                name == &&wildcard_name
                    && !nsec_data.type_set().contains(query.query_type)
                    && !nsec_data.type_set().contains(RecordType::CNAME)
                    && no_closer_matches(&query.name, soa_name, nsecs, wildcard_base_name.as_ref())
            }) =>
        {
            nsec1_yield(Proof::Secure, "no direct match, covering wildcard present")
        }
        _ => nsec1_yield(
            Proof::Bogus,
            "no NSEC record matches or covers the wildcard name",
        ),
    }
}

// Prove that no closer name exists between the query name and wildcard_base_name
fn no_closer_matches(
    query_name: &Name,
    soa: Option<&Name>,
    nsecs: &[(&'_ Name, &'_ NSEC)],
    wildcard_base_name: Option<&Name>,
) -> bool {
    let Some(wildcard_base_name) = wildcard_base_name else {
        return false;
    };

    // If the SOA name is present, the query name and wildcard base name must be children of it.
    if let Some(soa) = soa {
        if !soa.zone_of(wildcard_base_name) {
            debug!(%wildcard_base_name, %soa, "wildcard_base_name is not a child of SOA");
            return false;
        }

        if !soa.zone_of(query_name) {
            debug!(%query_name, %soa, "query_name is not a child of SOA");
            return false;
        }
    }

    if wildcard_base_name.num_labels() > query_name.num_labels() {
        debug!(%wildcard_base_name, %query_name, "wildcard_base_name cannot have more labels than query_name");
        return false;
    }

    // The query name must be a child of the wildcard (minus the *)
    if !wildcard_base_name.base_name().zone_of(query_name) {
        debug!(%wildcard_base_name, %query_name, "query_name is not a child of wildcard_name");
        return false;
    }

    // Verify that an appropriate proof exists for each wildcard between query.name() and wildcard_base_name.
    let mut name = query_name.base_name();
    while name.num_labels() > wildcard_base_name.num_labels() {
        let Ok(wildcard) = name.prepend_label("*") else {
            return false;
        };

        if find_nsec_covering_record(&wildcard, nsecs).is_none() {
            debug!(%wildcard, %name, ?nsecs, "covering record does not exist for name");
            return false;
        }

        name = name.base_name();
    }

    true
}

/// Find the NSEC record covering `test_name`, if any.
///
/// A zone-wrap NSEC (the last record in the zone) is detected by checking
/// that `next_domain_name <= nsec_name`, which is an intrinsic property of
/// the NSEC chain and does not depend on the SOA owner name.
fn find_nsec_covering_record<'a>(
    test_name: &Name,
    nsecs: &[(&'a Name, &'a NSEC)],
) -> Option<(&'a Name, &'a NSEC)> {
    nsecs.iter().copied().find(|(nsec_name, nsec_data)| {
        // RFC 6840 §4.1: a parent-side NSEC at the cut MUST NOT be used to
        // assume nonexistence of any name below the cut.
        if nsec_data.is_ancestor_delegation() && nsec_name.zone_of(test_name) {
            return false;
        }

        let next_domain_name = nsec_data.next_domain_name();
        test_name > nsec_name
            && (test_name < next_domain_name
                || next_domain_name <= nsec_name && next_domain_name.zone_of(test_name))
    })
}

/// All NSEC records in a response from one zone.
pub(super) struct ZoneNsecRecords {
    zone: Name,
    records: Vec<NsecPair>,
}

impl ZoneNsecRecords {
    /// Construct a new container for a zone, initialized with no NSEC records.
    pub(super) fn new(zone: Name) -> Self {
        Self {
            zone,
            records: Vec::new(),
        }
    }

    /// Add an NSEC record.
    pub(super) fn push(&mut self, name: LowerName, rdata: NSEC) {
        self.records.push(NsecPair { name, rdata })
    }

    /// Returns the NSEC record covering this name, if any.
    pub(super) fn find_covering_record(&self, name: &LowerName) -> Option<&NsecPair> {
        if !self.zone.zone_of(name) {
            return None;
        }
        self.records.iter().find(|nsec| nsec.covers(name))
    }
}

/// The name and RDATA of an NSEC record.
pub(super) struct NsecPair {
    /// The owner name of the NSEC record.
    pub(super) name: LowerName,
    /// The RDATA of the NSEC record.
    pub(super) rdata: NSEC,
}

impl NsecPair {
    /// Checks whether this NSEC record covers a name.
    pub(super) fn covers(&self, name: &LowerName) -> bool {
        // RFC 6840 §4.1: a parent-side NSEC at the cut MUST NOT be used to
        // assume nonexistence of any name below the cut.
        if self.rdata.is_ancestor_delegation() && self.name.zone_of(name) {
            return false;
        }

        let next_domain_name = self.rdata.next_domain_name();
        *name > self.name
            && (&**name < next_domain_name
                || next_domain_name <= &self.name && next_domain_name.zone_of(name))
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::{
        dnssec::{Proof, test::test_verify_wildcard_expansion},
        proto::{
            ProtoError,
            dnssec::{
                Algorithm,
                rdata::{DNSSECRData, NSEC as rdataNSEC, RRSIG as rdataRRSIG, SigInput},
            },
            op::{Query, ResponseCode},
            rr::{
                Name, RData, Record,
                RecordType::{A, AAAA, DNSKEY, DS, MX, NS, NSEC, RRSIG, SOA, TXT},
                SerialNumber, rdata,
            },
        },
    };

    use test_support::subscribe;

    #[test]
    fn test_no_closer_matches() -> Result<(), ProtoError> {
        subscribe();

        assert!(no_closer_matches(
            &Name::from_ascii("a.a.a.z.w.example")?,
            Some(&Name::from_ascii("example.")?),
            &[
                // This NSEC encloses the query name and proves that no closer wildcard match
                // exists in the zone.
                (
                    &Name::from_ascii("x.y.w.example.")?,
                    &rdataNSEC::new(Name::from_ascii("xx.example.")?, [MX, NSEC, RRSIG],),
                ),
            ],
            Some(&Name::from_ascii("*.w.example.")?),
        ),);

        assert!(!no_closer_matches(
            &Name::from_ascii("a.a.a.z.w.example")?,
            Some(&Name::from_ascii("example.")?),
            &[
                // This doesn't prove the non-existence of the closer wildcard
                (
                    &Name::from_ascii("*.w.example.")?,
                    &rdataNSEC::new(Name::from_ascii("z.w.example.")?, [MX, NSEC, RRSIG],),
                ),
            ],
            Some(&Name::from_ascii("*.w.example.")?),
        ),);

        assert!(!no_closer_matches(
            &Name::from_ascii("a.a.a.z.w.example")?,
            Some(&Name::from_ascii("example.")?),
            &[(
                &Name::from_ascii("x.y.w.example.")?,
                &rdataNSEC::new(Name::from_ascii("xx.example.")?, [MX, NSEC, RRSIG],),
            ),],
            // no_closer_matches requires a wildcard base name be present
            None,
        ),);

        // SOA mismatch
        assert!(!no_closer_matches(
            &Name::from_ascii("a.a.a.z.w.example")?,
            Some(&Name::from_ascii("z.example.")?),
            &[
                // This NSEC encloses the query name and proves that no closer wildcard match
                // exists in the zone.
                (
                    &Name::from_ascii("x.y.w.example.")?,
                    &rdataNSEC::new(Name::from_ascii("xx.example.")?, [MX, NSEC, RRSIG],),
                ),
                // This NSEC proves the requested record type does not exist at the wildcard
                (
                    &Name::from_ascii("*.w.example.")?,
                    &rdataNSEC::new(Name::from_ascii("xw.example.")?, [MX, NSEC, RRSIG],),
                ),
            ],
            Some(&Name::from_ascii("*.w.example.")?),
        ),);

        // Irrelevant wildcard.
        assert!(!no_closer_matches(
            &Name::from_ascii("a.a.a.z.w.example")?,
            Some(&Name::from_ascii("example.")?),
            &[
                // This NSEC encloses the query name and proves that no closer wildcard match
                // exists in the zone.
                (
                    &Name::from_ascii("x.y.w.example.")?,
                    &rdataNSEC::new(Name::from_ascii("xx.example.")?, [MX, NSEC, RRSIG],),
                ),
                // This NSEC proves the requested record type does not exist at the wildcard
                (
                    &Name::from_ascii("*.x.example.")?,
                    &rdataNSEC::new(Name::from_ascii("xw.example.")?, [MX, NSEC, RRSIG],),
                ),
            ],
            Some(&Name::from_ascii("*.x.example.")?),
        ),);

        Ok(())
    }

    // These test cases prove a name does not exist
    #[test]
    fn nsec_name_error() -> Result<(), ProtoError> {
        subscribe();

        // Based on RFC 4035 B.2 - Name Error
        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("ml.example.")?, A),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NXDomain,
                &[
                    // This NSEC encloses the query name and proves the record does not exist.
                    (
                        &Name::from_ascii("b.example.")?,
                        &rdataNSEC::new(Name::from_ascii("ns1.example.")?, [NS, RRSIG, NSEC],),
                    ),
                    // This NSEC proves no covering wildcard record exists (i.e., it encloses
                    // *.example. and thus proves that record does not exist.)
                    (
                        &Name::from_ascii("example.")?,
                        &rdataNSEC::new(
                            Name::from_ascii("a.example.")?,
                            [DNSKEY, MX, NS, NSEC, RRSIG, SOA],
                        ),
                    )
                ],
            ),
            Proof::Secure
        );

        // Single NSEC that proves the record does not exist, and no covering wildcard exists.
        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("a.example.")?, A),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NXDomain,
                &[(
                    &Name::from_ascii("example.")?,
                    &rdataNSEC::new(Name::from_ascii("c.example.")?, [SOA, NS, RRSIG, NSEC],),
                ),],
            ),
            Proof::Secure
        );

        Ok(())
    }

    /// Ensure invalid name error NSEC scenarios fail
    #[test]
    fn nsec_invalid_name_error() -> Result<(), ProtoError> {
        subscribe();
        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("ml.example.")?, A),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NXDomain,
                &[
                    // This NSEC does not enclose the query name and so should cause this
                    // verification to fail
                    (
                        &Name::from_ascii("ml.example.")?,
                        &rdataNSEC::new(Name::from_ascii("ns1.example.")?, [NS, RRSIG, NSEC],),
                    ),
                    // This NSEC proves no covering wildcard record exists (i.e., it encloses
                    // *.example. and thus proves that record does not exist.)
                    (
                        &Name::from_ascii("example.")?,
                        &rdataNSEC::new(
                            Name::from_ascii("a.example.")?,
                            [DNSKEY, MX, NS, NSEC, RRSIG, SOA],
                        ),
                    )
                ],
            ),
            Proof::Bogus
        );

        // Test without proving wildcard non-existence.
        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("ml.example.")?, A),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NXDomain,
                &[
                    // This NSEC encloses the query name and proves the record does not exist.
                    (
                        &Name::from_ascii("ml.example.")?,
                        &rdataNSEC::new(Name::from_ascii("ns1.example.")?, [NS, RRSIG, NSEC],),
                    ),
                ],
            ),
            Proof::Bogus
        );

        // Invalid SOA
        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("ml.example.")?, A),
                Some(&Name::from_ascii("example2.")?),
                ResponseCode::NXDomain,
                &[
                    // This NSEC encloses the query name and proves the record does not exist.
                    (
                        &Name::from_ascii("b.example.")?,
                        &rdataNSEC::new(Name::from_ascii("ns1.example.")?, [NS, RRSIG, NSEC],),
                    ),
                    // This NSEC proves no covering wildcard record exists (i.e., it encloses
                    // *.example. and thus proves that record does not exist.)
                    (
                        &Name::from_ascii("example.")?,
                        &rdataNSEC::new(
                            Name::from_ascii("a.example.")?,
                            [DNSKEY, MX, NS, NSEC, RRSIG, SOA],
                        ),
                    )
                ],
            ),
            Proof::Bogus
        );

        Ok(())
    }

    // RFC 6840 §4.1: an ancestor-delegation NSEC at a zone cut (parent-side, with NS set
    // and SOA clear) MUST NOT be used to prove nonexistence of any name strictly below
    // that cut. The signer is the parent and the only authenticated denial it can carry is
    // for DS at the cut owner itself.
    #[test]
    fn nsec_invalid_ancestor_delegation_nxdomain() -> Result<(), ProtoError> {
        subscribe();

        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("www.deleg.")?, A),
                Some(&Name::root()),
                ResponseCode::NXDomain,
                &[
                    // Parent-side ancestor-delegation NSEC at the zone cut.
                    (
                        &Name::from_ascii("deleg.")?,
                        &rdataNSEC::new(Name::from_ascii("honest.")?, [NS, DS, RRSIG, NSEC],),
                    ),
                    // Root NSEC covering `*.` (the slot where a wildcard at the
                    // root would live), used here to attempt to prove that no
                    // wildcard at the parent could synthesize the answer.
                    (
                        &Name::root(),
                        &rdataNSEC::new(
                            Name::from_ascii("deleg.")?,
                            [NS, SOA, RRSIG, NSEC, DNSKEY],
                        ),
                    ),
                ],
            ),
            Proof::Bogus
        );

        // NODATA at the cut owner itself: the same parent-side NSEC must not
        // authenticate the absence of any type other than DS at `deleg.`.
        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("deleg.")?, A),
                Some(&Name::root()),
                ResponseCode::NoError,
                &[(
                    &Name::from_ascii("deleg.")?,
                    &rdataNSEC::new(Name::from_ascii("honest.")?, [NS, DS, RRSIG, NSEC],),
                )],
            ),
            Proof::Bogus
        );

        // RFC 6840 §4.1 exception: the parent-side NSEC at the cut DOES
        // authenticate the absence of DS at the cut owner. This is the only
        // legitimate use of this NSEC and must continue to validate.
        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("insecure-deleg.")?, DS),
                Some(&Name::root()),
                ResponseCode::NoError,
                &[(
                    &Name::from_ascii("insecure-deleg.")?,
                    &rdataNSEC::new(Name::from_ascii("next.")?, [NS, RRSIG, NSEC],),
                )],
            ),
            Proof::Secure
        );

        Ok(())
    }

    // RFC 4035 §3.1.3.2 / §5.4 / RFC 8020 §3.1: an NSEC whose Next Domain
    // Name is a strict descendant of the query name proves that the query
    // name exists as an empty non-terminal (ENT). Such an NSEC must not
    // authenticate NXDOMAIN at the query name. The correct rcode is
    // NOERROR/NODATA.
    #[test]
    fn nsec_invalid_empty_non_terminal_nxdomain() -> Result<(), ProtoError> {
        subscribe();

        // Single-label ENT covered by the apex NSEC.
        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("b.poc.")?, TXT),
                Some(&Name::from_ascii("poc.")?),
                ResponseCode::NXDomain,
                &[(
                    &Name::from_ascii("poc.")?,
                    &rdataNSEC::new(
                        Name::from_ascii("a.b.poc.")?,
                        [NS, SOA, TXT, RRSIG, NSEC, DNSKEY],
                    ),
                )],
            ),
            Proof::Bogus
        );

        // Deeper ENT covered by a mid-zone NSEC.
        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("y.z.poc.")?, TXT),
                Some(&Name::from_ascii("poc.")?),
                ResponseCode::NXDomain,
                &[(
                    &Name::from_ascii("z.poc.")?,
                    &rdataNSEC::new(Name::from_ascii("x.y.z.poc.")?, [TXT, RRSIG, NSEC],),
                )],
            ),
            Proof::Bogus
        );

        // Single-label ENT covered by a non-apex NSEC.
        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("b.poc.")?, TXT),
                Some(&Name::from_ascii("poc.")?),
                ResponseCode::NXDomain,
                &[(
                    &Name::from_ascii("a.poc.")?,
                    &rdataNSEC::new(Name::from_ascii("c.b.poc.")?, [TXT, RRSIG, NSEC],),
                )],
            ),
            Proof::Bogus
        );

        // Same proof shape with rcode=NoError is the legitimate ENT NODATA
        // response per RFC 8020 §3.1 and must validate.
        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("b.poc.")?, TXT),
                Some(&Name::from_ascii("poc.")?),
                ResponseCode::NoError,
                &[(
                    &Name::from_ascii("poc.")?,
                    &rdataNSEC::new(
                        Name::from_ascii("a.b.poc.")?,
                        [NS, SOA, TXT, RRSIG, NSEC, DNSKEY],
                    ),
                )],
            ),
            Proof::Secure
        );

        // Deeper ENT NODATA companion.
        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("y.z.poc.")?, TXT),
                Some(&Name::from_ascii("poc.")?),
                ResponseCode::NoError,
                &[(
                    &Name::from_ascii("z.poc.")?,
                    &rdataNSEC::new(Name::from_ascii("x.y.z.poc.")?, [TXT, RRSIG, NSEC],),
                )],
            ),
            Proof::Secure
        );

        // True NXDOMAIN with a sibling next-domain must remain Secure.
        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("b.poc.")?, TXT),
                Some(&Name::from_ascii("poc.")?),
                ResponseCode::NXDomain,
                &[
                    (
                        &Name::from_ascii("a.poc.")?,
                        &rdataNSEC::new(Name::from_ascii("c.poc.")?, [TXT, RRSIG, NSEC],),
                    ),
                    // Apex NSEC covering `*.poc.` to rule out a wildcard.
                    (
                        &Name::from_ascii("poc.")?,
                        &rdataNSEC::new(
                            Name::from_ascii("a.poc.")?,
                            [NS, SOA, RRSIG, NSEC, DNSKEY],
                        ),
                    ),
                ],
            ),
            Proof::Secure
        );

        // Ancestor-delegation NSEC (NS set, SOA clear) at `a.poc.` marks an
        // insecure delegation at a sibling of the ENT. Its signer is the
        // parent zone `poc.`, and a next-domain of `c.b.poc.` proves that
        // `b.poc.` exists as an ENT in `poc.`. RFC 6840 §4.1 only forbids
        // using this NSEC to deny names below the cut at `a.poc.`; using it
        // to prove ENT existence at the sibling `b.poc.` is legitimate.
        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("b.poc.")?, TXT),
                Some(&Name::from_ascii("poc.")?),
                ResponseCode::NoError,
                &[(
                    &Name::from_ascii("a.poc.")?,
                    &rdataNSEC::new(Name::from_ascii("c.b.poc.")?, [NS, RRSIG, NSEC],),
                )],
            ),
            Proof::Secure
        );

        // Same shape under NXDOMAIN: the rcode contradicts the proof that
        // `b.poc.` exists, so the validator must reject as Bogus regardless
        // of the covering NSEC's ancestor-delegation flag.
        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("b.poc.")?, TXT),
                Some(&Name::from_ascii("poc.")?),
                ResponseCode::NXDomain,
                &[(
                    &Name::from_ascii("a.poc.")?,
                    &rdataNSEC::new(Name::from_ascii("c.b.poc.")?, [NS, RRSIG, NSEC],),
                )],
            ),
            Proof::Bogus
        );

        // A NoError response with answer records must not short-circuit to
        // Secure based on an ENT-shaped NSEC alone. Wildcard expansion
        // requires the full closest-encloser proof.
        let input = SigInput {
            type_covered: TXT,
            algorithm: Algorithm::ED25519,
            num_labels: 1,
            original_ttl: 3600,
            sig_expiration: SerialNumber::new(0),
            sig_inception: SerialNumber::new(0),
            key_tag: 0,
            signer_name: Name::root(),
        };
        let rrsig = rdataRRSIG::from_sig(input, vec![]);
        let mut rrsig_record = Record::from_rdata(
            Name::from_ascii("b.poc.")?,
            3600,
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
        );
        rrsig_record.proof = Proof::Secure;
        let answers = [
            Record::from_rdata(
                Name::from_ascii("b.poc.")?,
                3600,
                RData::TXT(rdata::TXT::new([b"forged".to_vec()].into_iter()).unwrap()),
            ),
            rrsig_record,
        ];
        assert!(!test_verify_wildcard_expansion(
            &answers,
            &make_nsec_and_rrsig(
                Name::from_ascii("poc.")?,
                Name::from_ascii("a.b.poc.")?,
                [NS, SOA, TXT, RRSIG, NSEC, DNSKEY],
                Name::root(),
            ),
        ));

        // Wrap-around NSEC where next-domain is the SOA owner. The SOA is
        // an ancestor of every name in the zone, so this case must be
        // excluded from the ENT check.
        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("zzz.poc.")?, TXT),
                Some(&Name::from_ascii("poc.")?),
                ResponseCode::NXDomain,
                &[
                    (
                        &Name::from_ascii("last.poc.")?,
                        &rdataNSEC::new(Name::from_ascii("poc.")?, [TXT, RRSIG, NSEC],),
                    ),
                    // Apex NSEC covering `*.poc.` to rule out a wildcard.
                    (
                        &Name::from_ascii("poc.")?,
                        &rdataNSEC::new(
                            Name::from_ascii("a.poc.")?,
                            [NS, SOA, RRSIG, NSEC, DNSKEY],
                        ),
                    ),
                ],
            ),
            Proof::Secure
        );

        Ok(())
    }

    // These test cases prove that the requested record type does not exist at the query name
    #[test]
    fn nsec_no_data_error() -> Result<(), ProtoError> {
        subscribe();

        // Based on RFC 4035 B.3 - No Data Error
        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("ns1.example.")?, MX),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[
                    // This NSEC encloses the query name and proves the record does exist, but
                    // the requested record type does not.
                    (
                        &Name::from_ascii("ns1.example.")?,
                        &rdataNSEC::new(Name::from_ascii("ns2.example.")?, [A, NSEC, RRSIG],),
                    ),
                ],
            ),
            Proof::Secure
        );

        // Record type at the SOA does not exist.
        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("example.")?, MX),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[
                    // This NSEC encloses the query name and proves the record does exist, but
                    // the requested record type does not.
                    (
                        &Name::from_ascii("example.")?,
                        &rdataNSEC::new(Name::from_ascii("a.example.")?, [A, NSEC, RRSIG, SOA],),
                    ),
                ],
            ),
            Proof::Secure
        );

        Ok(())
    }

    // Ensure invalid no data NSEC scenarios fails
    #[test]
    fn nsec_invalid_no_data_error() -> Result<(), ProtoError> {
        subscribe();

        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("ns1.example.")?, MX),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[
                    // This NSEC claims the requested record type DOES exist at ns1.example.
                    (
                        &Name::from_ascii("ns1.example.")?,
                        &rdataNSEC::new(Name::from_ascii("ns2.example.")?, [A, NSEC, RRSIG, MX],),
                    ),
                ],
            ),
            Proof::Bogus
        );

        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("ns1.example.")?, MX),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[
                    // In this case, the response indicates *some* record exists at ns1.example., just not an
                    // MX record. This NSEC claims ns1.example. does not exist at all.
                    (
                        &Name::from_ascii("ml.example.")?,
                        &rdataNSEC::new(Name::from_ascii("ns2.example.")?, [A, NSEC, RRSIG],),
                    ),
                ],
            ),
            Proof::Bogus
        );

        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("ns1.example.")?, MX),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[
                    // This NSEC claims nothing exists from the SOA to ns2.example.
                    (
                        &Name::from_ascii("example.")?,
                        &rdataNSEC::new(Name::from_ascii("ns2.example.")?, [A, NSEC, RRSIG],),
                    ),
                ],
            ),
            Proof::Bogus
        );

        Ok(())
    }

    // Ensure that positive answers expanded from wildcards pass validation
    #[test]
    fn nsec_wildcard_expansion() -> Result<(), ProtoError> {
        subscribe();

        let input = SigInput {
            type_covered: MX,
            algorithm: Algorithm::ED25519,
            num_labels: 2,
            original_ttl: 3600,
            sig_expiration: SerialNumber::new(0),
            sig_inception: SerialNumber::new(0),
            key_tag: 0,
            signer_name: Name::from_ascii("example.")?,
        };

        let rrsig = rdataRRSIG::from_sig(input, vec![]);
        let mut rrsig_record = Record::from_rdata(
            Name::from_ascii("a.z.w.example.")?,
            3600,
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
        );
        rrsig_record.proof = Proof::Secure;

        let answers = [
            Record::from_rdata(
                Name::from_ascii("a.z.w.example.")?,
                3600,
                RData::MX(rdata::MX::new(10, Name::from_ascii("a.z.w.example.")?)),
            ),
            rrsig_record,
        ];

        // Based on RFC 4035 B.6 - Wildcard Expansion
        assert!(test_verify_wildcard_expansion(
            &answers,
            // This NSEC record encloses the query name and proves that no closer wildcard match
            // exists in the zone.
            &make_nsec_and_rrsig(
                Name::from_ascii("x.y.w.example.")?,
                Name::from_ascii("xx.example.")?,
                [MX, NSEC, RRSIG],
                Name::from_ascii("example.")?,
            ),
        ));

        // This response doesn't include an appropriate NSEC record.
        assert!(!test_verify_wildcard_expansion(
            &answers,
            &[
                // This NSEC record is entirely after w.example.
                make_nsec_and_rrsig(
                    Name::from_ascii("y.example.")?,
                    Name::from_ascii("example.")?,
                    [A, NSEC, RRSIG],
                    Name::from_ascii("example.")?,
                )
                .as_slice(),
                // This NSEC record is entirely before w.example.
                make_nsec_and_rrsig(
                    Name::from_ascii("example.")?,
                    Name::from_ascii("a.example.")?,
                    [MX, NS, NSEC, RRSIG, SOA],
                    Name::from_ascii("example.")?,
                )
                .as_slice(),
            ]
            .join([].as_slice()),
        ));

        Ok(())
    }

    // Ensure that defective wildcard expansion positive answer scenarios fail validation
    #[test]
    fn nsec_invalid_wildcard_expansion() -> Result<(), ProtoError> {
        subscribe();

        let input = SigInput {
            type_covered: MX,
            algorithm: Algorithm::ED25519,
            num_labels: 2,
            original_ttl: 0,
            sig_expiration: SerialNumber::new(0),
            sig_inception: SerialNumber::new(0),
            key_tag: 0,
            signer_name: Name::from_ascii("example.")?,
        };

        let rrsig = rdataRRSIG::from_sig(input, vec![]);
        let mut rrsig_record = Record::from_rdata(
            Name::from_ascii("a.z.w.example.")?,
            3600,
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
        );
        rrsig_record.proof = Proof::Secure;

        let answers = [
            Record::from_rdata(
                Name::from_ascii("a.z.w.example.")?,
                3600,
                RData::MX(rdata::MX::new(10, Name::from_ascii("a.z.w.example.")?)),
            ),
            rrsig_record,
        ];

        assert!(!test_verify_wildcard_expansion(
            &answers,
            // This NSEC record does not prove the non-existence of z.w.example.
            &make_nsec_and_rrsig(
                Name::from_ascii("x.y.w.example.")?,
                Name::from_ascii("z.w.example.")?,
                [MX, NSEC, RRSIG],
                Name::from_ascii("example.")?,
            ),
        ));

        assert!(!test_verify_wildcard_expansion(&answers, &[]));

        Ok(())
    }

    /// Helper function to produce NSEC and RRSIG records.
    fn make_nsec_and_rrsig(
        name: Name,
        next_name: Name,
        record_types: impl IntoIterator<Item = RecordType>,
        signer_name: Name,
    ) -> [Record; 2] {
        [
            Record::from_rdata(
                name.clone(),
                3600,
                RData::DNSSEC(DNSSECRData::NSEC(rdataNSEC::new(next_name, record_types))),
            ),
            Record::from_rdata(
                name.clone(),
                3600,
                RData::DNSSEC(DNSSECRData::RRSIG(rdataRRSIG::from_sig(
                    SigInput {
                        type_covered: NSEC,
                        algorithm: Algorithm::ED25519,
                        num_labels: name.num_labels(),
                        original_ttl: 3600,
                        sig_expiration: SerialNumber::new(0),
                        sig_inception: SerialNumber::new(0),
                        key_tag: 0,
                        signer_name,
                    },
                    Vec::new(),
                ))),
            ),
        ]
    }

    #[test]
    fn nsec_wildcard_no_data_error() -> Result<(), ProtoError> {
        subscribe();

        // Based on RFC 4035 B.7 - Wildcard No Data Error
        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("a.z.w.example.")?, AAAA),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[
                    // This NSEC encloses the query name and proves that no closer wildcard match
                    // exists in the zone.
                    (
                        &Name::from_ascii("x.y.w.example.")?,
                        &rdataNSEC::new(Name::from_ascii("xx.example.")?, [MX, NSEC, RRSIG],),
                    ),
                    // This NSEC proves the requested record type does not exist at the wildcard
                    (
                        &Name::from_ascii("*.w.example.")?,
                        &rdataNSEC::new(Name::from_ascii("xw.example.")?, [MX, NSEC, RRSIG],),
                    ),
                ],
            ),
            Proof::Secure
        );

        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("zzzzzz.hickory-dns.testing.")?, TXT),
                Some(&Name::from_ascii("hickory-dns.testing.")?),
                ResponseCode::NoError,
                &[
                    // This NSEC proves zzzzzz.hickory-dns.testing. does not exist.
                    (
                        &Name::from_ascii("record.hickory-dns.testing.")?,
                        &rdataNSEC::new(
                            Name::from_ascii("hickory-dns.testing.")?,
                            [A, NSEC, RRSIG],
                        ),
                    ),
                    // This NSEC proves a wildcard does exist at *.hickory-dns.testing. but does not contain the
                    // requested record type.
                    (
                        &Name::from_ascii("*.hickory-dns.testing.")?,
                        &rdataNSEC::new(
                            Name::from_ascii("primary0.hickory-dns.testing.")?,
                            [A, NSEC, RRSIG],
                        ),
                    ),
                ],
            ),
            Proof::Secure
        );

        Ok(())
    }

    #[test]
    fn nsec_invalid_wildcard_no_data_error() -> Result<(), ProtoError> {
        subscribe();

        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("a.z.w.example.")?, AAAA),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[
                    // This NSEC doesn't prove the non-existence of the query name
                    (
                        &Name::from_ascii("x.y.w.example.")?,
                        &rdataNSEC::new(Name::from_ascii("z.w.example.")?, [MX, NSEC, RRSIG],),
                    ),
                    // This NSEC proves the wildcard does not contain the requested record type
                    (
                        &Name::from_ascii("*.w.example.")?,
                        &rdataNSEC::new(Name::from_ascii("x.y.w.example.")?, [MX, NSEC, RRSIG],),
                    ),
                ],
            ),
            Proof::Bogus
        );

        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("a.z.w.example.")?, AAAA),
                Some(&Name::from_ascii("example.")?),
                ResponseCode::NoError,
                &[
                    // This NSEC proves the query name does not exist
                    (
                        &Name::from_ascii("x.y.w.example.")?,
                        &rdataNSEC::new(Name::from_ascii("xx.example.")?, [MX, NSEC, RRSIG],),
                    ),
                    // This NSEC proves the requested record type exists at the wildcard
                    (
                        &Name::from_ascii("*.w.example.")?,
                        &rdataNSEC::new(Name::from_ascii("xw.example.")?, [AAAA, MX, NSEC, RRSIG],),
                    ),
                ],
            ),
            Proof::Bogus
        );

        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("r.hickory-dns.testing.")?, TXT),
                Some(&Name::from_ascii("hickory-dns.testing.")?),
                ResponseCode::NoError,
                &[
                    // There is no NSEC proving the non-existence of r.hickory-dns.testing.

                    // This NSEC proves a wildcard does exist at *.hickory-dns.testing. but does not contain the
                    // requested record type.
                    (
                        &Name::from_ascii("*.hickory-dns.testing.")?,
                        &rdataNSEC::new(
                            Name::from_ascii("primary0.hickory-dns.testing.")?,
                            [A, NSEC, RRSIG],
                        ),
                    ),
                ],
            ),
            Proof::Bogus
        );

        Ok(())
    }

    /// Zone-wrap NSEC detection uses the intrinsic `next <= owner` property
    /// instead of relying on the SOA owner name.
    #[test]
    fn find_nsec_covering_record_zone_wrap() -> Result<(), ProtoError> {
        // A zone-wrap NSEC: last record in the zone points back to the zone apex.
        // `record.example. NSEC example.` covers everything > record.example.
        let nsec_name = Name::from_ascii("record.example.")?;
        let nsec_data = rdataNSEC::new(Name::from_ascii("example.")?, [A, NSEC, RRSIG]);
        let nsecs = [(&nsec_name, &nsec_data)];

        // A name canonically after the NSEC owner should be covered by the wrap.
        let covered = Name::from_ascii("zzzz.example.")?;
        assert!(find_nsec_covering_record(&covered, &nsecs).is_some());

        // A name canonically before the NSEC owner should NOT be covered.
        let not_covered = Name::from_ascii("aaa.example.")?;
        assert!(find_nsec_covering_record(&not_covered, &nsecs).is_none());

        Ok(())
    }

    /// Confirm that a wraparound NSEC record from a different zone won't be accepted as a covering
    /// NSEC record.
    #[test]
    fn find_nsec_covering_record_unrelated_zone() -> Result<(), ProtoError> {
        subscribe();
        // A zone-wrap NSEC record from a different zone.
        let nsecs = [(
            &Name::from_ascii("record.aaaaaa.")?,
            &rdataNSEC::new(Name::from_ascii("aaaaaa.")?, [A, NSEC, RRSIG]),
        )];

        // This should fail to find a covering record since the the NSEC record and the target name
        // are in different zones.
        assert_eq!(
            find_nsec_covering_record(&Name::from_ascii("zzzz.example.")?, &nsecs),
            None
        );

        Ok(())
    }

    /// Regression test for forged-SOA NXDOMAIN attack.
    ///
    /// An attacker harvests a legitimate signed NSEC `a.zone. -> b.zone.` and
    /// forges an unsigned SOA with owner `b.zone.` (the NSEC's next field).
    /// The old code would treat the gap NSEC as the zone-wrap record because
    /// `next == soa_name`, accepting the forged denial. The fix detects wrap
    /// via `next <= owner` which is false for `b > a`, so the NSEC does NOT
    /// cover the target and the proof must be Bogus.
    #[test]
    fn forged_soa_nxdomain_attack() -> Result<(), ProtoError> {
        subscribe();

        // Attacker-replayed NSEC: a.zone.test. -> b.zone.test.
        // This is NOT a zone-wrap NSEC because b > a.
        let nsec_name = Name::from_ascii("a.zone.test.")?;
        let nsec_data = rdataNSEC::new(Name::from_ascii("b.zone.test.")?, [A, NSEC, RRSIG]);
        let nsecs = [(&nsec_name, &nsec_data)];

        // Target: target.zone.test. (canonically > b.zone.test.)
        // The forged SOA has owner b.zone.test., so old code would match.
        // With the fix, this NSEC does not cover the target.
        let target = Name::from_ascii("target.zone.test.")?;
        assert!(find_nsec_covering_record(&target, &nsecs).is_none());

        // Full verify_nsec must also reject the forged denial.
        // The attacker's forged SOA at b.zone.test. is not Proof::Secure,
        // so find_soa_name won't return it. Even passing the forged SOA name
        // directly, the proof should be Bogus.
        assert_eq!(
            verify_nsec(
                &Query::new(Name::from_ascii("target.zone.test.")?, A),
                Some(&Name::from_ascii("b.zone.test.")?),
                ResponseCode::NXDomain,
                &[(&nsec_name, &nsec_data)],
            ),
            Proof::Bogus
        );

        Ok(())
    }

    /// Ensure that the forged-SOA attack also fails for wildcard coverage.
    #[test]
    fn forged_soa_wildcard_attack() -> Result<(), ProtoError> {
        subscribe();

        // The attacker uses the same NSEC a.zone.test. -> b.zone.test. and
        // a forged SOA at b.zone.test. to try to prove wildcard non-existence.
        let nsec_name = Name::from_ascii("a.zone.test.")?;
        let nsec_data = rdataNSEC::new(Name::from_ascii("b.zone.test.")?, [A, NSEC, RRSIG]);
        let nsecs = [(&nsec_name, &nsec_data)];

        // *.zone.test. is canonically > b.zone.test. so the old code would
        // have treated the NSEC as covering it via the forged SOA match.
        let wildcard = Name::from_ascii("*.zone.test.")?;
        assert!(find_nsec_covering_record(&wildcard, &nsecs).is_none());

        Ok(())
    }

    /// Regression test for GHSA-896p-wpw8-vf4r.
    ///
    /// This scenario involves a parent zone with a wildcard record, a child zone with a wildcard
    /// record, and a network attacker that combines records retrieved from both name servers. The
    /// response claims to be a wildcard expansion of the parent zone's wildcard record, for a query
    /// that should instead have its response expanded from the child zone's wildcard record. It
    /// includes the NSEC record from the parent that is at the delegation point to the child zone.
    /// The issue was that the verifier accepted this NSEC record as a purported proof the child
    /// zone's wildcard record doesn't exist, though it can't prove anything about names directly
    /// descended from the delegation point.
    ///
    /// Parent zone:
    ///
    /// ```text
    /// com. SOA ...
    /// com. NS ...
    /// com. NSEC *.com. NS SOA RRSIG NSEC
    /// com. RRSIG SOA ...
    /// com. RRSIG NS ...
    /// com. RRSIG NSEC ...
    /// *.com. A 192.0.2.1
    /// *.com. NSEC example.com. A RRSIG NSEC
    /// *.com. RRSIG A ...
    /// *.com. RRSIG NSEC ...
    /// example.com. NS ...
    /// example.com. DS ...
    /// example.com. NSEC foobar.com. NS DS RRSIG NSEC
    /// example.com. RRSIG DS ...
    /// example.com. RRSIG NSEC ...
    /// foobar.com. NS ...
    /// foobar.com. NSEC com. NS RRSIG NSEC
    /// foobar.com. RRSIG NSEC ...
    /// ```
    ///
    /// Child zone:
    ///
    /// ```text
    /// example.com. SOA ...
    /// example.com. NS ...
    /// example.com. NSEC *.example.com. NS SOA RRSIG NSEC
    /// example.com. RRSIG SOA ...
    /// example.com. RRSIG NSEC ...
    /// *.example.com. A 192.0.2.2
    /// *.example.com. NSEC example.com. A RRSIG NSEC
    /// *.example.com. RRSIG A ...
    /// *.example.com. RRSIG NSEC ...
    /// ```
    #[test]
    fn nsec_invalid_wildcard_expansion_parent_nsec_record() -> Result<(), ProtoError> {
        subscribe();

        let parent_zone = Name::parse("com.", None)?;
        let child_zone = Name::parse("example.com.", None)?;
        let qname = Name::parse("www.example.com.", None)?;
        let answers = [
            mark_secure(Record::from_rdata(
                qname.clone(),
                0,
                RData::A(Ipv4Addr::new(192, 0, 2, 1).into()),
            )),
            mark_secure(Record::from_rdata(
                qname.clone(),
                0,
                RData::DNSSEC(DNSSECRData::RRSIG(rdataRRSIG::from_sig(
                    SigInput {
                        type_covered: A,
                        algorithm: Algorithm::ECDSAP256SHA256,
                        num_labels: 1, // expanded from *.com.
                        original_ttl: 0,
                        sig_expiration: 0.into(),
                        sig_inception: 0.into(),
                        key_tag: 0,
                        signer_name: parent_zone.clone(),
                    },
                    Vec::new(),
                ))),
            )),
        ];
        // Both of these NSEC records are taken from the parent zone.
        let authorities = [
            // Matching record for com.
            make_nsec_and_rrsig(
                parent_zone.clone(),
                Name::parse("*.com.", None)?,
                [NS, SOA, RRSIG, NSEC],
                parent_zone.clone(),
            )
            .as_slice(),
            // Bogus proof of nonexistence of *.example.com.
            make_nsec_and_rrsig(
                child_zone,
                Name::parse("foobar.com.", None)?,
                [NS, DS, RRSIG, NSEC],
                parent_zone.clone(),
            )
            .as_slice(),
        ]
        .join([].as_slice());

        assert!(!test_verify_wildcard_expansion(&answers, &authorities));

        Ok(())
    }

    /// Set the proof on a record to Secure and return it.
    fn mark_secure(mut record: Record) -> Record {
        record.proof = Proof::Secure;
        record
    }
}
