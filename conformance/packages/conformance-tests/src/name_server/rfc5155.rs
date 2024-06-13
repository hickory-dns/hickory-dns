use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use dns_test::client::{Client, DigSettings, DigStatus};
use dns_test::name_server::NameServer;
use dns_test::record::{Record, RecordType, NSEC3};
use dns_test::{Network, Result, FQDN};

///  An NSEC3 RR is said to "match" a name if the owner name of the NSEC3 RR is the same as the
///  hashed owner name of that name.
fn find_match<'a>(name_hash: &str, records: &'a BTreeMap<String, NSEC3>) -> Option<&'a NSEC3> {
    records.get(name_hash)
}

/// An NSEC3 RR is said to cover a name if the hash of the name or "next closer" name falls between
/// the owner name and the next hashed owner name of the NSEC3.  In other words, if it proves the
/// nonexistence of the name, either directly or by proving the nonexistence of an ancestor of the
/// name.
fn find_cover<'a>(name_hash: &str, records: &'a BTreeMap<String, NSEC3>) -> Option<&'a NSEC3> {
    let (hash, candidate) = records
        // Find the greater hash that is less or equal than the name's hash.
        .range(..=name_hash.to_owned())
        .last()
        // If no value is less or equal than the name's hash, it means that the name's hash is out
        // of range and the last record covers it.
        .or_else(|| records.last_key_value())?;

    // If the found hash is exactly the name's hash, return None as it wouldn't be proving its
    // nonexistence. Otherwise return the RR with that hash.
    (hash != name_hash).then_some(candidate)
}

/// This proof consists of (up to) two different NSEC3 RRs:
/// - An NSEC3 RR that matches the closest (provable) encloser.
/// - An NSEC3 RR that covers the "next closer" name to the closest encloser.
fn closest_encloser_proof<'a>(
    closest_encloser_hash: &str,
    next_closer_name_hash: &str,
    records: &'a BTreeMap<String, NSEC3>,
) -> Option<(&'a NSEC3, &'a NSEC3)> {
    Some((
        find_match(closest_encloser_hash, records)?,
        find_cover(next_closer_name_hash, records)?,
    ))
}

fn query_nameserver(
    records: impl IntoIterator<Item = Record>,
    qname: &FQDN,
    qtype: RecordType,
) -> Result<(BTreeMap<String, NSEC3>, DigStatus, Vec<NSEC3>)> {
    let network = Network::new()?;
    let mut ns = NameServer::new(&dns_test::SUBJECT, FQDN::ROOT, &network)?;

    for record in records {
        ns.add(record);
    }

    let ns = ns.sign()?;
    // Extract the NSEC3 RRs from the signed zonefile and sort them by the hash embedded in the
    // last label of each record's owner.
    let nsec3_rrs = ns
        .signed_zone_file()
        .records
        .iter()
        .cloned()
        .filter_map(|rr| {
            let mut nsec3_rr = rr.try_into_nsec3().ok()?;
            nsec3_rr.next_hashed_owner_name = nsec3_rr.next_hashed_owner_name.to_uppercase();
            Some((nsec3_rr.fqdn.last_label().to_uppercase(), nsec3_rr))
        })
        .collect::<BTreeMap<_, _>>();

    let ns = ns.start()?;

    let client = Client::new(&network)?;
    let output = client.dig(
        *DigSettings::default().dnssec().authentic_data(),
        ns.ipv4_addr(),
        qtype,
        qname,
    )?;

    let nsec3_rrs_response = output
        .authority
        .into_iter()
        .filter_map(|rr| rr.try_into_nsec3().ok())
        .collect::<Vec<_>>();

    Ok((nsec3_rrs, output.status, nsec3_rrs_response))
}

#[track_caller]
fn find_records<'a>(
    records: &[NSEC3],
    records_and_err_msgs: impl IntoIterator<Item = (&'a NSEC3, &'a str)>,
) {
    for (record, err_msg) in records_and_err_msgs {
        records.iter().find(|&rr| rr == record).expect(err_msg);
    }
}

const ALICE_FQDN: &str = "alice.com.";
const BOB_FQDN: &str = "bob.alice.com.";
const CHARLIE_FQDN: &str = "charlie.alice.com.";
const WILDCARD_FQDN: &str = "*.alice.com.";

// These hashes are computed with 1 iteration of SHA-1 without salt and must be recomputed if
// those parameters were to change.
const ALICE_HASH: &str = "LLKH4L6I60VHAPP6VRM3DFR9RI8AK9I0"; /* h(alice.com.) */
const CHARLIE_HASH: &str = "99P1CCPQ2N64LIRMT2838O4HK0QFA51B"; /* h(charlie.alice.com.) */
const WILDCARD_HASH: &str = "19GBV5V1BO0P51H34JQDH1C8CIAA5RAQ"; /* h(*.alice.com.) */

// This test checks that name servers produce a name error response compliant with section 7.2.2.
// of RFC5155.
#[test]
#[ignore]
fn name_error_response() -> Result<()> {
    let alice_fqdn = FQDN(ALICE_FQDN)?;
    let bob_fqdn = FQDN(BOB_FQDN)?;
    // The queried name
    let qname = FQDN(CHARLIE_FQDN)?;

    let (nsec3_rrs, status, nsec3_rrs_response) = query_nameserver(
        [
            Record::a(alice_fqdn, Ipv4Addr::new(1, 2, 3, 4)),
            Record::a(bob_fqdn, Ipv4Addr::new(1, 2, 3, 5)),
        ],
        &qname,
        RecordType::A,
    )?;

    assert!(status.is_nxdomain());

    // Closest Encloser Proof
    //
    // The closest encloser of a name is its longest existing ancestor. In this scenario, the
    // closest encloser of `charlie.alice.com.` is `alice.com.` as this is the longest ancestor with an
    // existing RR.
    //
    // The next closer name of a name is the name one label longer than its closest encloser. In
    // this scenario, the closest encloser is `alice.com.` which means that the next closer name is `charlie.alice.com.`

    // If this panics, it probably means that the precomputed hashes must be recomputed.
    let (closest_encloser_rr, next_closer_name_rr) =
        closest_encloser_proof(ALICE_HASH, CHARLIE_HASH, &nsec3_rrs)
            .expect("Cannot find a closest encloser proof in the zonefile");

    // Wildcard at the closet encloser RR: Must cover the wildcard at the closest encloser of
    // QNAME.
    //
    // In this scenario, the closest encloser is `alice.com.`, so the wildcard at the closer
    // encloser is `*.alice.com.`.
    //
    // This NSEC3 RR must cover the hash of the wildcard at the closests encloser.

    // if this panics, it probably means that the precomputed hashes must be recomputed.
    let wildcard_rr =
        find_cover(WILDCARD_HASH, &nsec3_rrs).expect("No RR in the zonefile covers the wildcard");

    // Now we check that the response has the three NSEC3 RRs.
    find_records(
        &nsec3_rrs_response,
        [
            (
                closest_encloser_rr,
                "No RR in the response matches the closest encloser",
            ),
            (
                next_closer_name_rr,
                "No RR in the response covers the next closer name",
            ),
            (wildcard_rr, "No RR in the response covers the wildcard"),
        ],
    );

    Ok(())
}

// This test checks that name servers produce a no data response compliant with section 7.2.3.
// of RFC5155 when the query type is not DS.
#[test]
#[ignore]
fn no_data_response_not_ds() -> Result<()> {
    let alice_fqdn = FQDN(ALICE_FQDN)?;
    // The queried name
    let qname = alice_fqdn.clone();

    let (nsec3_rrs, _status, nsec3_rrs_response) = query_nameserver(
        [Record::a(alice_fqdn, Ipv4Addr::new(1, 2, 3, 4))],
        &qname,
        RecordType::MX,
    )?;

    // The server MUST include the NSEC3 RR that matches QNAME.

    // if this panics, it probably means that the precomputed hashes must be recomputed.
    let qname_rr = find_match(ALICE_HASH, &nsec3_rrs).expect("No RR in the zonefile matches QNAME");

    find_records(
        &nsec3_rrs_response,
        [(qname_rr, "No RR in the response matches QNAME")],
    );

    Ok(())
}

// This test checks that name servers produce a no data response compliant with section 7.2.4.
// of RFC5155 when the query type is DS and there is an NSEC3 RR that matches the queried name.
#[test]
#[ignore]
fn no_data_response_ds_match() -> Result<()> {
    let alice_fqdn = FQDN(ALICE_FQDN)?;
    // The queried name
    let qname = alice_fqdn.clone();

    let (nsec3_rrs, _status, nsec3_rrs_response) = query_nameserver(
        [Record::a(alice_fqdn, Ipv4Addr::new(1, 2, 3, 4))],
        &qname,
        RecordType::DS,
    )?;

    // If there is an NSEC3 RR that matches QNAME, the server MUST return it in the response.

    // if this panics, it probably means that the precomputed hashes must be recomputed.
    let qname_rr = find_match(ALICE_HASH, &nsec3_rrs).expect("No RR in the zonefile matches QNAME");

    find_records(
        &nsec3_rrs_response,
        [(qname_rr, "No RR in the response matches QNAME")],
    );

    Ok(())
}

// This test checks that name servers produce a no data response compliant with section 7.2.4.
// of RFC5155 when the query type is DS and no NSEC3 RR matches the queried name.
#[test]
#[ignore]
fn no_data_response_ds_no_match() -> Result<()> {
    let alice_fqdn = FQDN(ALICE_FQDN)?;
    // The queried name
    let qname = FQDN(CHARLIE_FQDN)?;

    let (nsec3_rrs, _status, nsec3_rrs_response) = query_nameserver(
        [Record::a(alice_fqdn, Ipv4Addr::new(1, 2, 3, 4))],
        &qname,
        RecordType::DS,
    )?;

    // If no NSEC3 RR matches QNAME, the server MUST return a closest provable encloser proof for
    // QNAME.

    // Closest Encloser Proof
    //
    // The closest encloser of a name is its longest existing ancestor. In this scenario, the
    // closest encloser of `charlie.alice.com.` is `alice.com.` as this is the longest ancestor with an
    // existing RR.
    //
    // The next closer name of a name is the name one label longer than its closest encloser. In
    // this scenario, the closest encloser is `alice.com.` which means that the next closer name is `charlie.alice.com.`

    // If this panics, it probably means that the precomputed hashes must be recomputed.
    let (closest_encloser_rr, next_closer_name_rr) =
        closest_encloser_proof(ALICE_HASH, CHARLIE_HASH, &nsec3_rrs)
            .expect("Cannot find a closest encloser proof in the zonefile");

    find_records(
        &nsec3_rrs_response,
        [
            (
                closest_encloser_rr,
                "No RR in the response matches the closest encloser",
            ),
            (
                next_closer_name_rr,
                "No RR in the response covers the next closer name",
            ),
        ],
    );

    Ok(())
}

// This test checks that name servers produce a wildcard no data response compliant with section 7.2.5.
#[test]
#[ignore]
fn wildcard_no_data_response() -> Result<()> {
    let wildcard_fqdn = FQDN(WILDCARD_FQDN)?;
    // The queried name
    let qname = FQDN(CHARLIE_FQDN)?;

    let (nsec3_rrs, _status, nsec3_rrs_response) = query_nameserver(
        [Record::a(wildcard_fqdn, Ipv4Addr::new(1, 2, 3, 4))],
        &qname,
        RecordType::MX,
    )?;

    // If there is a wildcard match for QNAME, but QTYPE is not present at that name, the response MUST
    // include a closest encloser proof for QNAME and MUST include the NSEC3 RR that matches the
    // wildcard.

    // Closest Encloser Proof
    //
    // The closest encloser of a name is its longest existing ancestor. In this scenario, the
    // closest encloser of `charlie.alice.com.` is `alice.com.` as this is the longest ancestor with an
    // existing RR.
    //
    // The next closer name of a name is the name one label longer than its closest encloser. In
    // this scenario, the closest encloser is `alice.com.` which means that the next closer name is `charlie.alice.com.`

    // If this panics, it probably means that the precomputed hashes must be recomputed.
    let (closest_encloser_rr, next_closer_name_rr) =
        closest_encloser_proof(ALICE_HASH, CHARLIE_HASH, &nsec3_rrs)
            .expect("Cannot find a closest encloser proof in the zonefile");

    // Wildcard RR: This NSEC3 RR must match `*.alice.com`.

    // If this panics, it probably means that the precomputed hashes must be recomputed.
    let wildcard_rr =
        find_match(WILDCARD_HASH, &nsec3_rrs).expect("No RR in the zonefile matches the wildcard");

    find_records(
        &nsec3_rrs_response,
        [
            (
                closest_encloser_rr,
                "No RR in the response matches the closest encloser",
            ),
            (
                next_closer_name_rr,
                "No RR in the response covers the next closer name",
            ),
            (wildcard_rr, "No RR in the response covers the wildcard"),
        ],
    );

    Ok(())
}

// This test checks that name servers produce a wildcard answer response compliant with section 7.2.6.
#[test]
#[ignore]
fn wildcard_answer_response() -> Result<()> {
    let wildcard_fqdn = FQDN(WILDCARD_FQDN)?;
    // The queried name
    let qname = FQDN(CHARLIE_FQDN)?;

    let (nsec3_rrs, _status, nsec3_rrs_response) = query_nameserver(
        [Record::a(wildcard_fqdn, Ipv4Addr::new(1, 2, 3, 4))],
        &qname,
        RecordType::A,
    )?;

    // If there is a wildcard match for QNAME and QTYPE, then, in addition to the expanded wildcard
    // RRSet returned in the answer section of the response, proof that the wildcard match was
    // valid must be returned. ... To this end, the NSEC3 RR that covers the "next closer" name of the
    // immediate ancestor of the wildcard MUST be returned.

    // The next closer name of a name is the name one label longer than its closest encloser. In
    // this scenario, the closest encloser is `alice.com.` which means that the next closer name is `charlie.alice.com.`

    // If this panics, it probably means that the precomputed hashes must be recomputed.
    let next_closer_name_rr = find_cover(CHARLIE_HASH, &nsec3_rrs)
        .expect("No RR in the zonefile covers the next closer name");

    find_records(
        &nsec3_rrs_response,
        [(
            next_closer_name_rr,
            "No RR in the response covers the next closer name",
        )],
    );

    Ok(())
}
