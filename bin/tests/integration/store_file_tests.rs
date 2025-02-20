use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use hickory_proto::rr::{LowerName, Name, RecordType, RrKey};
use hickory_server::authority::{Authority, LookupOptions, ZoneType};
#[cfg(feature = "__dnssec")]
use hickory_server::dnssec::NxProofKind;
use hickory_server::store::file::{FileAuthority, FileConfig};
use test_support::subscribe;

fn file(master_file_path: &Path, _module: &str, _test_name: &str) -> FileAuthority {
    let config = FileConfig {
        zone_file_path: master_file_path.to_owned(),
    };

    FileAuthority::try_from_config(
        Name::from_str("example.com.").unwrap(),
        ZoneType::Primary,
        false,
        None,
        &config,
        #[cfg(feature = "__dnssec")]
        Some(NxProofKind::Nsec),
    )
    .expect("failed to load file")
}

basic_battery!(file, crate::store_file_tests::file);
#[cfg(feature = "__dnssec")]
dnssec_battery!(file, crate::store_file_tests::file);

#[test]
fn test_all_lines_are_loaded() {
    subscribe();
    let config = FileConfig {
        zone_file_path: PathBuf::from("../tests/test-data/test_configs/default/nonewline.zone"),
    };

    let mut authority = FileAuthority::try_from_config(
        Name::from_str("example.com.").unwrap(),
        ZoneType::Primary,
        false,
        None,
        &config,
        #[cfg(feature = "__dnssec")]
        Some(NxProofKind::Nsec),
    )
    .expect("failed to load");
    let rrkey = RrKey {
        record_type: RecordType::A,
        name: LowerName::from(Name::from_ascii("ensure.nonewline.").unwrap()),
    };
    assert!(authority.records_get_mut().get(&rrkey).is_some())
}

#[test]
fn test_implicit_in_class() {
    subscribe();
    let config = FileConfig {
        zone_file_path: PathBuf::from("../tests/test-data/test_configs/default/implicitclass.zone"),
    };

    let authority = FileAuthority::try_from_config(
        Name::from_str("example.com.").unwrap(),
        ZoneType::Primary,
        false,
        None,
        &config,
        #[cfg(feature = "__dnssec")]
        Some(NxProofKind::Nsec),
    );
    assert!(authority.is_ok());
}

#[tokio::test]
async fn test_ttl_wildcard() {
    subscribe();
    let config = FileConfig {
        zone_file_path: PathBuf::from("../tests/test-data/test_configs/default/test.local.zone"),
    };

    let zone_name = LowerName::from_str("test.local.").unwrap();
    let mut authority = FileAuthority::try_from_config(
        Name::from(zone_name.clone()),
        ZoneType::Primary,
        false,
        None,
        &config,
        #[cfg(feature = "__dnssec")]
        Some(NxProofKind::Nsec),
    )
    .unwrap();

    // This one pass.
    let rrkey = RrKey {
        record_type: RecordType::A,
        name: LowerName::from(Name::from_ascii("simple.test.local.").unwrap()),
    };
    assert_eq!(authority.records_get_mut().get(&rrkey).unwrap().ttl(), 120);
    // // This one related to a wildcard don't pass around $TTL
    let name = LowerName::from(Name::from_ascii("x.wc.test.local.").unwrap());
    let rr = authority
        .lookup(&name, RecordType::A, LookupOptions::default())
        .await
        .unwrap();
    let data = rr
        .into_iter()
        .next()
        .expect("A record not found in authority");

    assert_eq!(data.record_type(), RecordType::A);
    assert_eq!(data.ttl(), 120);
}
