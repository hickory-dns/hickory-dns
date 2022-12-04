use std::str::FromStr;

use trust_dns_client::rr::{LowerName, RecordType};
use trust_dns_client::rr::{Name, RrKey};
use trust_dns_server::authority::{Authority, LookupOptions, ZoneType};
use trust_dns_server::store::file::{FileAuthority, FileConfig};

#[macro_use]
mod authority_battery;

fn file(master_file_path: &str, _module: &str, _test_name: &str) -> FileAuthority {
    let config = FileConfig {
        zone_file_path: master_file_path.to_string(),
    };

    FileAuthority::try_from_config(
        Name::from_str("example.com.").unwrap(),
        ZoneType::Primary,
        false,
        None,
        &config,
    )
    .expect("failed to load file")
}

basic_battery!(file);
#[cfg(feature = "dnssec")]
dnssec_battery!(file);

#[test]
fn test_all_lines_are_loaded() {
    let config = FileConfig {
        zone_file_path: "../../tests/test-data/named_test_configs/default/nonewline.zone"
            .to_string(),
    };

    let mut authority = FileAuthority::try_from_config(
        Name::from_str("example.com.").unwrap(),
        ZoneType::Primary,
        false,
        None,
        &config,
    )
    .expect("failed to load");
    let rrkey = RrKey {
        record_type: RecordType::A,
        name: LowerName::from(Name::from_ascii("ensure.nonewline.").unwrap()),
    };
    assert!(authority.records_get_mut().get(&rrkey).is_some())
}

#[tokio::test]
async fn test_ttl_wilcard() {
    let config = FileConfig {
        zone_file_path: "../../tests/test-data/named_test_configs/default/test.local.zone"
            .to_string(),
    };

    let zone_name = LowerName::from_str("test.local.").unwrap();
    let mut authority = FileAuthority::try_from_config(
        Name::from(zone_name.clone()),
        ZoneType::Primary,
        false,
        None,
        &config,
    )
    .unwrap();

    // This one pass.
    let rrkey = RrKey {
        record_type: RecordType::A,
        name: LowerName::from(Name::from_ascii("simple.test.local.").unwrap()),
    };
    assert_eq!(authority.records_get_mut().get(&rrkey).unwrap().ttl(), 120);
    // // This one related to a wildcard don't pass arround $TTL
    let name = LowerName::from(Name::from_ascii("x.wc.test.local.").unwrap());
    let rr = authority
        .lookup(&name, RecordType::A, LookupOptions::default())
        .await
        .unwrap();
    let data = rr
        .into_iter()
        .next()
        .expect("A record not found in authority");

    assert_eq!(data.rr_type(), RecordType::A);
    assert_eq!(data.ttl(), 120);
}
