#![cfg(feature = "sqlite")]

use std::path::PathBuf;
use std::str::FromStr;
use std::{fs, path::Path};

use futures_executor::block_on;

use hickory_proto::rr::Name;
#[cfg(feature = "__dnssec")]
use hickory_server::dnssec::NxProofKind;
use hickory_server::{
    store::sqlite::{SqliteConfig, SqliteZoneHandler},
    zone_handler::{AxfrPolicy, ZoneType},
};

fn sqlite(zone_path: &Path, module: &str, test_name: &str) -> SqliteZoneHandler {
    let journal_path = PathBuf::from("target/tests")
        .join(module.replace("::", "_"))
        .join(test_name)
        .join("zone_handler_battery.jrnl");
    let _ = fs::create_dir_all(journal_path.parent().unwrap());

    // cleanup anything from previous test
    let _ = fs::remove_file(&journal_path);

    let config = SqliteConfig {
        zone_path: zone_path.to_owned(),
        journal_path,
        allow_update: true,
        #[cfg(feature = "__dnssec")]
        tsig_keys: Vec::new(),
    };

    block_on(SqliteZoneHandler::try_from_config(
        Name::from_str("example.com.").unwrap(),
        ZoneType::Primary,
        AxfrPolicy::Deny,
        true,
        None,
        &config,
        #[cfg(feature = "__dnssec")]
        Some(NxProofKind::Nsec),
    ))
    .expect("failed to load file")
}

#[cfg_attr(not(feature = "__dnssec"), allow(unused))]
fn sqlite_update(zone_path: &Path, module: &str, test_name: &str) -> SqliteZoneHandler {
    let journal_path = PathBuf::from("target/tests")
        .join(module.replace("::", "_"))
        .join(test_name)
        .join("zone_handler_battery.jrnl");
    let _ = fs::create_dir_all(journal_path.parent().unwrap());

    // cleanup anything from previous test
    let _ = fs::remove_file(&journal_path);

    let config = SqliteConfig {
        zone_path: zone_path.to_owned(),
        journal_path,
        allow_update: true,
        #[cfg(feature = "__dnssec")]
        tsig_keys: Vec::new(),
    };

    block_on(SqliteZoneHandler::try_from_config(
        Name::from_str("example.com.").unwrap(),
        ZoneType::Primary,
        AxfrPolicy::Deny,
        true,
        None,
        &config,
        #[cfg(feature = "__dnssec")]
        Some(NxProofKind::Nsec),
    ))
    .expect("failed to load file")
}

basic_battery!(sqlite, crate::store_sqlite_tests::sqlite);
#[cfg(feature = "__dnssec")]
dnssec_battery!(sqlite, crate::store_sqlite_tests::sqlite);
#[cfg(feature = "__dnssec")]
dynamic_update!(sqlite_update, crate::store_sqlite_tests::sqlite_update);
