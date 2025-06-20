#![cfg(feature = "sqlite")]

use std::path::PathBuf;
use std::str::FromStr;
use std::{fs, path::Path};

use futures_executor::block_on;

use hickory_proto::rr::Name;
#[cfg(feature = "__dnssec")]
use hickory_server::dnssec::NxProofKind;
use hickory_server::{
    authority::ZoneType,
    store::sqlite::{SqliteAuthority, SqliteConfig},
};

fn sqlite(master_file_path: &Path, module: &str, test_name: &str) -> SqliteAuthority {
    let journal_file_path = PathBuf::from("target/tests")
        .join(module.replace("::", "_"))
        .join(test_name)
        .join("authority_battery.jrnl");
    fs::create_dir_all(journal_file_path.parent().unwrap()).ok();

    // cleanup anything from previous test
    fs::remove_file(&journal_file_path).ok();

    let config = SqliteConfig {
        zone_file_path: master_file_path.to_owned(),
        journal_file_path,
        allow_update: true,
        #[cfg(feature = "__dnssec")]
        tsig_keys: Vec::new(),
    };

    block_on(SqliteAuthority::try_from_config(
        Name::from_str("example.com.").unwrap(),
        ZoneType::Primary,
        false,
        true,
        None,
        &config,
        #[cfg(feature = "__dnssec")]
        Some(NxProofKind::Nsec),
    ))
    .expect("failed to load file")
}

#[cfg_attr(not(feature = "__dnssec"), allow(unused))]
fn sqlite_update(master_file_path: &Path, module: &str, test_name: &str) -> SqliteAuthority {
    let journal_file_path = PathBuf::from("target/tests")
        .join(module.replace("::", "_"))
        .join(test_name)
        .join("authority_battery.jrnl");
    fs::create_dir_all(journal_file_path.parent().unwrap()).ok();

    // cleanup anything from previous test
    fs::remove_file(&journal_file_path).ok();

    let config = SqliteConfig {
        zone_file_path: master_file_path.to_owned(),
        journal_file_path,
        allow_update: true,
        #[cfg(feature = "__dnssec")]
        tsig_keys: Vec::new(),
    };

    block_on(SqliteAuthority::try_from_config(
        Name::from_str("example.com.").unwrap(),
        ZoneType::Primary,
        false,
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
