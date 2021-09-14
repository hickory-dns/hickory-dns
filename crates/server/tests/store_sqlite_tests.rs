#![cfg(feature = "sqlite")]

use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use futures_executor::block_on;

use trust_dns_client::rr::Name;
use trust_dns_server::{
    authority::ZoneType,
    store::sqlite::{SqliteAuthority, SqliteConfig},
};

#[macro_use]
mod authority_battery;

fn sqlite(master_file_path: &str, module: &str, test_name: &str) -> SqliteAuthority {
    let journal_path = PathBuf::from("target/tests")
        .join(module.replace("::", "_"))
        .join(test_name)
        .join("authority_battery.jrnl");
    fs::create_dir_all(journal_path.parent().unwrap()).ok();

    // cleanup anything from previous test
    fs::remove_file(&journal_path).ok();

    let config = SqliteConfig {
        zone_file_path: master_file_path.to_string(),
        journal_file_path: journal_path.to_str().unwrap().to_string(),
        allow_update: true,
    };

    block_on(SqliteAuthority::try_from_config(
        Name::from_str("example.com.").unwrap(),
        ZoneType::Primary,
        false,
        true,
        None,
        &config,
    ))
    .expect("failed to load file")
}

#[allow(unused)]
fn sqlite_update(master_file_path: &str, module: &str, test_name: &str) -> SqliteAuthority {
    let journal_path = PathBuf::from("target/tests")
        .join(module.replace("::", "_"))
        .join(test_name)
        .join("authority_battery.jrnl");
    fs::create_dir_all(journal_path.parent().unwrap()).ok();

    // cleanup anything from previous test
    fs::remove_file(&journal_path).ok();

    let config = SqliteConfig {
        zone_file_path: master_file_path.to_string(),
        journal_file_path: journal_path.to_str().unwrap().to_string(),
        allow_update: true,
    };

    block_on(SqliteAuthority::try_from_config(
        Name::from_str("example.com.").unwrap(),
        ZoneType::Primary,
        false,
        true,
        None,
        &config,
    ))
    .expect("failed to load file")
}

basic_battery!(sqlite);
#[cfg(feature = "dnssec")]
dnssec_battery!(sqlite);
#[cfg(feature = "dnssec")]
dynamic_update!(sqlite_update);
