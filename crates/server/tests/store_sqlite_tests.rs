extern crate futures;
extern crate trust_dns;
extern crate trust_dns_server;

use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use trust_dns::rr::Name;
use trust_dns_server::authority::ZoneType;
use trust_dns_server::store::sqlite::{SqliteAuthority, SqliteConfig};

#[macro_use]
mod authority_battery;

fn sqlite(master_file_path: &str, module: &str, test_name: &str) -> SqliteAuthority {
    let journal_path = PathBuf::from("target/tests")
        .join(module)
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

    SqliteAuthority::try_from_config(
        Name::from_str("example.com.").unwrap(),
        ZoneType::Master,
        false,
        true,
        None,
        &config,
    ).expect("failed to load file")
}

#[allow(unused)]
fn sqlite_update(master_file_path: &str, module: &str, test_name: &str) -> SqliteAuthority {
    let journal_path = PathBuf::from("target/tests")
        .join(module)
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

    SqliteAuthority::try_from_config(
        Name::from_str("example.com.").unwrap(),
        ZoneType::Master,
        false,
        true,
        None,
        &config,
    ).expect("failed to load file")
}

basic_battery!(sqlite);
#[cfg(feature = "dnssec")]
dnssec_battery!(sqlite);
#[cfg(feature = "dnssec")]
dynamic_update!(sqlite_update);