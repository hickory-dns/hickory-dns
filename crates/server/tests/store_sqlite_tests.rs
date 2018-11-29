extern crate trust_dns;
extern crate trust_dns_server;

use std::fs;
use std::str::FromStr;

use trust_dns::rr::Name;
use trust_dns_server::authority::ZoneType;
use trust_dns_server::store::sqlite::{SqliteAuthority, SqliteConfig};

#[macro_use]
mod authority_battery;

fn sqlite(master_file_path: &str, test_name: &str) -> SqliteAuthority {
    let journal_path = format!("target/tests/basic_authority_battery_{}.jrnl", test_name);
    fs::create_dir_all("target/tests/").ok();

    // cleanup anything from previous test
    fs::remove_file(&journal_path).ok();

    let config = SqliteConfig {
        zone_file_path: master_file_path.to_string(),
        journal_file_path: journal_path,
        allow_update: false,
        enable_dnssec: false,
    };

    SqliteAuthority::try_from_config(
        Some(Name::from_str("example.com.").unwrap()),
        ZoneType::Master,
        false,
        config,
    ).expect("failed to load file")
}

basic_battery!(sqlite);
