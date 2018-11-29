extern crate trust_dns;
extern crate trust_dns_server;

use std::str::FromStr;

use trust_dns::rr::Name;
use trust_dns_server::authority::ZoneType;
use trust_dns_server::store::file::{self, FileConfig};

#[macro_use]
mod authority_battery;

fn file(master_file_path: &str, _test_name: &str) -> file::Authority {
    let config = FileConfig {
        path: master_file_path.to_string(),
    };

    file::Authority::try_from_config(
        Some(Name::from_str("example.com.").unwrap()),
        ZoneType::Master,
        false,
        config,
    ).expect("failed to load file")
}

basic_battery!(file);
