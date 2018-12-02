extern crate trust_dns;
extern crate trust_dns_server;

use std::str::FromStr;

use trust_dns::rr::Name;
use trust_dns_server::authority::ZoneType;
use trust_dns_server::store::file::{FileAuthority, FileConfig};

#[macro_use]
mod authority_battery;

fn file(master_file_path: &str, _module: &str, _test_name: &str) -> FileAuthority {
    let config = FileConfig {
        zone_file_path: master_file_path.to_string(),
    };

    FileAuthority::try_from_config(
        Name::from_str("example.com.").unwrap(),
        ZoneType::Master,
        false,
        None,
        &config,
    ).expect("failed to load file")
}

basic_battery!(file);
#[cfg(feature = "dnssec")]
dnssec_battery!(file);
