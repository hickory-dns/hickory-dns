/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
extern crate log;
extern crate trust_dns;
extern crate trust_dns_proto;
extern crate trust_dns_server;

use std::env;
use std::path::{Path, PathBuf};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use log::LogLevel;

use trust_dns_server::authority::ZoneType;
use trust_dns_server::config::*;

#[test]
fn test_read_config() {
    let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or(".".to_owned());
    let path: PathBuf = PathBuf::from(server_path).join("tests/named_test_configs/example.toml");

    if !path.exists() {
        assert!(
            false,
            "can't locate example.toml and other configs: {:?}",
            path
        )
    }

    println!("reading config");
    let config: Config = Config::read_config(&path).unwrap();

    assert_eq!(config.get_listen_port(), 53);
    assert_eq!(config.get_listen_addrs_ipv4(), Vec::<Ipv4Addr>::new());
    assert_eq!(config.get_listen_addrs_ipv6(), Vec::<Ipv6Addr>::new());
    assert_eq!(config.get_tcp_request_timeout(), Duration::from_secs(5));
    assert_eq!(config.get_log_level(), LogLevel::Info);
    assert_eq!(config.get_directory(), Path::new("/var/named"));
    assert_eq!(
        config.get_zones(),
        [
            ZoneConfig::new(
                "localhost".into(),
                ZoneType::Master,
                "default/localhost.zone".into(),
                None,
                None,
                vec![],
            ),
            ZoneConfig::new(
                "0.0.127.in-addr.arpa".into(),
                ZoneType::Master,
                "default/127.0.0.1.zone".into(),
                None,
                None,
                vec![],
            ),
            ZoneConfig::new(
                "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.\
                                 ip6.arpa"
                    .into(),
                ZoneType::Master,
                "default/ipv6_1.zone".into(),
                None,
                None,
                vec![],
            ),
            ZoneConfig::new(
                "255.in-addr.arpa".into(),
                ZoneType::Master,
                "default/255.zone".into(),
                None,
                None,
                vec![],
            ),
            ZoneConfig::new(
                "0.in-addr.arpa".into(),
                ZoneType::Master,
                "default/0.zone".into(),
                None,
                None,
                vec![],
            ),
            ZoneConfig::new(
                "example.com".into(),
                ZoneType::Master,
                "example.com.zone".into(),
                None,
                None,
                vec![],
            ),
        ]
    );
}

#[test]
fn test_parse_toml() {
    let config: Config = "listen_port = 2053".parse().unwrap();
    assert_eq!(config.get_listen_port(), 2053);

    let config: Config = "listen_addrs_ipv4 = [\"0.0.0.0\"]".parse().unwrap();
    assert_eq!(
        config.get_listen_addrs_ipv4(),
        vec![Ipv4Addr::new(0, 0, 0, 0)]
    );

    let config: Config = "listen_addrs_ipv4 = [\"0.0.0.0\", \"127.0.0.1\"]"
        .parse()
        .unwrap();
    assert_eq!(
        config.get_listen_addrs_ipv4(),
        vec![Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(127, 0, 0, 1)]
    );

    let config: Config = "listen_addrs_ipv6 = [\"::0\"]".parse().unwrap();
    assert_eq!(
        config.get_listen_addrs_ipv6(),
        vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)]
    );

    let config: Config = "listen_addrs_ipv6 = [\"::0\", \"::1\"]".parse().unwrap();
    assert_eq!(
        config.get_listen_addrs_ipv6(),
        vec![
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
        ]
    );

    let config: Config = "tcp_request_timeout = 25".parse().unwrap();
    assert_eq!(config.get_tcp_request_timeout(), Duration::from_secs(25));

    let config: Config = "log_level = \"Debug\"".parse().unwrap();
    assert_eq!(config.get_log_level(), LogLevel::Debug);

    let config: Config = "directory = \"/dev/null\"".parse().unwrap();
    assert_eq!(config.get_directory(), Path::new("/dev/null"));
}

#[cfg(feature = "dnsssec")]
#[test]
fn test_parse_zone_keys() {
    use trust_dns::rr::Name;
    use trust_dns::rr::dnssec::Algorithm;

    let config: Config = "
[[zones]]
zone = \"example.com\"
zone_type = \"Master\"
file = \"example.com.zone\"

\
         [[zones.keys]]
key_path = \"/path/to/my_ed25519.pem\"
algorithm = \"ED25519\"
\
         signer_name = \"ns.example.com.\"
is_zone_signing_key = false
is_zone_update_auth = true

[[zones.keys]]
key_path = \"/path/to/my_rsa.pem\"
algorithm = \
         \"RSASHA256\"
signer_name = \"ns.example.com.\"

"
        .parse()
        .unwrap();
    assert_eq!(
        config.get_zones()[0].get_keys()[0].key_path(),
        Path::new("/path/to/my_ed25519.pem")
    );
    assert_eq!(
        config.get_zones()[0].get_keys()[0].algorithm().unwrap(),
        Algorithm::ED25519
    );
    assert_eq!(
        config.get_zones()[0].get_keys()[0]
            .signer_name()
            .unwrap()
            .unwrap(),
        Name::parse("ns.example.com.", None).unwrap()
    );
    assert_eq!(
        config.get_zones()[0].get_keys()[0].is_zone_signing_key(),
        false
    );
    assert_eq!(
        config.get_zones()[0].get_keys()[0].is_zone_update_auth(),
        true
    );

    assert_eq!(
        config.get_zones()[0].get_keys()[1].key_path(),
        Path::new("/path/to/my_rsa.pem")
    );
    assert_eq!(
        config.get_zones()[0].get_keys()[1].algorithm().unwrap(),
        Algorithm::RSASHA256
    );
    assert_eq!(
        config.get_zones()[0].get_keys()[1]
            .signer_name()
            .unwrap()
            .unwrap(),
        Name::parse("ns.example.com.", None).unwrap()
    );
    assert_eq!(
        config.get_zones()[0].get_keys()[1].is_zone_signing_key(),
        false
    );
    assert_eq!(
        config.get_zones()[0].get_keys()[1].is_zone_update_auth(),
        false
    );
}

#[test]
fn test_parse_tls() {
    // defaults
    let config: Config = "".parse().unwrap();

    assert_eq!(config.get_tls_listen_port(), 853);
    assert_eq!(config.get_tls_cert(), None);

    let config: Config = "
tls_cert = { path = \"path/to/some.pkcs12\" }
tls_listen_port = 8853
  "
        .parse()
        .unwrap();

    assert_eq!(config.get_tls_listen_port(), 8853);
    assert_eq!(
        config.get_tls_cert().unwrap().get_path(),
        Path::new("path/to/some.pkcs12")
    );
}
