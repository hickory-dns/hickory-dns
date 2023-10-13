/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#![cfg(feature = "toml")]

use std::env;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use hickory_server::authority::ZoneType;
use hickory_server::config::*;

#[test]
fn test_read_config() {
    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "../..".to_owned());
    let path: PathBuf =
        PathBuf::from(server_path).join("tests/test-data/test_configs/example.toml");

    if !path.exists() {
        panic!("can't locate example.toml and other configs: {:?}", path)
    }

    println!("reading config");
    let config: Config = Config::read_config(&path).unwrap();

    assert_eq!(config.get_listen_port(), 53);
    assert_eq!(config.get_listen_addrs_ipv4(), Ok(Vec::<Ipv4Addr>::new()));
    assert_eq!(config.get_listen_addrs_ipv6(), Ok(Vec::<Ipv6Addr>::new()));
    assert_eq!(config.get_tcp_request_timeout(), Duration::from_secs(5));
    assert_eq!(config.get_log_level(), tracing::Level::INFO);
    assert_eq!(config.get_directory(), Path::new("/var/named"));
    assert_eq!(
        config.get_zones(),
        [
            ZoneConfig::new(
                "localhost".into(),
                ZoneType::Primary,
                "default/localhost.zone".into(),
                None,
                None,
                None,
                vec![],
            ),
            ZoneConfig::new(
                "0.0.127.in-addr.arpa".into(),
                ZoneType::Primary,
                "default/127.0.0.1.zone".into(),
                None,
                None,
                None,
                vec![],
            ),
            ZoneConfig::new(
                "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.\
                 ip6.arpa"
                    .into(),
                ZoneType::Primary,
                "default/ipv6_1.zone".into(),
                None,
                None,
                None,
                vec![],
            ),
            ZoneConfig::new(
                "255.in-addr.arpa".into(),
                ZoneType::Primary,
                "default/255.zone".into(),
                None,
                None,
                None,
                vec![],
            ),
            ZoneConfig::new(
                "0.in-addr.arpa".into(),
                ZoneType::Primary,
                "default/0.zone".into(),
                None,
                None,
                None,
                vec![],
            ),
            ZoneConfig::new(
                "example.com".into(),
                ZoneType::Primary,
                "example.com.zone".into(),
                None,
                None,
                None,
                vec![],
            )
        ]
    );
}

#[test]
fn test_parse_toml() {
    let config = Config::from_toml("listen_port = 2053").unwrap();
    assert_eq!(config.get_listen_port(), 2053);

    let config = Config::from_toml("listen_addrs_ipv4 = [\"0.0.0.0\"]").unwrap();
    assert_eq!(
        config.get_listen_addrs_ipv4(),
        Ok(vec![Ipv4Addr::new(0, 0, 0, 0)])
    );

    let config = Config::from_toml("listen_addrs_ipv4 = [\"0.0.0.0\", \"127.0.0.1\"]").unwrap();
    assert_eq!(
        config.get_listen_addrs_ipv4(),
        Ok(vec![Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(127, 0, 0, 1)])
    );

    let config = Config::from_toml("listen_addrs_ipv6 = [\"::0\"]").unwrap();
    assert_eq!(
        config.get_listen_addrs_ipv6(),
        Ok(vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)])
    );

    let config = Config::from_toml("listen_addrs_ipv6 = [\"::0\", \"::1\"]").unwrap();
    assert_eq!(
        config.get_listen_addrs_ipv6(),
        Ok(vec![
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
        ])
    );

    let config = Config::from_toml("tcp_request_timeout = 25").unwrap();
    assert_eq!(config.get_tcp_request_timeout(), Duration::from_secs(25));

    let config = Config::from_toml("log_level = \"Debug\"").unwrap();
    assert_eq!(config.get_log_level(), tracing::Level::DEBUG);

    let config = Config::from_toml("directory = \"/dev/null\"").unwrap();
    assert_eq!(config.get_directory(), Path::new("/dev/null"));
}

#[cfg(feature = "dnssec")]
#[test]
fn test_parse_zone_keys() {
    use hickory_proto::rr::dnssec::Algorithm;
    use hickory_proto::rr::Name;

    let config = Config::from_toml(
        "
[[zones]]
zone = \"example.com\"
zone_type = \"Primary\"
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
",
    )
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
    assert!(!config.get_zones()[0].get_keys()[0].is_zone_signing_key(),);
    assert!(config.get_zones()[0].get_keys()[0].is_zone_update_auth(),);

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
    assert!(!config.get_zones()[0].get_keys()[1].is_zone_signing_key(),);
    assert!(!config.get_zones()[0].get_keys()[1].is_zone_update_auth(),);
}

#[test]
#[cfg(feature = "dnssec")]
fn test_parse_tls() {
    // defaults
    let config = Config::from_toml("").unwrap();

    assert_eq!(config.get_tls_listen_port(), 853);
    assert_eq!(config.get_tls_cert(), None);

    let config = Config::from_toml(
        "tls_cert = { path = \"path/to/some.pkcs12\", endpoint_name = \"ns.example.com\" }
tls_listen_port = 8853
  ",
    )
    .unwrap();

    assert_eq!(config.get_tls_listen_port(), 8853);
    assert_eq!(
        config.get_tls_cert().unwrap().get_path(),
        Path::new("path/to/some.pkcs12")
    );
}

fn test_config(path: &str) {
    let workspace = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "../..".to_owned());
    let path = PathBuf::from(workspace)
        .join("tests/test-data/test_configs")
        .join(path)
        .with_extension("toml");
    assert!(path.exists(), "does not exist: {}", path.display());
    println!("reading: {}", path.display());
    Config::read_config(&path).expect("failed to read");
}

macro_rules! define_test_config {
    ($name:ident) => {
        #[test]
        fn $name() {
            test_config(stringify!($name));
        }
    };
}

define_test_config!(all_supported_dnssec);
define_test_config!(dns_over_https);
define_test_config!(dns_over_tls_rustls_and_openssl);
define_test_config!(dns_over_tls);
#[cfg(feature = "sqlite")]
define_test_config!(dnssec_with_update);
define_test_config!(dnssec_with_update_deprecated);
define_test_config!(example);
define_test_config!(ipv4_and_ipv6);
define_test_config!(ipv4_only);
define_test_config!(ipv6_only);
define_test_config!(openssl_dnssec);
define_test_config!(ring_dnssec);
#[cfg(feature = "hickory-resolver")]
define_test_config!(example_forwarder);
