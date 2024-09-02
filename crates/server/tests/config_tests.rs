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
use std::fs::{read_dir, File};
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hickory_server::authority::ZoneType;
use hickory_server::config::*;
use toml::map::Keys;
use toml::value::Array;
use toml::{Table, Value};

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
                #[cfg(feature = "dnssec")]
                None,
            ),
            ZoneConfig::new(
                "0.0.127.in-addr.arpa".into(),
                ZoneType::Primary,
                "default/127.0.0.1.zone".into(),
                None,
                None,
                None,
                vec![],
                #[cfg(feature = "dnssec")]
                None,
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
                #[cfg(feature = "dnssec")]
                None,
            ),
            ZoneConfig::new(
                "255.in-addr.arpa".into(),
                ZoneType::Primary,
                "default/255.zone".into(),
                None,
                None,
                None,
                vec![],
                #[cfg(feature = "dnssec")]
                None,
            ),
            ZoneConfig::new(
                "0.in-addr.arpa".into(),
                ZoneType::Primary,
                "default/0.zone".into(),
                None,
                None,
                None,
                vec![],
                #[cfg(feature = "dnssec")]
                None,
            ),
            ZoneConfig::new(
                "example.com".into(),
                ZoneType::Primary,
                "example.com.zone".into(),
                None,
                None,
                None,
                vec![],
                #[cfg(feature = "dnssec")]
                None,
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

/// Iterator that yields modified TOML tables with an extra field added, and recurses down the
/// table's values.
struct TableMutator<'a> {
    original: &'a Table,
    yielded_base_case: bool,
    key_iter: Keys<'a>,
    nested_table_mutator: Option<(&'a str, Box<TableMutator<'a>>)>,
    nested_array_mutator: Option<(&'a str, Box<ArrayMutator<'a>>)>,
}

impl<'a> TableMutator<'a> {
    fn new(table: &'a Table) -> Self {
        Self {
            original: table,
            yielded_base_case: false,
            key_iter: table.keys(),
            nested_table_mutator: None,
            nested_array_mutator: None,
        }
    }
}

impl<'a> Iterator for TableMutator<'a> {
    type Item = Table;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.yielded_base_case {
            self.yielded_base_case = true;
            let mut table = self.original.clone();
            table.insert("test_only_invalid_config_key".into(), Value::Integer(1));
            return Some(table);
        }

        loop {
            if let Some((key, iter)) = self.nested_table_mutator.as_mut() {
                if let Some(table) = iter.next() {
                    let mut output = self.original.clone();
                    output[*key] = Value::Table(table);
                    return Some(output);
                } else {
                    self.nested_table_mutator = None;
                }
            }
            if let Some((key, iter)) = self.nested_array_mutator.as_mut() {
                if let Some(array) = iter.next() {
                    let mut output = self.original.clone();
                    output[*key] = Value::Array(array);
                    return Some(output);
                } else {
                    self.nested_array_mutator = None;
                }
            }
            if let Some(key) = self.key_iter.next() {
                match self.original.get(key).unwrap() {
                    Value::String(_)
                    | Value::Integer(_)
                    | Value::Float(_)
                    | Value::Boolean(_)
                    | Value::Datetime(_) => {}
                    Value::Array(array) => {
                        self.nested_array_mutator = Some((key, Box::new(ArrayMutator::new(array))));
                    }
                    Value::Table(table) => {
                        self.nested_table_mutator = Some((key, Box::new(TableMutator::new(table))));
                    }
                }
            } else {
                return None;
            }
        }
    }
}

/// Iterator that yields modified TOML arrays, working with [`TableMutator`], and recurses down the
/// array's contents.
struct ArrayMutator<'a> {
    original: &'a Array,
    index_iter: Range<usize>,
    nested_table_mutator: Option<(usize, Box<TableMutator<'a>>)>,
    nested_array_mutator: Option<(usize, Box<ArrayMutator<'a>>)>,
}

impl<'a> ArrayMutator<'a> {
    fn new(array: &'a Array) -> Self {
        Self {
            original: array,
            index_iter: 0..array.len(),
            nested_table_mutator: None,
            nested_array_mutator: None,
        }
    }
}

impl<'a> Iterator for ArrayMutator<'a> {
    type Item = Array;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some((key, iter)) = self.nested_table_mutator.as_mut() {
                if let Some(table) = iter.next() {
                    let mut output = self.original.clone();
                    output[*key] = Value::Table(table);
                    return Some(output);
                } else {
                    self.nested_table_mutator = None;
                }
            }
            if let Some((key, iter)) = self.nested_array_mutator.as_mut() {
                if let Some(array) = iter.next() {
                    let mut output = self.original.clone();
                    output[*key] = Value::Array(array);
                    return Some(output);
                } else {
                    self.nested_array_mutator = None;
                }
            }
            if let Some(index) = self.index_iter.next() {
                match self.original.get(index).unwrap() {
                    Value::String(_)
                    | Value::Integer(_)
                    | Value::Float(_)
                    | Value::Boolean(_)
                    | Value::Datetime(_) => {}
                    Value::Array(array) => {
                        self.nested_array_mutator =
                            Some((index, Box::new(ArrayMutator::new(array))));
                    }
                    Value::Table(table) => {
                        self.nested_table_mutator =
                            Some((index, Box::new(TableMutator::new(table))));
                    }
                }
            } else {
                return None;
            }
        }
    }
}

/// Check that unknown fields in configuration files are rejected. This uses each example
/// configuration file as a seed, and tries adding invalid fields to each table.
#[test]
fn test_reject_unknown_fields() {
    let test_configs_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/test-data/test_configs");
    for result in read_dir(test_configs_dir).unwrap() {
        let entry = result.unwrap();
        let file_name = entry.file_name().into_string().unwrap();
        if !file_name.ends_with(".toml") {
            continue;
        }
        println!("seed file: {file_name}");

        let mut file = File::open(entry.path()).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        let value = toml::from_str::<toml::Value>(&contents).unwrap();
        let config_table = value.as_table().unwrap();

        // Skip over configs that can't be read with the current set of features.
        #[allow(unused_mut)]
        let mut skip = false;
        #[cfg(not(feature = "dnssec"))]
        if config_table.contains_key("tls_cert") {
            println!("skipping due to tls_cert setting");
            skip = true;
        }
        let zones = config_table.get("zones").unwrap().as_array().unwrap();
        for zone in zones {
            if let Some(stores) = zone.get("stores") {
                let stores = stores.as_table().unwrap();
                let _store_type = stores.get("type").unwrap().as_str().unwrap();

                #[cfg(not(feature = "sqlite"))]
                if _store_type == "sqlite" {
                    println!("skipping due to sqlite store");
                    skip = true;
                    break;
                }

                #[cfg(not(feature = "hickory-resolver"))]
                if _store_type == "forward" {
                    println!("skipping due to forward store");
                    skip = true;
                    break;
                }

                #[cfg(not(feature = "hickory-recursor"))]
                if _store_type != "recursor" {
                    println!("skipping due to recursor store");
                    skip = true;
                    break;
                }
            }
        }

        if skip {
            continue;
        }

        // Confirm the example config file can be read as-is.
        toml::from_str::<Config>(&contents).unwrap();

        // Recursively add a key to every table in the configuration file, and confirm that each
        // modified config file is rejected.
        for modified_config in TableMutator::new(config_table) {
            let serialized = toml::to_string(&modified_config).unwrap();
            match toml::from_str::<Config>(&serialized) {
                Ok(_) => panic!(
                    "config with spurious key was accepted:\n{}",
                    toml::to_string_pretty(&modified_config).unwrap()
                ),
                Err(error) => assert!(
                    error.message().starts_with("unknown field"),
                    "unexpected error: {error:?}"
                ),
            }
        }
    }
}
