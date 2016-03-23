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
use std::path::{Path, PathBuf};
use std::net::{Ipv4Addr, Ipv6Addr};

use log::LogLevel;

use ::authority::ZoneType;
use super::*;

#[test]
fn test_read_config() {
  let mut path: PathBuf = PathBuf::from(".");
  path.push("src");
  path.push("config");
  path.push("test");
  path.push("example.toml");

  println!("reading config");
  let config: Config = Config::read_config(&path).unwrap();

  assert_eq!(config.get_listen_port(), 53);
  assert_eq!(config.get_listen_addrs_ipv4(), vec![]);
  assert_eq!(config.get_listen_addrs_ipv6(), vec![]);
  assert_eq!(config.get_log_level(), LogLevel::Info);
  assert_eq!(config.get_directory(), Path::new("/var/named"));
  assert_eq!(config.get_zones(), [
    ZoneConfig { zone: "localhost".into(), zone_type: ZoneType::Master, file: "default/localhost.zone".into(), allow_update: None },
    ZoneConfig { zone: "0.0.127.in-addr.arpa".into(), zone_type: ZoneType::Master, file: "default/127.0.0.1.zone".into(), allow_update: None },
    ZoneConfig { zone: "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa".into(), zone_type: ZoneType::Master, file: "default/ipv6_1.zone".into(), allow_update: None },
    ZoneConfig { zone: "255.in-addr.arpa".into(), zone_type: ZoneType::Master, file: "default/255.zone".into(), allow_update: None },
    ZoneConfig { zone: "0.in-addr.arpa".into(), zone_type: ZoneType::Master, file: "default/0.zone".into(), allow_update: None }
  ]);
}

#[test]
fn test_parse_toml() {
  let config: Config = "listen_port = 2053".parse().unwrap();
  assert_eq!(config.get_listen_port(), 2053);

  let config: Config = "listen_addrs_ipv4 = [\"0.0.0.0\"]".parse().unwrap();
  assert_eq!(config.get_listen_addrs_ipv4(), vec![Ipv4Addr::new(0,0,0,0)]);

  let config: Config = "listen_addrs_ipv4 = [\"0.0.0.0\", \"127.0.0.1\"]".parse().unwrap();
  assert_eq!(config.get_listen_addrs_ipv4(), vec![Ipv4Addr::new(0,0,0,0), Ipv4Addr::new(127,0,0,1)]);

  let config: Config = "listen_addrs_ipv6 = [\"::0\"]".parse().unwrap();
  assert_eq!(config.get_listen_addrs_ipv6(), vec![Ipv6Addr::new(0,0,0,0,0,0,0,0)]);

  let config: Config = "listen_addrs_ipv6 = [\"::0\", \"::1\"]".parse().unwrap();
  assert_eq!(config.get_listen_addrs_ipv6(), vec![Ipv6Addr::new(0,0,0,0,0,0,0,0), Ipv6Addr::new(0,0,0,0,0,0,0,1)]);

  let config: Config = "log_level = \"Debug\"".parse().unwrap();
  assert_eq!(config.get_log_level(), LogLevel::Debug);

  let config: Config = "directory = \"/dev/null\"".parse().unwrap();
  assert_eq!(config.get_directory(), Path::new("/dev/null"));
}
