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
use std::io::Read;
use std::fs::File;
use std::path::Path;
use std::str::FromStr;
use std::net::{Ipv4Addr, Ipv6Addr};

use log::LogLevel;
use rustc_serialize::Decodable;

use toml::{Decoder, Value};

use ::error::*;

static DEFAULT_PORT: u16 = 53;
static DEFAULT_PATH: &'static str = "/var/named"; // TODO what about windows (do I care? ;)

#[derive(RustcDecodable, Debug)]
pub struct Config {
  listen_addrs_ipv4: Vec<String>,
  listen_addrs_ipv6: Vec<String>,
  listen_port: Option<u16>,
  log_level: Option<String>,
  directory: Option<String>,
  zones: Vec<ZoneConfig>,
}

impl Config {
  /// read a Config file from the file specified at path.
  fn read_config(path: &Path) -> ConfigResult<Config> {
    let mut file: File = try!(File::open(path));
    let mut toml: String = String::new();
    try!(file.read_to_string(&mut toml));
    toml.parse()
  }

  fn get_listen_addrs_ipv4(&self) -> Vec<Ipv4Addr> { self.listen_addrs_ipv4.iter().map(|s| s.parse().unwrap()).collect() }
  fn get_listen_addrs_ipv6(&self) -> Vec<Ipv6Addr> { self.listen_addrs_ipv6.iter().map(|s| s.parse().unwrap()).collect() }
  fn get_listen_port(&self) -> u16 { self.listen_port.unwrap_or(DEFAULT_PORT) }
  fn get_log_level(&self) -> LogLevel {
    if let Some(ref level_str) = self.log_level {
      match level_str as &str {
        "Trace" => LogLevel::Trace,
        "Debug" => LogLevel::Debug,
        "Info" => LogLevel::Info,
        "Warn" => LogLevel::Warn,
        "Error" => LogLevel::Error,
        _ => LogLevel::Info,
      }
    } else {
      LogLevel::Info
    }
  }
  fn get_directory(&self) -> &Path { self.directory.as_ref().map_or(Path::new(DEFAULT_PATH), |s|Path::new(s)) }
  fn get_zones(&self) -> &[ZoneConfig] { &self.zones }
}

impl FromStr for Config {
  type Err = ConfigError;

  fn from_str(toml: &str) -> ConfigResult<Config> {
    let value: Value = try!(toml.parse());
    let mut decoder: Decoder = Decoder::new(value);
    Ok(try!(Self::decode(&mut decoder)))
  }
}

#[derive(RustcDecodable, PartialEq, Debug)]
pub struct ZoneConfig {
  zone: String, // TODO: make Domain::Name decodable
  zone_type: ZoneType,
  file: String,
}

#[derive(RustcDecodable, PartialEq, Eq, Debug, Clone, Copy)]
pub enum ZoneType { Master, Slave, Hint, Forward }

#[cfg(test)]
mod test;
