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

//! Configuration module for the server binary, `named`.

use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use log::LogLevel;
use rustc_serialize::Decodable;
use toml::{Decoder, Value};

use trust_dns::error::*;
use trust_dns::rr::Name;
use trust_dns::rr::dnssec::{Algorithm, KeyFormat};

use ::authority::ZoneType;
use ::error::{ConfigErrorKind, ConfigResult, ConfigError};

static DEFAULT_PATH: &'static str = "/var/named"; // TODO what about windows (do I care? ;)
static DEFAULT_PORT: u16 = 53;
static DEFAULT_TCP_REQUEST_TIMEOUT: u64 = 5;

#[derive(RustcDecodable, Debug)]
pub struct Config {
  listen_addrs_ipv4: Vec<String>,
  listen_addrs_ipv6: Vec<String>,
  listen_port: Option<u16>,
  tcp_request_timeout: Option<u64>,
  log_level: Option<String>,
  directory: Option<String>,
  zones: Vec<ZoneConfig>,
}

impl Config {
  /// read a Config file from the file specified at path.
  pub fn read_config(path: &Path) -> ConfigResult<Config> {
    let mut file: File = try!(File::open(path));
    let mut toml: String = String::new();
    try!(file.read_to_string(&mut toml));
    toml.parse()
  }

  /// set of listening ipv4 addresses (for TCP and UDP)
  pub fn get_listen_addrs_ipv4(&self) -> Vec<Ipv4Addr> { self.listen_addrs_ipv4.iter().map(|s| s.parse().unwrap()).collect() }
  /// set of listening ipv6 addresses (for TCP and UDP)
  pub fn get_listen_addrs_ipv6(&self) -> Vec<Ipv6Addr> { self.listen_addrs_ipv6.iter().map(|s| s.parse().unwrap()).collect() }
  /// port on which to listen for connections on specified addresses
  pub fn get_listen_port(&self) -> u16 { self.listen_port.unwrap_or(DEFAULT_PORT) }
  /// default timeout for all TCP connections before forceably shutdown
  pub fn get_tcp_request_timeout(&self) -> Duration { Duration::from_secs(self.tcp_request_timeout.unwrap_or(DEFAULT_TCP_REQUEST_TIMEOUT)) }

  // TODO: also support env_logger
  /// specify the log level which should be used, ["Trace", "Debug", "Info", "Warn", "Error"]
  pub fn get_log_level(&self) -> LogLevel {
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
  /// the path for all zone configurations, defaults to `/var/named`
  pub fn get_directory(&self) -> &Path { self.directory.as_ref().map_or(Path::new(DEFAULT_PATH), |s|Path::new(s)) }
  /// the set of zones which should be loaded
  pub fn get_zones(&self) -> &[ZoneConfig] { &self.zones }
}

impl FromStr for Config {
  type Err = ConfigError;

  fn from_str(toml: &str) -> ConfigResult<Config> {
    let value: Value = try!(toml.parse().map_err(|vec| ConfigErrorKind::VecParserError(vec)));
    let mut decoder: Decoder = Decoder::new(value);
    Ok(try!(Self::decode(&mut decoder)))
  }
}

#[derive(RustcDecodable, PartialEq, Debug)]
pub struct ZoneConfig {
  zone: String, // TODO: make Domain::Name decodable
  zone_type: ZoneType,
  file: String,
  allow_update: Option<bool>,
  enable_dnssec: Option<bool>,
  keys: Vec<KeyConfig>,
}

impl ZoneConfig {
  pub fn new(zone: String, zone_type: ZoneType, file: String, allow_update: Option<bool>,
             enable_dnssec: Option<bool>, keys: Vec<KeyConfig>) -> Self {
    ZoneConfig{zone: zone, zone_type: zone_type, file: file, allow_update: allow_update,
               enable_dnssec: enable_dnssec, keys: keys}
  }

  // TODO this is a little ugly for the parse, b/c there is no terminal char
  /// retuns the name of the Zone, i.e. the `example.com` of `www.example.com.`
  pub fn get_zone(&self) -> ParseResult<Name> { Name::parse(&self.zone, Some(&Name::new())) }

  /// the type of the zone
  pub fn get_zone_type(&self) -> ZoneType { self.zone_type }

  /// path to the zone file, i.e. the base set of original records in the zone
  ///
  /// this is ony used on first load, if dynamic update is enabled for the zone, then the journal
  /// file is the actual source of truth for the zone.
  pub fn get_file(&self) -> PathBuf { PathBuf::from(&self.file) }

  /// enable dynamic updates for the zone (see SIG0 and the registered keys)
  pub fn is_update_allowed(&self) -> bool { self.allow_update.unwrap_or(false) }

  /// declare that this zone should be signed, see keys for configuration of the keys for signing
  pub fn is_dnssec_enabled(&self) -> bool { self.enable_dnssec.unwrap_or(false) }

  /// the configuration for the keys used for auth and/or dnssec zone signing.
  pub fn get_keys(&self) -> &[KeyConfig] {
    &self.keys
  }
}

#[derive(RustcDecodable, PartialEq, Debug)]
pub struct KeyConfig {
  key_path: String,
  password: Option<String>,
  algorithm: String,
  signer_name: Option<String>,
  is_zone_signing_key: Option<bool>,
  is_zone_update_auth: Option<bool>,
  do_auto_generate: Option<bool>,
}

impl KeyConfig {
  pub fn new(key_path: String, password: Option<String>, algorithm: Algorithm, signer_name: String,
    is_zone_signing_key: bool, is_zone_update_auth: bool, do_auto_generate: bool) -> Self {
    KeyConfig{ key_path: key_path, password: password, algorithm: algorithm.to_str().to_string(), signer_name: Some(signer_name),
      is_zone_signing_key: Some(is_zone_signing_key), is_zone_update_auth: Some(is_zone_update_auth),
      do_auto_generate: Some(do_auto_generate)
    }
  }

  /// path to the key file, either relative to the zone file, or a explicit from the root.
  pub fn get_key_path(&self) -> &Path { Path::new(&self.key_path) }

  /// Converts key into
  pub fn get_format(&self) -> ParseResult<KeyFormat> {
    let extension = try!(self.get_key_path().extension().ok_or(ParseErrorKind::Msg(format!("file lacks extension, e.g. '.p12': {:?}", self.get_key_path()).into() )));

    match extension.to_str() {
      Some("der") => Ok(KeyFormat::Der),
      Some("key") => Ok(KeyFormat::Pem), // TODO: deprecate this...
      Some("pem") => Ok(KeyFormat::Pem),
      Some("raw") => Ok(KeyFormat::Raw),
      e @ _ => Err(ParseErrorKind::Msg(format!("extension not understood, '{:?}': {:?}", e, self.get_key_path() )).into() ),
    }
  }

  pub fn get_password(&self) -> Option<&str> { self.password.as_ref().map(|s|s.as_str()) }

  /// algorithm for for the key, see `Algorithm` for supported algorithms.
  pub fn get_algorithm(&self) -> ParseResult<Algorithm> { Algorithm::from_str(&self.algorithm).map_err(|e|e.into()) }

  /// the signer name for the key, this defaults to the $ORIGIN aka zone name.
  pub fn get_signer_name(&self) -> ParseResult<Option<Name>> {
    if let Some(ref signer_name) = self.signer_name.as_ref() {
      let name = try!(Name::parse(signer_name, None));
      return Ok(Some(name))
    }

    Ok(None)
  }

  /// specifies that this key should be used to sign the zone
  ///
  /// The public key for this must be trusted by a resolver to work. The key must have a private
  /// portion associated with it. It will be registered as a DNSKEY in the zone.
  pub fn is_zone_signing_key(&self) -> bool { self.is_zone_signing_key.unwrap_or(false) }

  /// this is at least a public_key, and can be used for SIG0 dynamic updates.
  ///
  /// it will be registered as a KEY record in the zone.
  pub fn is_zone_update_auth(&self) -> bool { self.is_zone_update_auth.unwrap_or(false) }

  /// auto generate/create the key if it doesn't already exist (the public portion can be
  /// retrieved by a DNS query to the zone for DNSKEY and KEY records).
  pub fn do_auto_generate(&self) -> bool { self.do_auto_generate.unwrap_or(false) }
}
