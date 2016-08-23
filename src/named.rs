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

//! The `named` binary for running a DNS server
//!
//! ```text
//! Usage: named [options]
//!       named (-h | --help | --version)
//!
//! Options:
//!    -q, --quiet             Disable INFO messages, WARN and ERROR will remain
//!    -d, --debug             Turn on DEBUG messages (default is only INFO)
//!    -h, --help              Show this message
//!    -v, --version           Show the version of trust-dns
//!    -c FILE, --config=FILE  Path to configuration file, default is /etc/named.toml
//!    -z DIR, --zonedir=DIR   Path to the root directory for all zone files, see also config toml
//!    -p PORT, --port=PORT    Override the listening port
//! ```

extern crate trust_dns;
extern crate rustc_serialize;
extern crate docopt;
#[macro_use] extern crate log;
extern crate mio;
extern crate openssl;
extern crate chrono;

use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::net::ToSocketAddrs;

use chrono::{Duration};
use mio::tcp::TcpListener;
use mio::udp::UdpSocket;
use log::LogLevel;
use docopt::Docopt;
use openssl::crypto::pkey::PKey;

use trust_dns::logger;
use trust_dns::version;
use trust_dns::authority::{Authority, Catalog, Journal};
use trust_dns::config::{Config, ZoneConfig};
use trust_dns::serialize::txt::Parser;
use trust_dns::rr::Name;
use trust_dns::server::Server;
use trust_dns::rr::dnssec::{Algorithm, Signer};

// the Docopt usage string.
//  http://docopt.org
const USAGE: &'static str = "
Usage: named [options]
       named (-h | --help | --version)

Options:
    -q, --quiet             Disable INFO messages, WARN and ERROR will remain
    -d, --debug             Turn on DEBUG messages (default is only INFO)
    -h, --help              Show this message
    -v, --version           Show the version of trust-dns
    -c FILE, --config=FILE  Path to configuration file, default is /etc/named.toml
    -z DIR, --zonedir=DIR   Path to the root directory for all zone files, see also config toml
    -p PORT, --port=PORT    Override the listening port
";

#[derive(RustcDecodable)]
struct Args {
  pub flag_quiet: bool,
  pub flag_debug: bool,
  pub flag_help: bool,
  pub flag_version: bool,
  pub flag_config: Option<String>,
  pub flag_zonedir: Option<String>,
  pub flag_port: Option<u16>,
}

fn load_zone(zone_dir: &Path, zone: &ZoneConfig) -> Result<Authority, String> {
  let zone_name: Name = zone.get_zone().expect("bad zone name");
  let zone_path: PathBuf = zone_dir.to_owned().join(zone.get_file());
  let journal_path: PathBuf = zone_path.with_extension(".jrnl");
  let key_path: PathBuf = zone_path.with_extension(".key");

  // load the zone
  let mut authority = if zone.is_update_allowed() && journal_path.exists() {
    info!("recovering zone from journal: {:?}", journal_path);
    let journal = match Journal::from_file(&journal_path) {
      Ok(j) => j,
      Err(e) => return Err(format!("error opening journal: {:?}: {}", journal_path, e)),
    };

    let mut authority = Authority::new(zone_name.clone(), BTreeMap::new(),  zone.get_zone_type(), zone.is_update_allowed());
    if let Err(e) = authority.recover_with_journal(&journal) {
      return Err(format!("error recovering from journal: {}", e))
    }

    authority.journal(journal);
    info!("recovered zone: {}", zone_name);

    authority
  } else if zone_path.exists() {
    info!("loading zone file: {:?}", zone_path);

    let zone_file = match File::open(&zone_path) {
      Ok(f) => f,
      Err(e) => return Err(format!("error opening zone file: {:?}: {}", zone_path, e)),
    };

    let mut authority: Authority = match Parser::parse_file(zone_file, Some(zone_name.clone()), zone.get_zone_type(), zone.is_update_allowed()) {
      Ok(a) => a,
      Err(e) => return Err(format!("error reading zone: {:?}: {}", zone_path, e)),
    };

    // if dynamic update is enabled, enable the journal
    if zone.is_update_allowed() {
      info!("enabling journal: {:?}", journal_path);
      let journal = match Journal::from_file(&journal_path) {
        Ok(j) => j,
        Err(e) => return Err(format!("error creating journal {:?}: {}", journal_path, e)),
      };

      authority.journal(journal);

      // preserve to the new journal, i.e. we just loaded the zone from disk, start the journal
      if let Err(e) = authority.persist_to_journal() {
        return Err(format!("error persisting to journal {:?}: {}", journal_path, e))
      }
    }

    info!("loaded zone: {}", zone_name);
    authority
  } else {
    return Err(format!("no zone file defined at: {:?}", zone_path))
  };

  // load any keys for the Zone, if it is a dynamic update zone, then keys are required
  if zone.is_dnssec_enabled() {
    let pkey = if key_path.exists() {
      info!("reading key: {:?}", key_path);

      // TODO: validate owndership
      let mut file = match File::open(&key_path) {
        Ok(f) => f,
        Err(e) => return Err(format!("error opening private key file: {:?}: {}", key_path, e)),
      };

      match PKey::private_rsa_key_from_pem(&mut file) {
        Ok(pkey) => pkey,
        Err(e) => return Err(format!("error reading private key file: {:?}: {}", key_path, e)),
      }
    } else {
      info!("creating key: {:?}", key_path);

      // TODO: establish proper ownership
      let mut file = match File::create(&key_path) {
        Ok(f) => f,
        Err(e) => return Err(format!("error creating private key file: {:?}: {}", key_path, e))
      };

      let mut pkey: PKey = PKey::new();
      pkey.gen(2048);

      if let Err(e) = pkey.write_pem(&mut file) {
        fs::remove_file(&key_path).ok(); // ignored
        return Err(format!("error writing private key file: {:?}: {}", key_path, e))
      }

      pkey
    };

    // add the key to the zone
    // TODO: allow the duration of signatutes to be customized
    let signer = Signer::new(Algorithm::RSASHA256, pkey.into(), authority.get_origin().clone(), Duration::weeks(52));
    authority.add_secure_key(signer);
  }


  Ok(authority)
}

/// Main method for running the named server.
///
/// `Note`: Tries to avoid panics, in favor of always starting.
pub fn main() {
  // read any command line options
  let args: Args = Docopt::new(USAGE)
                        .and_then(|d| d.help(true).version(Some(version().into())).decode())
                        .unwrap_or_else(|e| e.exit());

  // TODO, this should be set after loading config, but it's necessary for initial log lines, no?
  if args.flag_quiet {
    logger::TrustDnsLogger::enable_logging(LogLevel::Warn);
  } else if args.flag_debug {
    logger::TrustDnsLogger::enable_logging(LogLevel::Debug);
  } else {
    logger::TrustDnsLogger::enable_logging(LogLevel::Info);
  }

  info!("Trust-DNS {} starting", trust_dns::version());
  // start up the server for listening

  let config_path = Path::new(args.flag_config.as_ref().map(|s| s as &str).unwrap_or("/etc/named.toml"));
  info!("loading configuration from: {:?}", config_path);
  let config = Config::read_config(config_path).unwrap();
  let zone_dir: &Path = args.flag_zonedir.as_ref().map(|s| Path::new(s)).unwrap_or(config.get_directory());

  let mut catalog: Catalog = Catalog::new();
  // configure our server based on the config_path
  for zone in config.get_zones() {
    let zone_name = zone.get_zone().expect(&format!("bad zone name in {:?}", config_path));

    match load_zone(zone_dir, zone) {
      Ok(authority) => catalog.upsert(zone_name, authority),
      Err(error) => error!("could not load zone {}: {}", zone_name, error),
    }
  }

  // TODO support all the IPs asked to listen on...
  let listen_addr_v4: Ipv4Addr = *config.get_listen_addrs_ipv4().first().unwrap_or(&Ipv4Addr::new(0,0,0,0));
  let listen_addr_v6: Ipv6Addr = *config.get_listen_addrs_ipv6().first().unwrap_or(&Ipv6Addr::new(0,0,0,0, 0,0,0,0));
  let listen_port: u16 = args.flag_port.unwrap_or(config.get_listen_port());

  let addr_v4 = (listen_addr_v4, listen_port).to_socket_addrs().unwrap().next().unwrap();
  let addr_v6 = (listen_addr_v6, listen_port).to_socket_addrs().unwrap().next().unwrap();

  let udp_sockets: Vec<UdpSocket> = vec![UdpSocket::bound(&addr_v4).unwrap(),
                                         UdpSocket::bound(&addr_v6).unwrap()];
  let tcp_listeners: Vec<TcpListener> = vec![TcpListener::bind(&addr_v4).unwrap(),
                                             TcpListener::bind(&addr_v6).unwrap()];


  // now, run the server, based on the config
  let mut server = Server::new(catalog);

  for udp_socket in udp_sockets {
    info!("listening for UDP on {:?}", udp_socket);
    server.register_socket(udp_socket);
  }

  for tcp_listener in tcp_listeners {
    info!("listening for TCP on {:?}", tcp_listener);
    server.register_listener(tcp_listener);
  }

  banner();
  if let Err(e) = server.listen() {
    error!("failed to listen: {}", e);
  }

  //let mut server = Server::new((listen_addr, listen_port), catalog).unwrap();
  //server.listen().unwrap();

  // we're exiting for some reason...
  info!("Trust-DNS {} stopping", trust_dns::version());
}

fn banner() {
  println!("   o                    o           o             ");
  println!("   |                    |           |             ");
  println!("  -o-  o-o  o  o  o-o  -o-  o-o   o-O  o-o   o-o  ");
  println!("   |   |    |  |   \\    |        |  |  |  |   \\   ");
  println!("   o   o    o--o  o-o   o         o-o  o  o  o-o  ");
  println!("                                                  ");
}
