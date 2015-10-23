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
extern crate trust_dns;
extern crate rustc_serialize;
extern crate docopt;
#[macro_use] extern crate log;
extern crate mio;

use std::fs::File;
use std::path::{Path, PathBuf};
use std::net::Ipv4Addr;
use std::net::{SocketAddr, ToSocketAddrs};

use mio::tcp::TcpListener;
use log::LogLevel;
use docopt::Docopt;

use trust_dns::logger;
use trust_dns::version;
use trust_dns::authority::{Catalog, Authority};
use trust_dns::config::Config;
use trust_dns::serialize::txt::Parser;
use trust_dns::rr::Name;
use trust_dns::server::Server;

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

/// Main method for running the named server.
/// As of this writing, this will panic on any invalid input. At this top level binary is the only
///  part Trust-DNS where panics are allowed.
pub fn main() {
  // read any command line options
  let args: Args = Docopt::new(USAGE)
                        .and_then(|d| d.help(true).version(Some(trust_dns::version().into())).decode())
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
    let zone_name: Name = zone.get_zone().unwrap();
    let zone_path: PathBuf = zone_dir.to_owned().join(zone.get_file());
    info!("loading zone file: {:?}", zone_path);

    let zone_file = File::open(zone_path).unwrap();
    let authority: Authority = Parser::parse_file(zone_file, Some(zone_name.clone()), zone.get_zone_type(), zone.get_allow_udpate()).unwrap();

    catalog.upsert(zone_name, authority);
  }

  debug!("catalog: {:?}", catalog);

  // TODO support all the IPs asked to listen on...
  let listen_addr: Ipv4Addr = *config.get_listen_addrs_ipv4().first().unwrap_or(&Ipv4Addr::new(0,0,0,0));
  let listen_port: u16 = args.flag_port.unwrap_or(config.get_listen_port());
  let addr = (listen_addr, listen_port).to_socket_addrs().unwrap().next().unwrap();

  let tcp_listener: TcpListener = TcpListener::bind(&addr).unwrap();

  // now, run the server, based on the config
  info!("listening on {}:{}", listen_addr, listen_port);

  let mut server = Server::new(catalog);
  server.register_listener(tcp_listener);

  //let mut server = Server::new((listen_addr, listen_port), catalog).unwrap();
  //server.listen().unwrap();

  // we're exiting for some reason...
  info!("Trust-DNS {} stopping", trust_dns::version());
}
