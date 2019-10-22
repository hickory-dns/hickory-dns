// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

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
//!    --tls-port=PORT         Override the listening port for TLS connections
//! ```
#![recursion_limit = "128"]

extern crate chrono;
#[macro_use]
extern crate clap;
extern crate futures;
#[macro_use]
extern crate log;
#[cfg(feature = "dns-over-rustls")]
extern crate rustls;
extern crate tokio;
extern crate tokio_executor;
extern crate tokio_net;
extern crate trust_dns_client;
#[cfg(feature = "dns-over-openssl")]
extern crate trust_dns_openssl;
#[cfg(feature = "dns-over-rustls")]
extern crate trust_dns_rustls;
extern crate trust_dns_server;

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::pin::Pin;

use clap::{Arg, ArgMatches};
use futures::{future, Future};
use tokio::runtime::Runtime;
use tokio::runtime::TaskExecutor;
use tokio_net::tcp::TcpListener;
use tokio_net::udp::UdpSocket;

#[cfg(feature = "dnssec")]
use trust_dns_client::rr::rdata::key::KeyUsage;
use trust_dns_client::rr::Name;
use trust_dns_server::authority::{AuthorityObject, Catalog, ZoneType};
#[cfg(any(feature = "dns-over-tls", feature = "dnssec"))]
use trust_dns_server::config::dnssec::{self, TlsCertConfig};
use trust_dns_server::config::{Config, ZoneConfig};
use trust_dns_server::logger;
use trust_dns_server::server::ServerFuture;
use trust_dns_server::store::file::{FileAuthority, FileConfig};
#[cfg(feature = "trust-dns-resolver")]
use trust_dns_server::store::forwarder::ForwardAuthority;
#[cfg(feature = "sqlite")]
use trust_dns_server::store::sqlite::{SqliteAuthority, SqliteConfig};
use trust_dns_server::store::StoreConfig;

#[cfg_attr(not(feature = "dnssec"), allow(unused_mut, unused))]
fn load_zone(
    zone_dir: &Path,
    zone_config: &ZoneConfig,
    executor: &TaskExecutor,
) -> Result<Box<dyn AuthorityObject>, String> {
    debug!("loading zone with config: {:#?}", zone_config);

    let zone_name: Name = zone_config.get_zone().expect("bad zone name");
    let zone_name_for_signer = zone_name.clone();
    let zone_path: Option<String> = zone_config.file.clone();
    let zone_type: ZoneType = zone_config.get_zone_type();
    let is_axfr_allowed = zone_config.is_axfr_allowed();
    let is_dnssec_enabled = zone_config.is_dnssec_enabled();

    if zone_config.is_update_allowed() {
        warn!("allow_update is deprecated in [[zones]] section, it belongs in [[zones.stores]]");
    }

    // load the zone
    let mut authority: Box<dyn AuthorityObject> = match zone_config.stores {
        #[cfg(feature = "sqlite")]
        Some(StoreConfig::Sqlite(ref config)) => {
            if zone_path.is_some() {
                warn!("ignoring [[zones.file]] instead using [[zones.stores.zone_file_path]]");
            }

            SqliteAuthority::try_from_config(
                zone_name,
                zone_type,
                is_axfr_allowed,
                is_dnssec_enabled,
                Some(zone_dir),
                config,
            )
            .map(Box::new)?
        }
        Some(StoreConfig::File(ref config)) => {
            if zone_path.is_some() {
                warn!("ignoring [[zones.file]] instead using [[zones.stores.zone_file_path]]");
            }
            FileAuthority::try_from_config(
                zone_name,
                zone_type,
                is_axfr_allowed,
                Some(zone_dir),
                config,
            )
            .map(Box::new)?
        }
        #[cfg(feature = "trust-dns-resolver")]
        Some(StoreConfig::Forward(ref config)) => {
            let (forwarder, bg) = ForwardAuthority::try_from_config(zone_name, zone_type, config)?;

            executor.spawn(bg);
            Box::new(forwarder)
        }
        #[cfg(feature = "sqlite")]
        None if zone_config.is_update_allowed() => {
            warn!(
                "using deprecated SQLite load configuration, please move to [[zones.stores]] form"
            );
            let zone_file_path =
                zone_path.ok_or_else(|| "file is a necessary parameter of zone_config")?;
            let journal_file_path = PathBuf::from(zone_file_path.clone())
                .with_extension("jrnl")
                .to_str()
                .map(String::from)
                .ok_or_else(|| "non-unicode characters in file name")?;

            let config = SqliteConfig {
                zone_file_path,
                journal_file_path,
                allow_update: zone_config.is_update_allowed(),
            };

            SqliteAuthority::try_from_config(
                zone_name,
                zone_type,
                is_axfr_allowed,
                is_dnssec_enabled,
                Some(zone_dir),
                &config,
            )
            .map(Box::new)?
        }
        None => {
            let config = FileConfig {
                zone_file_path: zone_path
                    .ok_or_else(|| "file is a necessary parameter of zone_config")?,
            };
            FileAuthority::try_from_config(
                zone_name,
                zone_type,
                is_axfr_allowed,
                Some(zone_dir),
                &config,
            )
            .map(Box::new)?
        }
    };

    #[cfg(feature = "dnssec")]
    fn load_keys(
        authority: &mut dyn AuthorityObject,
        zone_name: Name,
        zone_config: &ZoneConfig,
    ) -> Result<(), String> {
        if zone_config.is_dnssec_enabled() {
            for key_config in zone_config.get_keys() {
                info!(
                    "adding key to zone: {:?}, is_zsk: {}, is_auth: {}",
                    key_config.key_path(),
                    key_config.is_zone_signing_key(),
                    key_config.is_zone_update_auth()
                );
                if key_config.is_zone_signing_key() {
                    let zone_signer =
                        key_config.try_into_signer(zone_name.clone()).map_err(|e| {
                            format!("failed to load key: {:?} msg: {}", key_config.key_path(), e)
                        })?;
                    authority
                        .add_zone_signing_key(zone_signer)
                        .expect("failed to add zone signing key to authority");
                }
                if key_config.is_zone_update_auth() {
                    let update_auth_signer =
                        key_config.try_into_signer(zone_name.clone()).map_err(|e| {
                            format!("failed to load key: {:?} msg: {}", key_config.key_path(), e)
                        })?;
                    let public_key = update_auth_signer
                        .key()
                        .to_sig0key_with_usage(update_auth_signer.algorithm(), KeyUsage::Host)
                        .expect("failed to get sig0 key");
                    authority
                        .add_update_auth_key(zone_name.clone(), public_key)
                        .expect("failed to add update auth key to authority");
                }
            }

            info!("signing zone: {}", zone_config.get_zone().unwrap());
            authority.secure_zone().expect("failed to sign zone");
        }
        Ok(())
    }

    #[cfg(not(feature = "dnssec"))]
    fn load_keys(
        _authority: &mut dyn AuthorityObject,
        _zone_name: Name,
        _zone_config: &ZoneConfig,
    ) -> Result<(), String> {
        Ok(())
    }

    // load any keys for the Zone, if it is a dynamic update zone, then keys are required
    load_keys(authority.as_mut(), zone_name_for_signer, zone_config)?;

    info!(
        "zone successfully loaded: {}",
        zone_config.get_zone().unwrap()
    );
    Ok(authority)
}

// argument name constants for the CLI options
const QUIET_ARG: &str = "quiet";
const DEBUG_ARG: &str = "debug";
const CONFIG_ARG: &str = "config";
const ZONEDIR_ARG: &str = "zonedir";
const PORT_ARG: &str = "port";
const TLS_PORT_ARG: &str = "tls-port";
const HTTPS_PORT_ARG: &str = "https-port";

/// Args struct for all options
struct Args {
    pub flag_quiet: bool,
    pub flag_debug: bool,
    pub flag_config: String,
    pub flag_zonedir: Option<String>,
    pub flag_port: Option<u16>,
    pub flag_tls_port: Option<u16>,
    pub flag_https_port: Option<u16>,
}

impl<'a> From<ArgMatches<'a>> for Args {
    fn from(matches: ArgMatches<'a>) -> Args {
        Args {
            flag_quiet: matches.is_present(QUIET_ARG),
            flag_debug: matches.is_present(DEBUG_ARG),
            flag_config: matches
                .value_of(CONFIG_ARG)
                .map(ToString::to_string)
                .expect("config path should have had default"),
            flag_zonedir: matches.value_of(ZONEDIR_ARG).map(ToString::to_string),
            flag_port: matches
                .value_of(PORT_ARG)
                .map(|s| u16::from_str_radix(s, 10).expect("bad port argument")),
            flag_tls_port: matches
                .value_of(TLS_PORT_ARG)
                .map(|s| u16::from_str_radix(s, 10).expect("bad tls-port argument")),
            flag_https_port: matches
                .value_of(HTTPS_PORT_ARG)
                .map(|s| u16::from_str_radix(s, 10).expect("bad https-port argument")),
        }
    }
}

/// Main method for running the named server.
///
/// `Note`: Tries to avoid panics, in favor of always starting.
pub fn main() {
    let args = app_from_crate!()
        .arg(
            Arg::with_name(QUIET_ARG)
                .long(QUIET_ARG)
                .short("q")
                .help("Disable INFO messages, WARN and ERROR will remain")
                .conflicts_with(DEBUG_ARG),
        )
        .arg(
            Arg::with_name(DEBUG_ARG)
                .long(DEBUG_ARG)
                .short("d")
                .help("Turn on DEBUG messages (default is only INFO)")
                .conflicts_with(QUIET_ARG),
        )
        .arg(
            Arg::with_name(CONFIG_ARG)
                .long(CONFIG_ARG)
                .short("c")
                .help("Path to configuration file")
                .value_name("FILE")
                .default_value("/etc/named.toml"),
        )
        .arg(
            Arg::with_name(ZONEDIR_ARG)
                .long(ZONEDIR_ARG)
                .short("z")
                .help("Path to the root directory for all zone files, see also config toml")
                .value_name("DIR"),
        )
        .arg(
            Arg::with_name(PORT_ARG)
                .long(PORT_ARG)
                .short("p")
                .help("Listening port for DNS queries, overrides any value in config file")
                .value_name(PORT_ARG),
        )
        .arg(
            Arg::with_name(TLS_PORT_ARG)
                .long(TLS_PORT_ARG)
                .help("Listening port for DNS over TLS queries, overrides any value in config file")
                .value_name(TLS_PORT_ARG),
        )
        .arg(
            Arg::with_name(HTTPS_PORT_ARG)
                .long(HTTPS_PORT_ARG)
                .help(
                    "Listening port for DNS over HTTPS queries, overrides any value in config file",
                )
                .value_name(HTTPS_PORT_ARG),
        )
        .get_matches();

    let args: Args = args.into();

    // TODO: this should be set after loading config, but it's necessary for initial log lines, no?
    if args.flag_quiet {
        logger::quiet();
    } else if args.flag_debug {
        logger::debug();
    } else {
        logger::default();
    }

    info!("Trust-DNS {} starting", trust_dns_client::version());
    // start up the server for listening

    let flag_config = args.flag_config.clone();
    let config_path = Path::new(&flag_config);
    info!("loading configuration from: {:?}", config_path);
    let config = Config::read_config(config_path)
        .unwrap_or_else(|e| panic!("could not read config {}: {:?}", config_path.display(), e));
    let directory_config = config.get_directory().to_path_buf();
    let flag_zonedir = args.flag_zonedir.clone();
    let zone_dir: PathBuf = flag_zonedir
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| directory_config.clone());

    let io_loop = Runtime::new().expect("error when creating tokio Runtime");
    let executor = io_loop.executor();
    let mut catalog: Catalog = Catalog::new();
    // configure our server based on the config_path
    for zone in config.get_zones() {
        let zone_name = zone
            .get_zone()
            .unwrap_or_else(|_| panic!("bad zone name in {:?}", config_path));

        match load_zone(&zone_dir, zone, &executor) {
            Ok(authority) => catalog.upsert(zone_name.into(), authority),
            Err(error) => panic!("could not load zone {}: {}", zone_name, error),
        }
    }

    // TODO: support all the IPs asked to listen on...
    // TODO:, there should be the option to listen on any port, IP and protocol option...
    let v4addr = config.get_listen_addrs_ipv4();
    let v6addr = config.get_listen_addrs_ipv6();
    let mut listen_addrs: Vec<IpAddr> = v4addr
        .into_iter()
        .map(IpAddr::V4)
        .chain(v6addr.into_iter().map(IpAddr::V6))
        .collect();
    let listen_port: u16 = args.flag_port.unwrap_or_else(|| config.get_listen_port());
    let tcp_request_timeout = config.get_tcp_request_timeout();

    if listen_addrs.is_empty() {
        listen_addrs.push(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    }
    let sockaddrs: Vec<SocketAddr> = listen_addrs
        .iter()
        .flat_map(|x| (*x, listen_port).to_socket_addrs().unwrap())
        .collect();
    let udp_sockets: Vec<UdpSocket> = sockaddrs
        .iter()
        .map(|x| {
            io_loop
                .block_on(UdpSocket::bind(x))
                .unwrap_or_else(|_| panic!("could not bind to udp: {}", x))
        })
        .collect();
    let tcp_listeners: Vec<TcpListener> = sockaddrs
        .iter()
        .map(|x| {
            io_loop
                .block_on(TcpListener::bind(x))
                .unwrap_or_else(|_| panic!("could not bind to tcp: {}", x))
        })
        .collect();

    // now, run the server, based on the config
    #[cfg_attr(not(feature = "dns-over-tls"), allow(unused_mut))]
    let mut server = ServerFuture::new(catalog);

    let server_future: Pin<Box<dyn Future<Output = ()> + Send>> =
        Box::pin(future::lazy(move |_| {
            // load all the listeners
            for udp_socket in udp_sockets {
                info!("listening for UDP on {:?}", udp_socket);
                server.register_socket(udp_socket);
            }

            // and TCP as necessary
            for tcp_listener in tcp_listeners {
                info!("listening for TCP on {:?}", tcp_listener);
                server
                    .register_listener(tcp_listener, tcp_request_timeout)
                    .expect("could not register TCP listener");
            }

            let tls_cert_config = config.get_tls_cert();

            // and TLS as necessary
            // TODO: we should add some more control from configs to enable/disable TLS/HTTPS
            if let Some(_tls_cert_config) = tls_cert_config {
                // setup TLS listeners
                // TODO: support rustls
                #[cfg(feature = "dns-over-tls")]
                config_tls(
                    &args,
                    &mut server,
                    &config,
                    _tls_cert_config,
                    &zone_dir,
                    &listen_addrs,
                );

                // setup HTTPS listeners
                #[cfg(feature = "dns-over-https")]
                config_https(
                    &args,
                    &mut server,
                    &config,
                    _tls_cert_config,
                    &zone_dir,
                    &listen_addrs,
                );
            }

            // config complete, starting!
            banner();
            info!("awaiting connections...");

            // TODO: how to do threads? should we do a bunch of listener threads and then query threads?
            // Ideally the processing would be n-threads for receiving, which hand off to m-threads for
            //  request handling. It would generally be the case that n <= m.
            info!("Server starting up");
        }));

    io_loop.spawn(server_future);
    io_loop.shutdown_on_idle();

    // we're exiting for some reason...
    info!("Trust-DNS {} stopping", trust_dns_client::version());
}

#[cfg(feature = "dns-over-tls")]
fn config_tls(
    args: &Args,
    server: &mut ServerFuture<Catalog>,
    config: &Config,
    tls_cert_config: &TlsCertConfig,
    zone_dir: &Path,
    listen_addrs: &[IpAddr],
) {
    use futures::executor::block_on;
    use futures::TryFutureExt;

    let tls_listen_port: u16 = args
        .flag_tls_port
        .unwrap_or_else(|| config.get_tls_listen_port());
    let tls_sockaddrs: Vec<SocketAddr> = listen_addrs
        .iter()
        .flat_map(|x| (*x, tls_listen_port).to_socket_addrs().unwrap())
        .collect();
    let tls_listeners: Vec<TcpListener> = tls_sockaddrs
        .iter()
        .map(|x| {
            block_on(
                TcpListener::bind(x).unwrap_or_else(|_| panic!("could not bind to tls: {}", x)),
            )
        })
        .collect();
    if tls_listeners.is_empty() {
        warn!("a tls certificate was specified, but no TLS addresses configured to listen on");
    }

    for tls_listener in tls_listeners {
        info!(
            "loading cert for DNS over TLS: {:?}",
            tls_cert_config.get_path()
        );

        let tls_cert = dnssec::load_cert(zone_dir, tls_cert_config)
            .expect("error loading tls certificate file");

        info!("listening for TLS on {:?}", tls_listener);
        server
            .register_tls_listener(tls_listener, config.get_tcp_request_timeout(), tls_cert)
            .expect("could not register TLS listener");
    }
}

#[cfg(feature = "dns-over-https")]
fn config_https(
    args: &Args,
    server: &mut ServerFuture<Catalog>,
    config: &Config,
    tls_cert_config: &TlsCertConfig,
    zone_dir: &Path,
    listen_addrs: &[IpAddr],
) {
    use futures::executor::block_on;
    use futures::TryFutureExt;

    let https_listen_port: u16 = args
        .flag_https_port
        .unwrap_or_else(|| config.get_https_listen_port());
    let https_sockaddrs: Vec<SocketAddr> = listen_addrs
        .iter()
        .flat_map(|x| (*x, https_listen_port).to_socket_addrs().unwrap())
        .collect();
    let https_listeners: Vec<TcpListener> = https_sockaddrs
        .iter()
        .map(|x| {
            block_on(
                TcpListener::bind(x).unwrap_or_else(|_| panic!("could not bind to tls: {}", x)),
            )
        })
        .collect();
    if https_listeners.is_empty() {
        warn!("a tls certificate was specified, but no HTTPS addresses configured to listen on");
    }

    for https_listener in https_listeners {
        info!(
            "loading cert for DNS over TLS named {} from {:?}",
            tls_cert_config.get_endpoint_name(),
            tls_cert_config.get_path()
        );
        // TODO: see about modifying native_tls to impl Clone for Pkcs12
        let tls_cert = dnssec::load_cert(zone_dir, tls_cert_config)
            .expect("error loading tls certificate file");

        info!("listening for HTTPS on {:?}", https_listener);
        server
            .register_https_listener(
                https_listener,
                config.get_tcp_request_timeout(),
                tls_cert,
                tls_cert_config.get_endpoint_name().to_string(),
            )
            .expect("could not register TLS listener");
    }
}

fn banner() {
    info!("");
    info!("    o                      o            o             ");
    info!("    |                      |            |             ");
    info!("  --O--  o-o  o  o  o-o  --O--  o-o   o-O  o-o   o-o  ");
    info!("    |    |    |  |   \\     |         |  |  |  |   \\   ");
    info!("    o    o    o--o  o-o    o          o-o  o  o  o-o  ");
    info!("");
}
