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

extern crate chrono;
#[macro_use]
extern crate clap;
extern crate futures;
#[macro_use]
extern crate log;
#[cfg(feature = "dns-over-rustls")]
extern crate rustls;
extern crate tokio;
extern crate tokio_tcp;
extern crate tokio_udp;
extern crate trust_dns;
#[cfg(feature = "dns-over-openssl")]
extern crate trust_dns_openssl;
#[cfg(feature = "dns-over-rustls")]
extern crate trust_dns_rustls;
extern crate trust_dns_server;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

#[cfg(feature = "dnssec")]
use chrono::Duration;
use clap::{Arg, ArgMatches};
use futures::{future, Future};
#[cfg(feature = "dns-over-rustls")]
use rustls::{Certificate, PrivateKey};
use tokio::runtime::current_thread::Runtime;
use tokio_tcp::TcpListener;
use tokio_udp::UdpSocket;

use trust_dns::error::ParseResult;
#[cfg(feature = "dnssec")]
use trust_dns::rr::dnssec::{KeyPair, Private, Signer};
use trust_dns::rr::Name;
use trust_dns::serialize::txt::{Lexer, Parser};

#[cfg(all(
    feature = "dns-over-openssl",
    not(feature = "dns-over-rustls")
))]
use trust_dns_openssl::tls_server::*;
use trust_dns_server::authority::{Catalog, ZoneType};
#[cfg(feature = "dnssec")]
use trust_dns_server::config::KeyConfig;
#[cfg(feature = "dns-over-tls")]
use trust_dns_server::config::TlsCertConfig;
use trust_dns_server::config::{Config, ZoneConfig};
use trust_dns_server::logger;
use trust_dns_server::server::ServerFuture;
use trust_dns_server::store::sqlite::{Journal, SqliteAuthority};

fn parse_zone_file(
    file: File,
    origin: Option<Name>,
    zone_type: ZoneType,
    allow_update: bool,
    allow_axfr: bool,
    is_dnssec_enabled: bool,
) -> ParseResult<SqliteAuthority> {
    let mut file = file;
    let mut buf = String::new();

    // TODO, this should really use something to read line by line or some other method to
    //  keep the usage down. and be a custom lexer...
    file.read_to_string(&mut buf)?;
    let lexer = Lexer::new(&buf);
    let (origin, records) = Parser::new().parse(lexer, origin)?;

    Ok(SqliteAuthority::new(
        origin,
        records,
        zone_type,
        allow_update,
        allow_axfr,
        is_dnssec_enabled,
    ))
}

#[cfg_attr(not(feature = "dnssec"), allow(unused_mut))]
fn load_zone(zone_dir: &Path, zone_config: &ZoneConfig) -> Result<SqliteAuthority, String> {
    debug!("loading zone with config: {:#?}", zone_config);

    let zone_name: Name = zone_config.get_zone().expect("bad zone name");
    let zone_path: PathBuf = zone_dir.to_owned().join(zone_config.get_file());
    let journal_path: PathBuf = zone_path.with_extension("jrnl");

    // load the zone
    let mut authority = if zone_config.is_update_allowed() && journal_path.exists() {
        info!("recovering zone from journal: {:?}", journal_path);
        let journal = Journal::from_file(&journal_path)
            .map_err(|e| format!("error opening journal: {:?}: {}", journal_path, e))?;

        let mut authority = SqliteAuthority::new(
            zone_name.clone(),
            BTreeMap::new(),
            zone_config.get_zone_type(),
            zone_config.is_update_allowed(),
            zone_config.is_axfr_allowed(),
            zone_config.is_dnssec_enabled(),
        );
        authority
            .recover_with_journal(&journal)
            .map_err(|e| format!("error recovering from journal: {}", e))?;

        authority.set_journal(journal);
        info!("recovered zone: {}", zone_name);

        authority
    } else if zone_path.exists() {
        info!("loading zone file: {:?}", zone_path);

        let zone_file = File::open(&zone_path)
            .map_err(|e| format!("error opening zone file: {:?}: {}", zone_path, e))?;

        let mut authority = parse_zone_file(
            zone_file,
            Some(zone_name.clone()),
            zone_config.get_zone_type(),
            zone_config.is_update_allowed(),
            zone_config.is_axfr_allowed(),
            zone_config.is_dnssec_enabled(),
        ).map_err(|e| format!("error reading zone: {:?}: {}", zone_path, e))?;

        // if dynamic update is enabled, enable the journal
        if zone_config.is_update_allowed() {
            info!("enabling journal: {:?}", journal_path);
            let journal = Journal::from_file(&journal_path)
                .map_err(|e| format!("error creating journal {:?}: {}", journal_path, e))?;

            authority.set_journal(journal);

            // preserve to the new journal, i.e. we just loaded the zone from disk, start the journal
            authority
                .persist_to_journal()
                .map_err(|e| format!("error persisting to journal {:?}: {}", journal_path, e))?;
        }

        info!("zone file loaded: {}", zone_name);
        authority
    } else {
        return Err(format!("no zone file defined at: {:?}", zone_path));
    };

    #[cfg(feature = "dnssec")]
    fn load_keys(
        authority: &mut SqliteAuthority,
        zone_name: Name,
        zone_config: &ZoneConfig,
    ) -> Result<(), String> {
        if zone_config.is_dnssec_enabled() {
            for key_config in zone_config.get_keys() {
                let signer = load_key(zone_name.clone(), key_config).map_err(|e| {
                    format!("failed to load key: {:?} msg: {}", key_config.key_path(), e)
                })?;
                info!(
                    "adding key to zone: {:?}, is_zsk: {}, is_auth: {}",
                    key_config.key_path(),
                    key_config.is_zone_signing_key(),
                    key_config.is_zone_update_auth()
                );
                authority
                    .add_secure_key(signer)
                    .expect("failed to add key to authority");
            }

            info!("signing zone: {}", zone_config.get_zone().unwrap());
            authority.secure_zone().expect("failed to sign zone");
        }
        Ok(())
    }

    #[cfg(not(feature = "dnssec"))]
    fn load_keys(
        _authority: &mut SqliteAuthority,
        _zone_name: Name,
        _zone_config: &ZoneConfig,
    ) -> Result<(), String> {
        Ok(())
    }

    // load any keys for the Zone, if it is a dynamic update zone, then keys are required
    load_keys(&mut authority, zone_name, zone_config)?;

    info!(
        "zone successfully loaded: {}",
        zone_config.get_zone().unwrap()
    );
    Ok(authority)
}

/// set of DNSSEC algorithms to use to sign the zone. enable_dnssec must be true.
/// these will be lookedup by $file.{key_name}.pem, for backward compatability
/// with previous versions of TRust-DNS, if enable_dnssec is enabled but
/// supported_algorithms is not specified, it will default to "RSASHA256" and
/// look for the $file.pem for the key. To control key length, or other options
/// keys of the specified formats can be generated in PEM format. Instructions
/// for custom keys can be found elsewhere.
///
/// the currently supported set of supported_algorithms are
/// ["RSASHA256", "RSASHA512", "ECDSAP256SHA256", "ECDSAP384SHA384", "ED25519"]
///
/// keys are listed in pairs of key_name and algorithm, the search path is the
/// same directory has the zone $file:
///  keys = [ "my_rsa_2048|RSASHA256", "/path/to/my_ed25519|ED25519" ]
#[cfg(feature = "dnssec")]
fn load_key(zone_name: Name, key_config: &KeyConfig) -> Result<Signer, String> {
    let key_path = key_config.key_path();
    let algorithm = key_config
        .algorithm()
        .map_err(|e| format!("bad algorithm: {}", e))?;
    let format = key_config
        .format()
        .map_err(|e| format!("bad key format: {}", e))?;

    // read the key in
    let key: KeyPair<Private> = {
        info!("reading key: {:?}", key_path);

        let mut file = File::open(&key_path)
            .map_err(|e| format!("error opening private key file: {:?}: {}", key_path, e))?;

        let mut key_bytes = Vec::with_capacity(256);
        file.read_to_end(&mut key_bytes)
            .map_err(|e| format!("could not read key from: {:?}: {}", key_path, e))?;

        format
            .decode_key(&key_bytes, key_config.password(), algorithm)
            .map_err(|e| format!("could not decode key: {}", e))?
    };

    let name = key_config
        .signer_name()
        .map_err(|e| format!("error reading name: {}", e))?
        .unwrap_or(zone_name);

    // add the key to the zone
    // TODO: allow the duration of signatutes to be customized
    let dnskey = key
        .to_dnskey(algorithm)
        .map_err(|e| format!("error converting to dnskey: {}", e))?;
    Ok(Signer::dnssec(
        dnskey.clone(),
        key,
        name,
        Duration::weeks(52),
    ))
}

#[cfg(all(
    feature = "dns-over-openssl",
    not(feature = "dns-over-rustls")
))]
fn load_cert(
    zone_dir: &Path,
    tls_cert_config: &TlsCertConfig,
) -> Result<((X509, Option<Stack<X509>>), PKey<Private>), String> {
    use trust_dns_openssl::tls_server::{read_cert_pem, read_cert_pkcs12, read_key_from_der};
    use trust_dns_server::config::{CertType, PrivateKeyType};

    let path = zone_dir.to_owned().join(tls_cert_config.get_path());
    let cert_type = tls_cert_config.get_cert_type();
    let password = tls_cert_config.get_password();
    let private_key_path = tls_cert_config
        .get_private_key()
        .map(|p| zone_dir.to_owned().join(p));
    let private_key_type = tls_cert_config.get_private_key_type();

    // if it's pkcs12, we'll be collecting the key and certs from that, otherwise continue processing
    let (cert, cert_chain) = match cert_type {
        CertType::Pem => {
            info!("loading TLS PEM certificate from: {:?}", path);
            read_cert_pem(&path)?
        }
        CertType::Pkcs12 => {
            if private_key_path.is_some() {
                warn!(
                    "ignoring specified key, using the one in the PKCS12 file: {}",
                    path.display()
                );
            }
            info!("loading TLS PKCS12 certificate from: {:?}", path);
            return read_cert_pkcs12(&path, password).map_err(Into::into);
        }
    };

    // it wasn't plcs12, we need to load the key separately
    let key = match (private_key_path, private_key_type) {
        (Some(private_key_path), PrivateKeyType::Pkcs8) => {
            info!("loading TLS PKCS8 key from: {}", private_key_path.display());
            read_key_from_pkcs8(&private_key_path, password)?
        }
        (Some(private_key_path), PrivateKeyType::Der) => {
            info!("loading TLS DER key from: {}", private_key_path.display());
            read_key_from_der(&private_key_path)?
        }
        (None, _) => {
            return Err(format!(
                "No private key associated with specified certificate"
            ))
        }
    };

    Ok(((cert, cert_chain), key))
}

#[cfg(feature = "dns-over-rustls")]
fn load_cert(
    zone_dir: &Path,
    tls_cert_config: &TlsCertConfig,
) -> Result<(Vec<Certificate>, PrivateKey), String> {
    use trust_dns_rustls::tls_server::{read_cert, read_key_from_der, read_key_from_pkcs8};
    use trust_dns_server::config::{CertType, PrivateKeyType};

    let path = zone_dir.to_owned().join(tls_cert_config.get_path());
    let cert_type = tls_cert_config.get_cert_type();
    let password = tls_cert_config.get_password();
    let private_key_path = tls_cert_config
        .get_private_key()
        .map(|p| zone_dir.to_owned().join(p));
    let private_key_type = tls_cert_config.get_private_key_type();

    let cert = match cert_type {
        CertType::Pem => {
            info!("loading TLS PEM certificate chain from: {}", path.display());
            read_cert(&path).map_err(|e| format!("error reading cert: {}", e))?
        }
        CertType::Pkcs12 => {
            return Err(
                "PKCS12 is not supported with Rustls for certificate, use PEM encoding".to_string(),
            )
        }
    };

    let key = match (private_key_path, private_key_type) {
        (Some(private_key_path), PrivateKeyType::Pkcs8) => {
            info!("loading TLS PKCS8 key from: {}", private_key_path.display());
            if password.is_some() {
                warn!("Password for key supplied, but Rustls does not support encrypted PKCS8");
            }

            read_key_from_pkcs8(&private_key_path)?
        }
        (Some(private_key_path), PrivateKeyType::Der) => {
            info!("loading TLS DER key from: {}", private_key_path.display());
            read_key_from_der(&private_key_path)?
        }
        (None, _) => return Err("No private key associated with specified certificate".to_string()),
    };

    Ok((cert, key))
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
                .map(|s| s.to_string())
                .expect("config path should have had default"),
            flag_zonedir: matches.value_of(ZONEDIR_ARG).map(|s| s.to_string()),
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
        ).arg(
            Arg::with_name(DEBUG_ARG)
                .long(DEBUG_ARG)
                .short("d")
                .help("Turn on DEBUG messages (default is only INFO)")
                .conflicts_with(QUIET_ARG),
        ).arg(
            Arg::with_name(CONFIG_ARG)
                .long(CONFIG_ARG)
                .short("c")
                .help("Path to configuration file")
                .value_name("FILE")
                .default_value("/etc/named.toml"),
        ).arg(
            Arg::with_name(ZONEDIR_ARG)
                .long(ZONEDIR_ARG)
                .short("z")
                .help("Path to the root directory for all zone files, see also config toml")
                .value_name("DIR"),
        ).arg(
            Arg::with_name(PORT_ARG)
                .long(PORT_ARG)
                .short("p")
                .help("Listening port for DNS queries, overrides any value in config file")
                .value_name(PORT_ARG),
        ).arg(
            Arg::with_name(TLS_PORT_ARG)
                .long(TLS_PORT_ARG)
                .help("Listening port for DNS over TLS queries, overrides any value in config file")
                .value_name(TLS_PORT_ARG),
        ).arg(
            Arg::with_name(HTTPS_PORT_ARG)
                .long(HTTPS_PORT_ARG)
                .help(
                    "Listening port for DNS over HTTPS queries, overrides any value in config file",
                ).value_name(HTTPS_PORT_ARG),
        ).get_matches();

    let args: Args = args.into();

    // TODO: this should be set after loading config, but it's necessary for initial log lines, no?
    if args.flag_quiet {
        logger::quiet();
    } else if args.flag_debug {
        logger::debug();
    } else {
        logger::default();
    }

    info!("Trust-DNS {} starting", trust_dns::version());
    // start up the server for listening

    let flag_config = args.flag_config.clone();
    let config_path = Path::new(&flag_config);
    info!("loading configuration from: {:?}", config_path);
    let config = Config::read_config(config_path)
        .unwrap_or_else(|_| panic!("could not read config: {:?}", config_path));
    let directory_config = config.get_directory().to_path_buf();
    let flag_zonedir = args.flag_zonedir.clone();
    let zone_dir: &Path = flag_zonedir
        .as_ref()
        .map(Path::new)
        .unwrap_or_else(|| &directory_config);

    let mut catalog: Catalog = Catalog::new();
    // configure our server based on the config_path
    for zone in config.get_zones() {
        let zone_name = zone
            .get_zone()
            .unwrap_or_else(|_| panic!("bad zone name in {:?}", config_path));

        match load_zone(zone_dir, zone) {
            Ok(authority) => catalog.upsert(zone_name.into(), Box::new(authority)),
            Err(error) => error!("could not load zone {}: {}", zone_name, error),
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
        .map(|x| UdpSocket::bind(x).unwrap_or_else(|_| panic!("could not bind to udp: {}", x)))
        .collect();
    let tcp_listeners: Vec<TcpListener> = sockaddrs
        .iter()
        .map(|x| TcpListener::bind(x).unwrap_or_else(|_| panic!("could not bind to tcp: {}", x)))
        .collect();

    let mut io_loop = Runtime::new().expect("error when creating tokio Runtime");

    // now, run the server, based on the config
    #[cfg_attr(not(feature = "dns-over-tls"), allow(unused_mut))]
    let mut server = ServerFuture::new(catalog);

    let server_future: Box<Future<Item = (), Error = ()> + Send> =
        Box::new(future::lazy(move || {
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
                    zone_dir,
                    &listen_addrs,
                );

                // setup HTTPS listeners
                #[cfg(feature = "dns-over-https")]
                config_https(
                    &args,
                    &mut server,
                    &config,
                    _tls_cert_config,
                    zone_dir,
                    &listen_addrs,
                );
            }

            // config complete, starting!
            banner();
            info!("awaiting connections...");

            /// TODO: how to do threads? should we do a bunch of listener threads and then query threads?
            /// Ideally the processing would be n-threads for recieving, which hand off to m-threads for
            ///  request handling. It would generally be the case that n <= m.
            info!("Server starting up");
            future::empty()
        }));

    if let Err(e) = io_loop.block_on(server_future.map_err(|_| {
        io::Error::new(
            io::ErrorKind::Interrupted,
            "Server stopping due to interruption",
        )
    })) {
        error!("failed to listen: {}", e);
    }

    // we're exiting for some reason...
    info!("Trust-DNS {} stopping", trust_dns::version());
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
    let tls_listen_port: u16 = args
        .flag_tls_port
        .unwrap_or_else(|| config.get_tls_listen_port());
    let tls_sockaddrs: Vec<SocketAddr> = listen_addrs
        .iter()
        .flat_map(|x| (*x, tls_listen_port).to_socket_addrs().unwrap())
        .collect();
    let tls_listeners: Vec<TcpListener> = tls_sockaddrs
        .iter()
        .map(|x| TcpListener::bind(x).unwrap_or_else(|_| panic!("could not bind to tls: {}", x)))
        .collect();
    if tls_listeners.is_empty() {
        warn!("a tls certificate was specified, but no TLS addresses configured to listen on");
    }

    for tls_listener in tls_listeners {
        info!(
            "loading cert for DNS over TLS: {:?}",
            tls_cert_config.get_path()
        );

        let tls_cert =
            load_cert(zone_dir, tls_cert_config).expect("error loading tls certificate file");

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
    let https_listen_port: u16 = args
        .flag_https_port
        .unwrap_or_else(|| config.get_https_listen_port());
    let https_sockaddrs: Vec<SocketAddr> = listen_addrs
        .iter()
        .flat_map(|x| (*x, https_listen_port).to_socket_addrs().unwrap())
        .collect();
    let https_listeners: Vec<TcpListener> = https_sockaddrs
        .iter()
        .map(|x| TcpListener::bind(x).unwrap_or_else(|_| panic!("could not bind to tls: {}", x)))
        .collect();
    if https_listeners.is_empty() {
        warn!("a tls certificate was specified, but no HTTPS addresses configured to listen on");
    }

    for https_listener in https_listeners {
        info!(
            "loading cert for DNS over TLS: {:?}",
            tls_cert_config.get_path()
        );
        // TODO: see about modifying native_tls to impl Clone for Pkcs12
        let tls_cert =
            load_cert(zone_dir, tls_cert_config).expect("error loading tls certificate file");

        info!("listening for HTTPS on {:?}", https_listener);
        server
        // FIXME: need to passthrough the DNS authority name
            .register_https_listener(https_listener, config.get_tcp_request_timeout(), tls_cert, "ns.example.com".to_string())
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
