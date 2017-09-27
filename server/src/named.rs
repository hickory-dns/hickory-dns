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
//!    --tls-port=PORT         Override the listening port for TLS connections
//! ```

extern crate chrono;
extern crate docopt;
#[macro_use]
extern crate log;
extern crate openssl;
extern crate rustc_serialize;
extern crate trust_dns;
extern crate trust_dns_server;

use std::fs;
use std::fs::File;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, IpAddr, SocketAddr, TcpListener, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::io::{Read, Write};

use chrono::Duration;
use docopt::Docopt;
use log::LogLevel;
use openssl::asn1::*;
use openssl::bn::*;
use openssl::{hash, nid};
use openssl::pkcs12::{ParsedPkcs12, Pkcs12};
use openssl::pkey::PKey;
use openssl::x509::*;
use openssl::x509::extension::*;

use trust_dns::error::{DnsSecResult, ParseResult};
use trust_dns::logger;
use trust_dns::version;
use trust_dns::serialize::txt::{Lexer, Parser};
use trust_dns::rr::Name;
use trust_dns::rr::dnssec::{Algorithm, KeyPair, Signer};

use trust_dns_server::authority::{Authority, Catalog, Journal, ZoneType};
use trust_dns_server::config::{Config, KeyConfig, TlsCertConfig, ZoneConfig};
use trust_dns_server::server::ServerFuture;

// the Docopt usage string.
//  http://docopt.org
// TODO: add option for specifying list of addresses instead of just port.
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
    --tls-port=PORT         Override the listening port for TLS connections
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
    pub flag_tls_port: Option<u16>,
}

fn parse_file(
    file: File,
    origin: Option<Name>,
    zone_type: ZoneType,
    allow_update: bool,
    is_dnssec_enabled: bool,
) -> ParseResult<Authority> {
    let mut file = file;
    let mut buf = String::new();

    // TODO, this should really use something to read line by line or some other method to
    //  keep the usage down. and be a custom lexer...
    try!(file.read_to_string(&mut buf));
    let lexer = Lexer::new(&buf);
    let (origin, records) = try!(Parser::new().parse(lexer, origin));

    Ok(Authority::new(
        origin,
        records,
        zone_type,
        allow_update,
        is_dnssec_enabled,
    ))
}

fn load_zone(zone_dir: &Path, zone_config: &ZoneConfig) -> Result<Authority, String> {
    let zone_name: Name = zone_config.get_zone().expect("bad zone name");
    let zone_path: PathBuf = zone_dir.to_owned().join(zone_config.get_file());
    let journal_path: PathBuf = zone_path.with_extension("jrnl");
    let original_key_path: PathBuf = zone_path.with_extension("key");

    // load the zone
    let mut authority = if zone_config.is_update_allowed() && journal_path.exists() {
        info!("recovering zone from journal: {:?}", journal_path);
        let journal = try!(Journal::from_file(&journal_path).map_err(|e| {
            format!("error opening journal: {:?}: {}", journal_path, e)
        }));

        let mut authority = Authority::new(
            zone_name.clone(),
            BTreeMap::new(),
            zone_config.get_zone_type(),
            zone_config.is_update_allowed(),
            zone_config.is_dnssec_enabled(),
        );
        try!(authority.recover_with_journal(&journal).map_err(|e| {
            format!("error recovering from journal: {}", e)
        }));

        authority.set_journal(journal);
        info!("recovered zone: {}", zone_name);

        authority
    } else if zone_path.exists() {
        info!("loading zone file: {:?}", zone_path);

        let zone_file = try!(File::open(&zone_path).map_err(|e| {
            format!("error opening zone file: {:?}: {}", zone_path, e)
        }));

        let mut authority = try!(
            parse_file(
                zone_file,
                Some(zone_name.clone()),
                zone_config.get_zone_type(),
                zone_config.is_update_allowed(),
                zone_config.is_dnssec_enabled(),
            ).map_err(|e| format!("error reading zone: {:?}: {}", zone_path, e))
        );

        // if dynamic update is enabled, enable the journal
        if zone_config.is_update_allowed() {
            info!("enabling journal: {:?}", journal_path);
            let journal = try!(Journal::from_file(&journal_path).map_err(|e| {
                format!("error creating journal {:?}: {}", journal_path, e)
            }));

            authority.set_journal(journal);

            // preserve to the new journal, i.e. we just loaded the zone from disk, start the journal
            try!(authority.persist_to_journal().map_err(|e| {
                format!("error persisting to journal {:?}: {}", journal_path, e)
            }));
        }

        info!("loaded zone: {}", zone_name);
        authority
    } else {
        return Err(format!("no zone file defined at: {:?}", zone_path));
    };

    // load any keys for the Zone, if it is a dynamic update zone, then keys are required
    if zone_config.is_dnssec_enabled() {
        // old backward compatible logic, TODO: deprecated
        if zone_config.get_keys().is_empty() {
            // original RSA key construction
            let key_config = KeyConfig::new(
                original_key_path.to_string_lossy().to_string(),
                None,
                Algorithm::RSASHA256,
                zone_name.clone().to_string(),
                true,
                true,
                true,
            );
            let signer = try!(load_key(zone_name, &key_config).map_err(|e| {
                format!("failed to load key: {:?} msg: {}", key_config.key_path(), e)
            }));
            info!(
                "adding key to zone: {:?}, is_zsk: {}, is_auth: {}",
                key_config.key_path(),
                key_config.is_zone_signing_key(),
                key_config.is_zone_update_auth()
            );
            authority.add_secure_key(signer).expect(
                "failed to add key to authority",
            );
        } else {
            for key_config in zone_config.get_keys() {
                let signer = try!(load_key(zone_name.clone(), &key_config).map_err(|e| {
                    format!("failed to load key: {:?} msg: {}", key_config.key_path(), e)
                }));
                info!(
                    "adding key to zone: {:?}, is_zsk: {}, is_auth: {}",
                    key_config.key_path(),
                    key_config.is_zone_signing_key(),
                    key_config.is_zone_update_auth()
                );
                authority.add_secure_key(signer).expect(
                    "failed to add key to authority",
                );
            }
        }

        authority.secure_zone().expect("failed to sign zone");
    }

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
fn load_key(zone_name: Name, key_config: &KeyConfig) -> Result<Signer, String> {
    let key_path = key_config.key_path();
    let algorithm = try!(key_config.algorithm().map_err(
        |e| format!("bad algorithm: {}", e),
    ));
    let format = try!(key_config.format().map_err(
        |e| format!("bad key format: {}", e),
    ));

    // generate and write a new key if it does not exist
    if !key_path.exists() && key_config.create_if_absent() {
        info!("creating key: {:?}", key_path);

        // TODO: establish proper ownership
        let mut file = try!(File::create(&key_path).map_err(|e| {
            format!("error creating private key file: {:?}: {}", key_path, e)
        }));

        let key_bytes: Vec<u8> = try!(
            format
                .generate_and_encode(algorithm, key_config.password())
                .map_err(|e| format!("could not generate key: {}", e))
        );

        try!(
            file.write_all(&key_bytes)
                .or_else(|_| fs::remove_file(&key_path))
                .map_err(|e| {
                    format!("error writing private key file: {:?}: {}", key_path, e)
                })
        );
    }

    // read the key in
    let key: KeyPair = if key_path.exists() {
        info!("reading key: {:?}", key_path);

        let mut file = try!(File::open(&key_path).map_err(|e| {
            format!("error opening private key file: {:?}: {}", key_path, e)
        }));

        let mut key_bytes = Vec::with_capacity(256);
        try!(file.read_to_end(&mut key_bytes).map_err(|e| {
            format!("could not read key from: {:?}: {}", key_path, e)
        }));

        try!(
            format
                .decode_key(&key_bytes, key_config.password(), algorithm)
                .map_err(|e| format!("could not decode key: {}", e))
        )
    } else {
        return Err(format!("file not found: {:?}", key_path));
    };

    let name = try!(key_config.signer_name().map_err(|e| {
        format!("error reading name: {}", e)
    })).unwrap_or(zone_name);

    // add the key to the zone
    // TODO: allow the duration of signatutes to be customized
    let dnskey = try!(key.to_dnskey(algorithm).map_err(|e| {
        format!("error converting to dnskey: {}", e)
    }));
    Ok(Signer::dnssec(
        dnskey.clone(),
        key,
        name,
        Duration::weeks(52),
    ))
}

fn read_cert(path: &Path, password: Option<&str>) -> Result<ParsedPkcs12, String> {
    let mut file = try!(File::open(&path).map_err(|e| {
        format!("error opening pkcs12 cert file: {:?}: {}", path, e)
    }));

    let mut key_bytes = vec![];
    try!(file.read_to_end(&mut key_bytes).map_err(|e| {
        format!("could not read pkcs12 key from: {:?}: {}", path, e)
    }));
    let pkcs12 = try!(Pkcs12::from_der(&key_bytes).map_err(|e| {
        format!("badly formated pkcs12 key from: {:?}: {}", path, e)
    }));
    pkcs12.parse(password.unwrap_or("")).map_err(|e| {
        format!("failed to open pkcs12 from: {:?}: {}", path, e)
    })
}

fn load_cert(zone_dir: &Path, tls_cert_config: &TlsCertConfig) -> Result<ParsedPkcs12, String> {
    let path = zone_dir.to_owned().join(tls_cert_config.get_path());
    let password = tls_cert_config.get_password();
    let subject_name = tls_cert_config.get_subject_name();

    if path.exists() {
        info!("reading TLS certificate from: {:?}", path);
        read_cert(&path, password)
    } else if tls_cert_config.create_if_absent() {
        info!("generating RSA certificate: {:?}", path);
        let key_pair = try!(KeyPair::generate(Algorithm::RSASHA256).map_err(|e| {
            format!("error generating key: {:?}: {}", path, e)
        }));
        if let KeyPair::RSA(pkey) = key_pair {
            let (cert, pkcs12) = try!(generate_cert(subject_name, pkey, password).map_err(|e| {
                format!("error generating certificate: {}", e)
            }));

            // write out the cert file
            let cert_path = path.with_extension("cert");
            if cert_path.exists() {
                return Err(format!("certificate file exists: {:?}", cert_path));
            }

            let cert_der = cert.to_der().unwrap();
            let mut file = File::create(&cert_path).unwrap();
            file.write_all(&cert_der)
                .or_else(|_| fs::remove_file(&cert_path))
                .unwrap();

            // write out to the file
            // TODO: establish proper ownership of the file
            // TODO: generate and write CSR
            let pkcs12_der = pkcs12.to_der().unwrap();
            let mut file = try!(File::create(&path).map_err(|e| {
                format!("error creating pkcs12 file: {:?}: {}", path, e)
            }));

            try!(
                file.write_all(&pkcs12_der)
                    .or_else(|_| fs::remove_file(&path))
                    .map_err(|e| {
                        format!("error writing pkcs12 cert file: {:?}: {}", path, e)
                    })
            );
        } else {
            panic!("the interior key was not an EC, something changed")
        }

        read_cert(&path, password)
    } else {
        Err(format!("TLS certificate not found: {:?}", path))
    }
}

/// generates a certificate
fn generate_cert(
    subject_name: &str,
    pkey: PKey,
    password: Option<&str>,
) -> DnsSecResult<(X509, Pkcs12)> {
    let mut x509_name = try!(X509NameBuilder::new());
    try!(x509_name.append_entry_by_nid(nid::COMMONNAME, subject_name));
    let x509_name = x509_name.build();

    let mut serial: BigNum = try!(BigNum::new());
    try!(serial.pseudo_rand(32, MSB_MAYBE_ZERO, false));
    let serial = try!(serial.to_asn1_integer());

    let mut x509_build = try!(X509::builder());
    try!(Asn1Time::days_from_now(0).and_then(
        |t| x509_build.set_not_before(&t),
    ));
    try!(Asn1Time::days_from_now(256).and_then(
        |t| x509_build.set_not_after(&t),
    ));
    try!(x509_build.set_issuer_name(&x509_name));
    try!(x509_build.set_subject_name(&x509_name));
    try!(x509_build.set_pubkey(&pkey));
    try!(x509_build.set_serial_number(&serial));

    let ext_key_usage = try!(ExtendedKeyUsage::new().server_auth().client_auth().build());
    try!(x509_build.append_extension(ext_key_usage));

    let subject_key_identifier = try!(SubjectKeyIdentifier::new().build(
        &x509_build.x509v3_context(
            None,
            None,
        ),
    ));
    try!(x509_build.append_extension(subject_key_identifier));

    let authority_key_identifier = try!(AuthorityKeyIdentifier::new().keyid(true).build(
        &x509_build.x509v3_context(None, None),
    ));
    try!(x509_build.append_extension(authority_key_identifier));

    let subject_alternative_name = try!(SubjectAlternativeName::new().dns(subject_name).build(
        &x509_build.x509v3_context(None, None),
    ));
    try!(x509_build.append_extension(subject_alternative_name));

    let basic_constraints = try!(BasicConstraints::new().critical().ca().build());
    try!(x509_build.append_extension(basic_constraints));

    try!(x509_build.sign(&pkey, hash::MessageDigest::sha256()));
    let cert = x509_build.build();

    let pkcs12_builder = Pkcs12::builder();
    let pkcs12 = try!(pkcs12_builder.build(
        password.unwrap_or(""),
        subject_name,
        &pkey,
        &cert,
    ));

    Ok((cert, pkcs12))
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

    let config_path = Path::new(args.flag_config.as_ref().map(|s| s as &str).unwrap_or(
        "/etc/named.toml",
    ));
    info!("loading configuration from: {:?}", config_path);
    let config = Config::read_config(config_path).expect(&format!(
        "could not read config: {:?}",
        config_path
    ));
    let zone_dir: &Path = args.flag_zonedir.as_ref().map(|s| Path::new(s)).unwrap_or(
        config.get_directory(),
    );

    let mut catalog: Catalog = Catalog::new();
    // configure our server based on the config_path
    for zone in config.get_zones() {
        let zone_name = zone.get_zone().expect(&format!(
            "bad zone name in {:?}",
            config_path
        ));

        match load_zone(zone_dir, zone) {
            Ok(authority) => catalog.upsert(zone_name, authority),
            Err(error) => error!("could not load zone {}: {}", zone_name, error),
        }
    }

    // TODO support all the IPs asked to listen on...
    // TODO, there should be the option to listen on any port, IP and protocol option...
    let v4addr = config.get_listen_addrs_ipv4();
    let v6addr = config.get_listen_addrs_ipv6();
    let mut listen_addrs: Vec<IpAddr> = v4addr
        .into_iter()
        .map(|x| IpAddr::V4(x))
        .chain(v6addr.into_iter().map(|x| IpAddr::V6(x)))
        .collect();
    let listen_port: u16 = args.flag_port.unwrap_or(config.get_listen_port());
    let tcp_request_timeout = config.get_tcp_request_timeout();

    if listen_addrs.len() == 0 {
        listen_addrs.push(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    }
    let sockaddrs: Vec<SocketAddr> = listen_addrs
        .iter()
        .flat_map(|x| (*x, listen_port).to_socket_addrs().unwrap())
        .collect();
    let udp_sockets: Vec<UdpSocket> = sockaddrs
        .iter()
        .map(|x| {
            UdpSocket::bind(x).expect(&format!("could not bind to udp: {}", x))
        })
        .collect();
    let tcp_listeners: Vec<TcpListener> = sockaddrs
        .iter()
        .map(|x| {
            TcpListener::bind(x).expect(&format!("could not bind to tcp: {}", x))
        })
        .collect();


    // now, run the server, based on the config
    let mut server = ServerFuture::new(catalog).expect("error creating ServerFuture");

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

    // and TLS as necessary
    if let Some(tls_cert_config) = config.get_tls_cert() {
        let tls_listen_port: u16 = args.flag_tls_port.unwrap_or(config.get_tls_listen_port());
        let tls_sockaddrs: Vec<SocketAddr> = listen_addrs
            .iter()
            .flat_map(|x| (*x, tls_listen_port).to_socket_addrs().unwrap())
            .collect();
        let tls_listeners: Vec<TcpListener> = tls_sockaddrs
            .iter()
            .map(|x| {
                TcpListener::bind(x).expect(&format!("could not bind to tls: {}", x))
            })
            .collect();
        if tls_listeners.is_empty() {
            warn!("a tls certificate was specified, but no TCP addresses configured to listen on");
        }

        for tls_listener in tls_listeners {
            info!(
                "loading cert for DNS over TLS: {:?}",
                tls_cert_config.get_path()
            );
            // TODO: see about modifying native_tls to impl Clone for Pkcs12
            let tls_cert =
                load_cert(zone_dir, tls_cert_config).expect("error loading tls certificate file");

            info!("listening for TLS on {:?}", tls_listener);
            server
                .register_tls_listener(tls_listener, tcp_request_timeout, tls_cert)
                .expect("could not register TLS listener");
        }
    }

    // config complete, starting!
    banner();
    info!("awaiting connections...");
    if let Err(e) = server.listen() {
        error!("failed to listen: {}", e);
    }

    // we're exiting for some reason...
    info!("Trust-DNS {} stopping", trust_dns::version());
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
