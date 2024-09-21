// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The `hickory-dns` binary for running a DNS server
//!
//! ```text
//! Usage: hickory-dns [options]
//!       hickory-dns (-h | --help | --version)
//!
//! Options:
//!    -q, --quiet             Disable INFO messages, WARN and ERROR will remain
//!    -d, --debug             Turn on DEBUG messages (default is only INFO)
//!    -h, --help              Show this message
//!    -v, --version           Show the version of hickory-dns
//!    -c FILE, --config=FILE  Path to configuration file, default is /etc/named.toml
//!    -z DIR, --zonedir=DIR   Path to the root directory for all zone files, see also config toml
//!    -p PORT, --port=PORT    Override the listening port
//!    --tls-port=PORT         Override the listening port for TLS connections
//! ```

// BINARY WARNINGS
#![warn(
    clippy::dbg_macro,
    clippy::unimplemented,
    missing_copy_implementations,
    missing_docs,
    non_snake_case,
    non_upper_case_globals,
    rust_2018_idioms,
    unreachable_pub
)]
#![recursion_limit = "128"]
#![allow(clippy::redundant_clone)]

use std::{
    env, fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::Parser;
use time::OffsetDateTime;
use tokio::{
    net::{TcpListener, UdpSocket},
    runtime,
};
use tracing::{debug, error, info, warn, Event, Subscriber};
use tracing_subscriber::{
    fmt::{format, FmtContext, FormatEvent, FormatFields, FormattedFields},
    layer::SubscriberExt,
    registry::LookupSpan,
    util::SubscriberInitExt,
};

use hickory_proto::rr::Name;
#[cfg(feature = "dns-over-tls")]
use hickory_server::config::dnssec::{self, TlsCertConfig};
#[cfg(feature = "resolver")]
use hickory_server::store::forwarder::ForwardAuthority;
#[cfg(feature = "recursor")]
use hickory_server::store::recursor::RecursiveAuthority;
#[cfg(feature = "sqlite")]
use hickory_server::store::sqlite::{SqliteAuthority, SqliteConfig};
use hickory_server::{
    authority::{AuthorityObject, Catalog, ZoneType},
    config::{Config, ZoneConfig},
    server::ServerFuture,
    store::{
        file::{FileAuthority, FileConfig},
        StoreConfig,
    },
};

#[cfg(feature = "dnssec")]
use {hickory_proto::rr::dnssec::rdata::key::KeyUsage, hickory_server::authority::DnssecAuthority};

#[cfg(feature = "dnssec")]
async fn load_keys<A, L>(
    authority: &mut A,
    zone_name: Name,
    zone_config: &ZoneConfig,
) -> Result<(), String>
where
    A: DnssecAuthority<Lookup = L>,
    L: Send + Sync + Sized + 'static,
{
    if zone_config.is_dnssec_enabled() {
        for key_config in zone_config.get_keys() {
            info!(
                "adding key to zone: {:?}, is_zsk: {}, is_auth: {}",
                key_config.key_path(),
                key_config.is_zone_signing_key(),
                key_config.is_zone_update_auth()
            );
            if key_config.is_zone_signing_key() {
                let zone_signer = key_config.try_into_signer(zone_name.clone()).map_err(|e| {
                    format!("failed to load key: {:?} msg: {}", key_config.key_path(), e)
                })?;
                authority
                    .add_zone_signing_key(zone_signer)
                    .await
                    .map_err(|err| format!("failed to add zone signing key to authority: {err}"))?;
            }
            if key_config.is_zone_update_auth() {
                let update_auth_signer =
                    key_config.try_into_signer(zone_name.clone()).map_err(|e| {
                        format!("failed to load key: {:?} msg: {}", key_config.key_path(), e)
                    })?;
                let public_key = update_auth_signer
                    .key()
                    .to_sig0key_with_usage(update_auth_signer.algorithm(), KeyUsage::Host)
                    .map_err(|err| format!("failed to get sig0 key: {err}"))?;
                authority
                    .add_update_auth_key(zone_name.clone(), public_key)
                    .await
                    .map_err(|err| format!("failed to update auth key to authority: {err}"))?;
            }
        }

        let zone_name = zone_config
            .get_zone()
            .map_err(|err| format!("failed to read zone name: {err}"))?;
        info!("signing zone: {zone_name}");
        authority
            .secure_zone()
            .await
            .map_err(|err| format!("failed to sign zone {zone_name}: {err}"))?;
    }
    Ok(())
}

#[cfg(not(feature = "dnssec"))]
#[allow(clippy::unnecessary_wraps)]
async fn load_keys<T>(
    _authority: &mut T,
    _zone_name: Name,
    _zone_config: &ZoneConfig,
) -> Result<(), String> {
    Ok(())
}

#[cfg_attr(not(feature = "dnssec"), allow(unused_mut, unused))]
#[warn(clippy::wildcard_enum_match_arm)] // make sure all cases are handled despite of non_exhaustive
async fn load_zone(
    zone_dir: &Path,
    zone_config: &ZoneConfig,
) -> Result<Arc<dyn AuthorityObject>, String> {
    debug!("loading zone with config: {:#?}", zone_config);

    let zone_name: Name = zone_config
        .get_zone()
        .map_err(|err| format!("failed to read zone name: {err}"))?;
    let zone_name_for_signer = zone_name.clone();
    let zone_path: Option<String> = zone_config.file.clone();
    let zone_type: ZoneType = zone_config.get_zone_type();
    let is_axfr_allowed = zone_config.is_axfr_allowed();
    #[allow(unused_variables)]
    let is_dnssec_enabled = zone_config.is_dnssec_enabled();

    if zone_config.is_update_allowed() {
        warn!("allow_update is deprecated in [[zones]] section, it belongs in [[zones.stores]]");
    }

    // load the zone
    let authority: Arc<dyn AuthorityObject> = match zone_config.stores {
        #[cfg(feature = "sqlite")]
        Some(StoreConfig::Sqlite(ref config)) => {
            if zone_path.is_some() {
                warn!("ignoring [[zones.file]] instead using [[zones.stores.zone_file_path]]");
            }

            let mut authority = SqliteAuthority::try_from_config(
                zone_name,
                zone_type,
                is_axfr_allowed,
                is_dnssec_enabled,
                Some(zone_dir),
                config,
                #[cfg(feature = "dnssec")]
                zone_config.nx_proof_kind.clone(),
            )
            .await?;

            // load any keys for the Zone, if it is a dynamic update zone, then keys are required
            load_keys(&mut authority, zone_name_for_signer, zone_config).await?;
            Arc::new(authority)
        }
        Some(StoreConfig::File(ref config)) => {
            if zone_path.is_some() {
                warn!("ignoring [[zones.file]] instead using [[zones.stores.zone_file_path]]");
            }

            let mut authority = FileAuthority::try_from_config(
                zone_name,
                zone_type,
                is_axfr_allowed,
                Some(zone_dir),
                config,
                #[cfg(feature = "dnssec")]
                zone_config.nx_proof_kind.clone(),
            )?;

            // load any keys for the Zone, if it is a dynamic update zone, then keys are required
            load_keys(&mut authority, zone_name_for_signer, zone_config).await?;
            Arc::new(authority)
        }
        #[cfg(feature = "resolver")]
        Some(StoreConfig::Forward(ref config)) => {
            let forwarder = ForwardAuthority::try_from_config(zone_name, zone_type, config)?;

            Arc::new(forwarder)
        }
        #[cfg(feature = "recursor")]
        Some(StoreConfig::Recursor(ref config)) => {
            let recursor =
                RecursiveAuthority::try_from_config(zone_name, zone_type, config, Some(zone_dir));
            let authority = recursor.await?;

            Arc::new(authority)
        }
        #[cfg(feature = "sqlite")]
        None if zone_config.is_update_allowed() => {
            warn!(
                "using deprecated SQLite load configuration, please move to [[zones.stores]] form"
            );
            let zone_file_path = zone_path.ok_or("file is a necessary parameter of zone_config")?;
            let journal_file_path = PathBuf::from(zone_file_path.clone())
                .with_extension("jrnl")
                .to_str()
                .map(String::from)
                .ok_or("non-unicode characters in file name")?;

            let config = SqliteConfig {
                zone_file_path,
                journal_file_path,
                allow_update: zone_config.is_update_allowed(),
            };

            let mut authority = SqliteAuthority::try_from_config(
                zone_name,
                zone_type,
                is_axfr_allowed,
                is_dnssec_enabled,
                Some(zone_dir),
                &config,
                #[cfg(feature = "dnssec")]
                zone_config.nx_proof_kind.clone(),
            )
            .await?;

            // load any keys for the Zone, if it is a dynamic update zone, then keys are required
            load_keys(&mut authority, zone_name_for_signer, zone_config).await?;
            Arc::new(authority)
        }
        None => {
            let config = FileConfig {
                zone_file_path: zone_path.ok_or("file is a necessary parameter of zone_config")?,
            };

            let mut authority = FileAuthority::try_from_config(
                zone_name,
                zone_type,
                is_axfr_allowed,
                Some(zone_dir),
                &config,
                #[cfg(feature = "dnssec")]
                zone_config.nx_proof_kind.clone(),
            )?;

            // load any keys for the Zone, if it is a dynamic update zone, then keys are required
            load_keys(&mut authority, zone_name_for_signer, zone_config).await?;
            Arc::new(authority)
        }
        Some(_) => {
            panic!("unrecognized authority type, check enabled features");
        }
    };

    info!("zone successfully loaded: {}", zone_config.get_zone()?);
    Ok(authority)
}

/// Cli struct for all options managed with clap derive api.
#[derive(Debug, Parser)]
#[clap(name = "Hickory DNS named server", version, about)]
struct Cli {
    /// Test validation of configuration files
    #[clap(long = "validate")]
    pub(crate) validate: bool,

    /// Number of runtime workers, defaults to the number of CPU cores
    #[clap(long = "workers")]
    pub(crate) workers: Option<usize>,

    /// Disable INFO messages, WARN and ERROR will remain
    #[clap(short = 'q', long = "quiet", conflicts_with = "debug")]
    pub(crate) quiet: bool,

    /// Turn on `DEBUG` messages (default is only `INFO`)
    #[clap(short = 'd', long = "debug", conflicts_with = "quiet")]
    pub(crate) debug: bool,

    /// Path to configuration file of named server
    #[clap(
        short = 'c',
        long = "config",
        default_value = "/etc/named.toml",
        value_name = "NAME",
        value_hint=clap::ValueHint::FilePath,
    )]
    pub(crate) config: PathBuf,

    /// Path to the root directory for all zone files,
    /// see also config toml
    #[clap(short = 'z', long = "zonedir", value_name = "DIR", value_hint=clap::ValueHint::DirPath)]
    pub(crate) zonedir: Option<PathBuf>,

    /// Listening port for DNS queries,
    /// overrides any value in config file
    #[clap(short = 'p', long = "port", value_name = "PORT")]
    pub(crate) port: Option<u16>,

    /// Listening port for DNS over TLS queries,
    /// overrides any value in config file
    #[cfg(feature = "dns-over-tls")]
    #[clap(long = "tls-port", value_name = "TLS-PORT")]
    pub(crate) tls_port: Option<u16>,

    /// Listening port for DNS over HTTPS queries,
    /// overrides any value in config file
    #[cfg(feature = "dns-over-https-rustls")]
    #[clap(long = "https-port", value_name = "HTTPS-PORT")]
    pub(crate) https_port: Option<u16>,

    /// Listening port for DNS over QUIC queries,
    /// overrides any value in config file
    #[cfg(feature = "dns-over-quic")]
    #[clap(long = "quic-port", value_name = "QUIC-PORT")]
    pub(crate) quic_port: Option<u16>,

    /// Disable TCP protocol,
    /// overrides any value in config file
    #[clap(long = "disable-tcp")]
    pub(crate) disable_tcp: bool,

    /// Disable UDP protocol,
    /// overrides any value in config file
    #[clap(long = "disable-udp")]
    pub(crate) disable_udp: bool,

    /// Disable TLS protocol,
    /// overrides any value in config file
    #[cfg(feature = "dns-over-tls")]
    #[clap(long = "disable-tls", conflicts_with = "tls_port")]
    pub(crate) disable_tls: bool,

    /// Disable HTTPS protocol,
    /// overrides any value in config file
    #[cfg(feature = "dns-over-https-rustls")]
    #[clap(long = "disable-https", conflicts_with = "https_port")]
    pub(crate) disable_https: bool,

    /// Disable QUIC protocol,
    /// overrides any value in config file
    #[cfg(feature = "dns-over-quic")]
    #[clap(long = "disable-quic", conflicts_with = "quic_port")]
    pub(crate) disable_quic: bool,
}

/// Main method for running the named server.
fn main() -> Result<(), String> {
    // this is essential for custom formatting the returned error message.
    // the displayed message of termination impl trait is not pretty.
    // https://doc.rust-lang.org/stable/src/std/process.rs.html#2439
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let args = Cli::parse();
    // TODO: this should be set after loading config, but it's necessary for initial log lines, no?
    if args.quiet {
        quiet()?;
    } else if args.debug {
        debug()?;
    } else {
        default()?;
    }

    info!("Hickory DNS {} starting...", hickory_client::version());

    // Load configuration files

    let config = args.config.clone();
    let config_path = Path::new(&config);

    info!("loading configuration from: {config_path:?}");

    let config = Config::read_config(config_path)
        .map_err(|err| format!("failed to read config file from {config_path:?}: {err}"))?;
    let directory_config = config.get_directory().to_path_buf();
    let zonedir = args.zonedir.clone();
    let zone_dir: PathBuf = zonedir
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or(directory_config);

    let mut runtime = runtime::Builder::new_multi_thread();
    runtime.enable_all().thread_name("hickory-server-runtime");
    if let Some(workers) = args.workers {
        runtime.worker_threads(workers);
    }
    let runtime = runtime
        .build()
        .map_err(|err| format!("failed to initialize Tokio runtime: {err}"))?;

    let mut catalog: Catalog = Catalog::new();
    // configure our server based on the config_path
    for zone in config.get_zones() {
        let zone_name = zone
            .get_zone()
            .map_err(|err| format!("failed to read zone name from {config_path:?}: {err}"))?;

        match runtime.block_on(load_zone(&zone_dir, zone)) {
            Ok(authority) => catalog.upsert(zone_name.into(), authority),
            Err(err) => return Err(format!("could not load zone {zone_name}: {err}")),
        }
    }

    let v4addr = config
        .get_listen_addrs_ipv4()
        .map_err(|err| format!("failed to parse IPv4 addresses from {config_path:?}: {err}"))?;
    let v6addr = config
        .get_listen_addrs_ipv6()
        .map_err(|err| format!("failed to parse IPv6 addresses from {config_path:?}: {err}"))?;
    let mut listen_addrs: Vec<IpAddr> = v4addr
        .into_iter()
        .map(IpAddr::V4)
        .chain(v6addr.into_iter().map(IpAddr::V6))
        .collect();

    let listen_port: u16 = args.port.unwrap_or_else(|| config.get_listen_port());

    if listen_addrs.is_empty() {
        listen_addrs.push(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    }
    let sockaddrs: Vec<SocketAddr> = listen_addrs
        .iter()
        .flat_map(|x| (*x, listen_port).to_socket_addrs().unwrap())
        .collect();

    if args.validate {
        info!("configuration files are validated");
        return Ok(());
    }

    let deny_networks = config.get_deny_networks();
    let allow_networks = config.get_allow_networks();
    let tcp_request_timeout = config.get_tcp_request_timeout();

    // now, run the server, based on the config
    #[cfg_attr(not(feature = "dns-over-tls"), allow(unused_mut))]
    let mut server = ServerFuture::with_access(catalog, deny_networks, allow_networks);

    if !args.disable_udp && !config.get_disable_udp() {
        // load all udp listeners
        for udp_socket in &sockaddrs {
            info!("binding UDP to {:?}", udp_socket);
            let udp_socket = runtime
                .block_on(UdpSocket::bind(udp_socket))
                .map_err(|err| {
                    format!("failed to bind to UDP socket address {udp_socket:?}: {err}")
                })?;

            info!(
                "listening for UDP on {:?}",
                udp_socket
                    .local_addr()
                    .map_err(|err| format!("failed to lookup local address: {err}"))?
            );

            let _guard = runtime.enter();
            server.register_socket(udp_socket);
        }
    } else {
        info!("UDP protocol is disabled");
    }

    if !args.disable_tcp && !config.get_disable_tcp() {
        // load all tcp listeners
        for tcp_listener in &sockaddrs {
            info!("binding TCP to {:?}", tcp_listener);
            let tcp_listener =
                runtime
                    .block_on(TcpListener::bind(tcp_listener))
                    .map_err(|err| {
                        format!("failed to bind to TCP socket address {tcp_listener:?}: {err}")
                    })?;

            info!(
                "listening for TCP on {:?}",
                tcp_listener
                    .local_addr()
                    .map_err(|err| format!("failed to lookup local address: {err}"))?
            );

            let _guard = runtime.enter();
            server.register_listener(tcp_listener, tcp_request_timeout);
        }
    } else {
        info!("TCP protocol is disabled");
    }

    #[cfg(any(
        feature = "dns-over-tls",
        feature = "dns-over-https-rustls",
        feature = "dns-over-quic"
    ))]
    if let Some(tls_cert_config) = config.get_tls_cert() {
        #[cfg(feature = "dns-over-tls")]
        if !args.disable_tls && !config.get_disable_tls() {
            // setup TLS listeners
            config_tls(
                &args,
                &mut server,
                &config,
                tls_cert_config,
                &zone_dir,
                &listen_addrs,
                &runtime,
            )?;
        } else {
            info!("TLS protocol is disabled");
        }

        #[cfg(feature = "dns-over-https-rustls")]
        if !args.disable_https && !config.get_disable_https() {
            // setup HTTPS listeners
            config_https(
                &args,
                &mut server,
                &config,
                tls_cert_config,
                &zone_dir,
                &listen_addrs,
                &runtime,
            )?;
        } else {
            info!("HTTPS protocol is disabled");
        }

        #[cfg(feature = "dns-over-quic")]
        if !args.disable_quic && !config.get_disable_quic() {
            // setup QUIC listeners
            config_quic(
                &args,
                &mut server,
                &config,
                tls_cert_config,
                &zone_dir,
                &listen_addrs,
                &runtime,
            )?;
        } else {
            info!("QUIC protocol is disabled");
        }
    } else {
        info!("TLS certificates are not provided");
        info!("TLS related protocols (TLS, HTTPS and QUIC) are disabled")
    }

    // config complete, starting!
    banner();

    // TODO: how to do threads? should we do a bunch of listener threads and then query threads?
    // Ideally the processing would be n-threads for receiving, which hand off to m-threads for
    //  request handling. It would generally be the case that n <= m.
    info!("server starting up, awaiting connections...");
    match runtime.block_on(server.block_until_done()) {
        Ok(()) => {
            // we're exiting for some reason...
            info!("Hickory DNS {} stopping", hickory_client::version());
        }
        Err(e) => {
            let error_msg = format!(
                "Hickory DNS {} has encountered an error: {}",
                hickory_client::version(),
                e
            );

            error!("{}", error_msg);
            panic!("{}", error_msg);
        }
    };

    Ok(())
}

#[cfg(feature = "dns-over-tls")]
fn config_tls(
    args: &Cli,
    server: &mut ServerFuture<Catalog>,
    config: &Config,
    tls_cert_config: &TlsCertConfig,
    zone_dir: &Path,
    listen_addrs: &[IpAddr],
    runtime: &runtime::Runtime,
) -> Result<(), String> {
    let tls_listen_port: u16 = args
        .tls_port
        .unwrap_or_else(|| config.get_tls_listen_port());
    let tls_sockaddrs: Vec<SocketAddr> = listen_addrs
        .iter()
        .flat_map(|x| (*x, tls_listen_port).to_socket_addrs().unwrap())
        .collect();

    if tls_sockaddrs.is_empty() {
        warn!("a tls certificate was specified, but no TLS addresses configured to listen on");
        return Ok(());
    }

    for tls_listener in &tls_sockaddrs {
        let tls_cert_path = tls_cert_config.get_path();
        info!("loading cert for DNS over TLS: {tls_cert_path:?}");

        let tls_cert = dnssec::load_cert(zone_dir, tls_cert_config).map_err(|err| {
            format!("failed to load tls certificate files from {tls_cert_path:?}: {err}")
        })?;

        info!("binding TLS to {:?}", tls_listener);
        let tls_listener = runtime
            .block_on(TcpListener::bind(tls_listener))
            .map_err(|err| {
                format!("failed to bind to TLS socket address {tls_listener:?}: {err}")
            })?;

        info!(
            "listening for TLS on {:?}",
            tls_listener
                .local_addr()
                .map_err(|err| format!("failed to lookup local address: {err}"))?
        );

        let _guard = runtime.enter();
        server
            .register_tls_listener(tls_listener, config.get_tcp_request_timeout(), tls_cert)
            .map_err(|err| format!("failed to register TLS listener: {err}"))?;
    }
    Ok(())
}

#[cfg(feature = "dns-over-https-rustls")]
fn config_https(
    args: &Cli,
    server: &mut ServerFuture<Catalog>,
    config: &Config,
    tls_cert_config: &TlsCertConfig,
    zone_dir: &Path,
    listen_addrs: &[IpAddr],
    runtime: &runtime::Runtime,
) -> Result<(), String> {
    let https_listen_port: u16 = args
        .https_port
        .unwrap_or_else(|| config.get_https_listen_port());
    let https_sockaddrs: Vec<SocketAddr> = listen_addrs
        .iter()
        .flat_map(|x| (*x, https_listen_port).to_socket_addrs().unwrap())
        .collect();
    let endpoint_path = config.get_http_endpoint();

    if https_sockaddrs.is_empty() {
        warn!("a tls certificate was specified, but no HTTPS addresses configured to listen on");
        return Ok(());
    }

    for https_listener in &https_sockaddrs {
        let tls_cert_path = tls_cert_config.get_path();
        if let Some(endpoint_name) = tls_cert_config.get_endpoint_name() {
            info!("loading cert for DNS over TLS named {endpoint_name} from {tls_cert_path:?}");
        } else {
            info!("loading cert for DNS over TLS from {tls_cert_path:?}");
        }
        // TODO: see about modifying native_tls to impl Clone for Pkcs12
        let tls_cert = dnssec::load_cert(zone_dir, tls_cert_config).map_err(|err| {
            format!("failed to load tls certificate files from {tls_cert_path:?}: {err}")
        })?;

        info!("binding HTTPS to {:?}", https_listener);
        let https_listener = runtime
            .block_on(TcpListener::bind(https_listener))
            .map_err(|err| {
                format!("failed to bind to HTTPS socket address {https_listener:?}: {err}")
            })?;

        info!(
            "listening for HTTPS on {:?}",
            https_listener
                .local_addr()
                .map_err(|err| format!("failed to lookup local address: {err}"))?
        );

        let _guard = runtime.enter();
        server
            .register_https_listener(
                https_listener,
                config.get_tcp_request_timeout(),
                tls_cert,
                tls_cert_config.get_endpoint_name().map(|s| s.to_string()),
                endpoint_path.into(),
            )
            .map_err(|err| format!("failed to register HTTPS listener: {err}"))?;
    }

    Ok(())
}

#[cfg(feature = "dns-over-quic")]
fn config_quic(
    args: &Cli,
    server: &mut ServerFuture<Catalog>,
    config: &Config,
    tls_cert_config: &TlsCertConfig,
    zone_dir: &Path,
    listen_addrs: &[IpAddr],
    runtime: &runtime::Runtime,
) -> Result<(), String> {
    let quic_listen_port: u16 = args
        .quic_port
        .unwrap_or_else(|| config.get_quic_listen_port());
    let quic_sockaddrs: Vec<SocketAddr> = listen_addrs
        .iter()
        .flat_map(|x| (*x, quic_listen_port).to_socket_addrs().unwrap())
        .collect();

    if quic_sockaddrs.is_empty() {
        warn!("a tls certificate was specified, but no QUIC addresses configured to listen on");
        return Ok(());
    }

    for quic_listener in &quic_sockaddrs {
        let tls_cert_path = tls_cert_config.get_path();
        if let Some(endpoint_name) = tls_cert_config.get_endpoint_name() {
            info!("loading cert for DNS over QUIC named {endpoint_name} from {tls_cert_path:?}");
        } else {
            info!("loading cert for DNS over QUIC from {tls_cert_path:?}",);
        }
        // TODO: see about modifying native_tls to impl Clone for Pkcs12
        let tls_cert = dnssec::load_cert(zone_dir, tls_cert_config).map_err(|err| {
            format!("failed to load tls certificate files from {tls_cert_path:?}: {err}")
        })?;

        info!("Binding QUIC to {:?}", quic_listener);
        let quic_listener = runtime
            .block_on(UdpSocket::bind(quic_listener))
            .map_err(|err| {
                format!("failed to bind to QUIC socket address {quic_listener:?}: {err}")
            })?;

        info!(
            "listening for QUIC on {:?}",
            quic_listener
                .local_addr()
                .map_err(|err| format!("failed to lookup local address: {err}"))?
        );

        let _guard = runtime.enter();
        server
            .register_quic_listener(
                quic_listener,
                config.get_tcp_request_timeout(),
                tls_cert,
                tls_cert_config.get_endpoint_name().map(|s| s.to_string()),
            )
            .map_err(|err| format!("failed to register QUIC listener: {err}"))?;
    }
    Ok(())
}

fn banner() {
    #[cfg(feature = "ascii-art")]
    const HICKORY_DNS_LOGO: &str = include_str!("hickory-dns.ascii");

    #[cfg(not(feature = "ascii-art"))]
    const HICKORY_DNS_LOGO: &str = "Hickory DNS";

    info!("");
    for line in HICKORY_DNS_LOGO.lines() {
        info!(" {line}");
    }
    info!("");
}

struct TdnsFormatter;

impl<S, N> FormatEvent<S, N> for TdnsFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: format::Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let now = OffsetDateTime::now_utc();
        let now_secs = now.unix_timestamp();

        // Format values from the event's's metadata:
        let metadata = event.metadata();
        write!(
            &mut writer,
            "{}:{}:{}",
            now_secs,
            metadata.level(),
            metadata.target()
        )?;

        if let Some(line) = metadata.line() {
            write!(&mut writer, ":{line}")?;
        }

        // Format all the spans in the event's span context.
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                write!(writer, ":{}", span.name())?;

                let ext = span.extensions();
                let fields = &ext
                    .get::<FormattedFields<N>>()
                    .expect("will never be `None`");

                // Skip formatting the fields if the span had no fields.
                if !fields.is_empty() {
                    write!(writer, "{{{fields}}}")?;
                }
            }
        }

        // Write fields on the event
        write!(writer, ":")?;
        ctx.field_format().format_fields(writer.by_ref(), event)?;

        writeln!(writer)
    }
}

fn get_env() -> String {
    env::var("RUST_LOG").unwrap_or_default()
}

fn all_hickory_dns(level: impl ToString) -> String {
    format!(
        "hickory_dns={level},hickory_server={level},{env}",
        level = level.to_string().to_lowercase(),
        env = get_env()
    )
}

/// appends hickory-server debug to RUST_LOG
pub fn debug() -> Result<(), String> {
    logger(tracing::Level::DEBUG)
}

/// appends hickory-server info to RUST_LOG
pub fn default() -> Result<(), String> {
    logger(tracing::Level::INFO)
}

/// appends hickory-server error to RUST_LOG
pub fn quiet() -> Result<(), String> {
    logger(tracing::Level::ERROR)
}

// TODO: add dep on util crate, share logging config...
fn logger(level: tracing::Level) -> Result<(), String> {
    // Setup tracing for logging based on input
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::Level::WARN.into())
        .parse(all_hickory_dns(level))
        .map_err(|err| format!("failed to configure tracing/logging: {err}"))?;

    let formatter = tracing_subscriber::fmt::layer().event_format(TdnsFormatter);

    tracing_subscriber::registry()
        .with(formatter)
        .with(filter)
        .init();

    Ok(())
}
