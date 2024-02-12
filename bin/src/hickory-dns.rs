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

use hickory_client::rr::Name;
#[cfg(feature = "dns-over-tls")]
use hickory_server::config::dnssec::{self, TlsCertConfig};
#[cfg(feature = "blocklist")]
use hickory_server::store::blocklist::BlocklistAuthority;
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
        StoreConfig, StoreConfigContainer,
    },
};

#[cfg(feature = "dnssec")]
use {hickory_client::rr::rdata::key::KeyUsage, hickory_server::authority::DnssecAuthority};

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
                    .await
                    .expect("failed to add update auth key to authority");
            }
        }

        info!("signing zone: {}", zone_config.get_zone()?);
        authority.secure_zone().await.expect("failed to sign zone");
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
) -> Result<Vec<Box<dyn AuthorityObject>>, String> {
    debug!("loading zone with config: {:#?}", zone_config);

    let zone_name: Name = zone_config.get_zone().expect("bad zone name");
    let zone_name_for_signer = zone_name.clone();
    let zone_path: Option<String> = zone_config.file.clone();
    let zone_type: ZoneType = zone_config.get_zone_type();
    let is_axfr_allowed = zone_config.is_axfr_allowed();
    #[allow(unused_variables)]
    let is_dnssec_enabled = zone_config.is_dnssec_enabled();

    if zone_config.is_update_allowed() {
        warn!("allow_update is deprecated in [[zones]] section, it belongs in [[zones.stores]]");
    }

    let mut normalized_stores = vec![];
    if let Some(StoreConfigContainer::Single(store)) = &zone_config.stores {
        normalized_stores.push(store);
    } else if let Some(StoreConfigContainer::Chained(chained_stores)) = &zone_config.stores {
        for store in chained_stores {
            normalized_stores.push(store);
        }
    } else {
        normalized_stores.push(&StoreConfig::Default);
        debug!(
            "No stores specified for {}, using default config processing",
            zone_name.clone()
        );
    }

    // Load the zone and build a vector of associated authorities to load in the catalog.
    debug!(
        "Loading authorities for {} with stores {:?}",
        &zone_name, &normalized_stores
    );
    let mut authorities: Vec<Box<dyn AuthorityObject>> = vec![];
    for store in normalized_stores {
        let authority: Box<dyn AuthorityObject> = match store {
            #[cfg(feature = "sqlite")]
            StoreConfig::Sqlite(ref config) => {
                if zone_path.is_some() {
                    warn!("ignoring [[zones.file]] instead using [[zones.stores.zone_file_path]]");
                }

                let mut authority = SqliteAuthority::try_from_config(
                    zone_name.clone(),
                    zone_type,
                    is_axfr_allowed,
                    is_dnssec_enabled,
                    Some(zone_dir),
                    config,
                )
                .await?;

                // load any keys for the Zone, if it is a dynamic update zone, then keys are required
                load_keys(&mut authority, zone_name_for_signer.clone(), zone_config).await?;
                Box::new(Arc::new(authority)) as Box<dyn AuthorityObject>
            }
            StoreConfig::File(ref config) => {
                if zone_path.is_some() {
                    warn!("ignoring [[zones.file]] instead using [[zones.stores.zone_file_path]]");
                }

                let mut authority = FileAuthority::try_from_config(
                    zone_name.clone(),
                    zone_type,
                    is_axfr_allowed,
                    Some(zone_dir),
                    config,
                )?;

                // load any keys for the Zone, if it is a dynamic update zone, then keys are required
                load_keys(&mut authority, zone_name_for_signer.clone(), zone_config).await?;
                Box::new(Arc::new(authority)) as Box<dyn AuthorityObject>
            }
            #[cfg(feature = "resolver")]
            StoreConfig::Forward(ref config) => {
                let forwarder =
                    ForwardAuthority::try_from_config(zone_name.clone(), zone_type, config)?;

                Box::new(Arc::new(forwarder)) as Box<dyn AuthorityObject>
            }
            #[cfg(feature = "recursor")]
            StoreConfig::Recursor(ref config) => {
                let recursor = RecursiveAuthority::try_from_config(
                    zone_name.clone(),
                    zone_type,
                    config,
                    Some(zone_dir),
                );
                let authority = recursor.await?;

                Box::new(Arc::new(authority)) as Box<dyn AuthorityObject>
            }
            #[cfg(feature = "blocklist")]
            StoreConfig::Blocklist(ref config) => {
                let blocklist = BlocklistAuthority::try_from_config(
                    zone_name.clone(),
                    zone_type,
                    config,
                    Some(zone_dir),
                );
                let authority = blocklist.await?;
                Box::new(Arc::new(authority)) as Box<dyn AuthorityObject>
            }
            #[cfg(feature = "sqlite")]
            _ if zone_config.is_update_allowed() => {
                warn!(
                    "using deprecated SQLite load configuration, please move to [[zones.stores]] form"
                );
                let zone_file_path = zone_path
                    .clone()
                    .ok_or("file is a necessary parameter of zone_config")?;
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
                    zone_name.clone(),
                    zone_type,
                    is_axfr_allowed,
                    is_dnssec_enabled,
                    Some(zone_dir),
                    &config,
                )
                .await?;

                // load any keys for the Zone, if it is a dynamic update zone, then keys are required
                load_keys(&mut authority, zone_name_for_signer.clone(), zone_config).await?;
                Box::new(Arc::new(authority)) as Box<dyn AuthorityObject>
            }
            _ => {
                let config = FileConfig {
                    zone_file_path: zone_path
                        .clone()
                        .ok_or("file is a necessary parameter of zone_config")?,
                };

                let mut authority = FileAuthority::try_from_config(
                    zone_name.clone(),
                    zone_type,
                    is_axfr_allowed,
                    Some(zone_dir),
                    &config,
                )?;

                // load any keys for the Zone, if it is a dynamic update zone, then keys are required
                load_keys(&mut authority, zone_name_for_signer.clone(), zone_config).await?;
                Box::new(Arc::new(authority)) as Box<dyn AuthorityObject>
            }
        };

        authorities.push(authority);
    }

    info!("zone successfully loaded: {}", zone_config.get_zone()?);
    Ok(authorities)
}

/// Cli struct for all options managed with clap derive api.
#[derive(Debug, Parser)]
#[clap(name = "Hickory DNS named server", version, about)]
struct Cli {
    /// Disable INFO messages, WARN and ERROR will remain
    #[clap(short = 'q', long = "quiet", conflicts_with = "debug")]
    pub(crate) quiet: bool,

    /// Turn on `DEBUG` messages (default is only `INFO`)
    #[clap(short = 'd', long = "debug", conflicts_with = "quiet")]
    pub(crate) debug: bool,

    /// Path to configuration file of named server,
    /// by default `/etc/named.toml`
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
    #[clap(long = "tls-port", value_name = "TLS-PORT")]
    pub(crate) tls_port: Option<u16>,

    /// Listening port for DNS over HTTPS queries,
    /// overrides any value in config file
    #[clap(long = "https-port", value_name = "HTTPS-PORT")]
    pub(crate) https_port: Option<u16>,

    /// Listening port for DNS over QUIC queries,
    /// overrides any value in config file
    #[clap(long = "quic-port", value_name = "QUIC-PORT")]
    pub(crate) quic_port: Option<u16>,
}

/// Main method for running the named server.
///
/// `Note`: Tries to avoid panics, in favor of always starting.
#[allow(unused_mut)]
fn main() {
    let args = Cli::parse();
    // TODO: this should be set after loading config, but it's necessary for initial log lines, no?
    if args.quiet {
        quiet();
    } else if args.debug {
        debug();
    } else {
        default();
    }

    info!("Hickory DNS {} starting", hickory_client::version());
    // start up the server for listening

    let config = args.config.clone();
    let config_path = Path::new(&config);
    info!("loading configuration from: {:?}", config_path);
    let config = Config::read_config(config_path)
        .unwrap_or_else(|e| panic!("could not read config {}: {:?}", config_path.display(), e));
    let directory_config = config.get_directory().to_path_buf();
    let zonedir = args.zonedir.clone();
    let zone_dir: PathBuf = zonedir
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| directory_config.clone());

    // TODO: allow for num threads configured...
    let mut runtime = runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .thread_name("hickory-server-runtime")
        .build()
        .expect("failed to initialize Tokio Runtime");
    let mut catalog: Catalog = Catalog::new();
    // configure our server based on the config_path
    for zone in config.get_zones() {
        let zone_name = zone
            .get_zone()
            .unwrap_or_else(|_| panic!("bad zone name in {:?}", config_path));

        match runtime.block_on(load_zone(&zone_dir, zone)) {
            Ok(authority) => catalog.upsert(zone_name.into(), authority),
            Err(error) => panic!("could not load zone {}: {}", zone_name, error),
        }
    }

    // TODO: support all the IPs asked to listen on...
    // TODO:, there should be the option to listen on any port, IP and protocol option...
    let v4addr = config
        .get_listen_addrs_ipv4()
        .expect("Error with parsing provided by configuration Ipv4");
    let v6addr = config
        .get_listen_addrs_ipv6()
        .expect("Error with parsing provided by configuration Ipv6");
    let mut listen_addrs: Vec<IpAddr> = v4addr
        .into_iter()
        .map(IpAddr::V4)
        .chain(v6addr.into_iter().map(IpAddr::V6))
        .collect();
    let listen_port: u16 = args.port.unwrap_or_else(|| config.get_listen_port());
    let tcp_request_timeout = config.get_tcp_request_timeout();

    if listen_addrs.is_empty() {
        listen_addrs.push(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    }
    let sockaddrs: Vec<SocketAddr> = listen_addrs
        .iter()
        .flat_map(|x| (*x, listen_port).to_socket_addrs().unwrap())
        .collect();
    let deny_networks = config.get_deny_networks();
    let allow_networks = config.get_allow_networks();

    // now, run the server, based on the config
    #[cfg_attr(not(feature = "dns-over-tls"), allow(unused_mut))]
    let mut server = ServerFuture::with_access(catalog, deny_networks, allow_networks);

    // load all the listeners
    for udp_socket in &sockaddrs {
        info!("binding UDP to {:?}", udp_socket);
        let udp_socket = runtime
            .block_on(UdpSocket::bind(udp_socket))
            .unwrap_or_else(|err| panic!("could not bind to UDP socket {udp_socket}: {err}"));

        info!(
            "listening for UDP on {:?}",
            udp_socket
                .local_addr()
                .expect("could not lookup local address")
        );

        let _guard = runtime.enter();
        server.register_socket(udp_socket);
    }

    // and TCP as necessary
    for tcp_listener in &sockaddrs {
        info!("binding TCP to {:?}", tcp_listener);
        let tcp_listener = runtime
            .block_on(TcpListener::bind(tcp_listener))
            .unwrap_or_else(|_| panic!("could not bind to tcp: {}", tcp_listener));

        info!(
            "listening for TCP on {:?}",
            tcp_listener
                .local_addr()
                .expect("could not lookup local address")
        );

        let _guard = runtime.enter();
        server.register_listener(tcp_listener, tcp_request_timeout);
    }

    let tls_cert_config = config.get_tls_cert();

    // and TLS as necessary
    // TODO: we should add some more control from configs to enable/disable TLS/HTTPS/QUIC
    if let Some(_tls_cert_config) = tls_cert_config {
        // setup TLS listeners
        #[cfg(feature = "dns-over-tls")]
        config_tls(
            &args,
            &mut server,
            &config,
            _tls_cert_config,
            &zone_dir,
            &listen_addrs,
            &mut runtime,
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
            &mut runtime,
        );

        // setup QUIC listeners
        #[cfg(feature = "dns-over-quic")]
        config_quic(
            &args,
            &mut server,
            &config,
            _tls_cert_config,
            &zone_dir,
            &listen_addrs,
            &mut runtime,
        );
    }

    // config complete, starting!
    banner();
    info!("awaiting connections...");

    // TODO: how to do threads? should we do a bunch of listener threads and then query threads?
    // Ideally the processing would be n-threads for receiving, which hand off to m-threads for
    //  request handling. It would generally be the case that n <= m.
    info!("Server starting up");
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
}

#[cfg(feature = "dns-over-tls")]
fn config_tls(
    args: &Cli,
    server: &mut ServerFuture<Catalog>,
    config: &Config,
    tls_cert_config: &TlsCertConfig,
    zone_dir: &Path,
    listen_addrs: &[IpAddr],
    runtime: &mut runtime::Runtime,
) {
    use futures_util::TryFutureExt;

    let tls_listen_port: u16 = args
        .tls_port
        .unwrap_or_else(|| config.get_tls_listen_port());
    let tls_sockaddrs: Vec<SocketAddr> = listen_addrs
        .iter()
        .flat_map(|x| (*x, tls_listen_port).to_socket_addrs().unwrap())
        .collect();

    if tls_sockaddrs.is_empty() {
        warn!("a tls certificate was specified, but no TLS addresses configured to listen on");
    }

    for tls_listener in &tls_sockaddrs {
        info!(
            "loading cert for DNS over TLS: {:?}",
            tls_cert_config.get_path()
        );

        let tls_cert = dnssec::load_cert(zone_dir, tls_cert_config)
            .expect("error loading tls certificate file");

        info!("binding TLS to {:?}", tls_listener);
        let tls_listener = runtime.block_on(
            TcpListener::bind(tls_listener)
                .unwrap_or_else(|_| panic!("could not bind to tls: {}", tls_listener)),
        );

        info!(
            "listening for TLS on {:?}",
            tls_listener
                .local_addr()
                .expect("could not lookup local address")
        );

        let _guard = runtime.enter();
        server
            .register_tls_listener(tls_listener, config.get_tcp_request_timeout(), tls_cert)
            .expect("could not register TLS listener");
    }
}

#[cfg(feature = "dns-over-https")]
fn config_https(
    args: &Cli,
    server: &mut ServerFuture<Catalog>,
    config: &Config,
    tls_cert_config: &TlsCertConfig,
    zone_dir: &Path,
    listen_addrs: &[IpAddr],
    runtime: &mut runtime::Runtime,
) {
    use futures_util::TryFutureExt;

    let https_listen_port: u16 = args
        .https_port
        .unwrap_or_else(|| config.get_https_listen_port());
    let https_sockaddrs: Vec<SocketAddr> = listen_addrs
        .iter()
        .flat_map(|x| (*x, https_listen_port).to_socket_addrs().unwrap())
        .collect();

    if https_sockaddrs.is_empty() {
        warn!("a tls certificate was specified, but no HTTPS addresses configured to listen on");
    }

    for https_listener in &https_sockaddrs {
        if let Some(endpoint_name) = tls_cert_config.get_endpoint_name() {
            info!(
                "loading cert for DNS over TLS named {} from {:?}",
                endpoint_name,
                tls_cert_config.get_path()
            );
        } else {
            info!(
                "loading cert for DNS over TLS from {:?}",
                tls_cert_config.get_path()
            );
        }
        // TODO: see about modifying native_tls to impl Clone for Pkcs12
        let tls_cert = dnssec::load_cert(zone_dir, tls_cert_config)
            .expect("error loading tls certificate file");

        info!("binding HTTPS to {:?}", https_listener);
        let https_listener = runtime.block_on(
            TcpListener::bind(https_listener)
                .unwrap_or_else(|_| panic!("could not bind to tls: {}", https_listener)),
        );

        info!(
            "listening for HTTPS on {:?}",
            https_listener
                .local_addr()
                .expect("could not lookup local address")
        );

        let _guard = runtime.enter();
        server
            .register_https_listener(
                https_listener,
                config.get_tcp_request_timeout(),
                tls_cert,
                tls_cert_config.get_endpoint_name().map(|s| s.to_string()),
            )
            .expect("could not register HTTPS listener");
    }
}

#[cfg(feature = "dns-over-quic")]
fn config_quic(
    args: &Cli,
    server: &mut ServerFuture<Catalog>,
    config: &Config,
    tls_cert_config: &TlsCertConfig,
    zone_dir: &Path,
    listen_addrs: &[IpAddr],
    runtime: &mut runtime::Runtime,
) {
    use futures_util::TryFutureExt;

    let quic_listen_port: u16 = args
        .quic_port
        .unwrap_or_else(|| config.get_quic_listen_port());
    let quic_sockaddrs: Vec<SocketAddr> = listen_addrs
        .iter()
        .flat_map(|x| (*x, quic_listen_port).to_socket_addrs().unwrap())
        .collect();

    if quic_sockaddrs.is_empty() {
        warn!("a tls certificate was specified, but no QUIC addresses configured to listen on");
    }

    for quic_listener in &quic_sockaddrs {
        if let Some(endpoint_name) = tls_cert_config.get_endpoint_name() {
            info!(
                "loading cert for DNS over QUIC named {} from {:?}",
                endpoint_name,
                tls_cert_config.get_path()
            );
        } else {
            info!(
                "loading cert for DNS over QUIC from {:?}",
                tls_cert_config.get_path()
            );
        }
        // TODO: see about modifying native_tls to impl Clone for Pkcs12
        let tls_cert = dnssec::load_cert(zone_dir, tls_cert_config)
            .expect("error loading tls certificate file");

        info!("binding QUIC to {:?}", quic_listener);
        let quic_listener = runtime.block_on(
            UdpSocket::bind(quic_listener)
                .unwrap_or_else(|_| panic!("could not bind to tls: {}", quic_listener)),
        );

        info!(
            "listening for QUIC on {:?}",
            quic_listener
                .local_addr()
                .expect("could not lookup local address")
        );

        let _guard = runtime.enter();
        server
            .register_quic_listener(
                quic_listener,
                config.get_tcp_request_timeout(),
                tls_cert,
                tls_cert_config.get_endpoint_name().map(|s| s.to_string()),
            )
            .expect("could not register QUIC listener");
    }
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
        "hickory_dns={level},{env}",
        level = level.to_string().to_lowercase(),
        env = get_env()
    )
}

/// appends hickory-server debug to RUST_LOG
pub fn debug() {
    logger(tracing::Level::DEBUG);
}

/// appends hickory-server info to RUST_LOG
pub fn default() {
    logger(tracing::Level::INFO);
}

/// appends hickory-server error to RUST_LOG
pub fn quiet() {
    logger(tracing::Level::ERROR);
}

// TODO: add dep on util crate, share logging config...
fn logger(level: tracing::Level) {
    // Setup tracing for logging based on input
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::Level::WARN.into())
        .parse(all_hickory_dns(level))
        .expect("failed to configure tracing/logging");

    let formatter = tracing_subscriber::fmt::layer().event_format(TdnsFormatter);

    tracing_subscriber::registry()
        .with(formatter)
        .with(filter)
        .init();
}
