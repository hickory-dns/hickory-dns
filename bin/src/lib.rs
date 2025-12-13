#[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
use std::sync::Arc;
#[cfg(feature = "metrics")]
use std::time::Duration;
use std::{
    io::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};

use clap::Parser;
#[cfg(feature = "metrics")]
use metrics::{Counter, Unit, counter, describe_counter, describe_gauge, gauge};
#[cfg(feature = "metrics")]
use metrics_process::Collector;
#[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
use rustls::KeyLogFile;
use socket2::{Domain, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
#[cfg(feature = "metrics")]
use tokio::time::sleep;
#[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
use tracing::warn;
use tracing::{error, info};

use hickory_server::proto::ProtoError;
use hickory_server::proto::rr::rdata::opt::NSIDPayload;
#[cfg(feature = "__tls")]
use hickory_server::server::default_tls_server_config;
use hickory_server::{server::Server, zone_handler::Catalog};

mod config;
pub use config::{
    Config, ConfigError, ExternalStoreConfig, ServerStoreConfig, ServerZoneConfig, TlsCertConfig,
    ZoneConfig, ZoneTypeConfig,
};

#[cfg(feature = "__dnssec")]
pub mod dnssec;

#[cfg(feature = "prometheus-metrics")]
mod prometheus_server;
#[cfg(feature = "prometheus-metrics")]
pub use prometheus_server::PrometheusServer;

/// Cli struct for all options managed with clap derive api.
#[derive(Debug, Parser)]
#[clap(name = "Hickory DNS named server", version, about)]
pub struct Cli {
    /// Test validation of configuration files
    #[clap(long = "validate")]
    validate: bool,

    /// Number of runtime workers, defaults to the number of CPU cores
    #[clap(long = "workers")]
    pub workers: Option<usize>,

    /// Disable INFO messages, WARN and ERROR will remain
    #[clap(short = 'q', long = "quiet", conflicts_with = "debug")]
    pub quiet: bool,

    /// Turn on `DEBUG` messages (default is only `INFO`)
    #[clap(short = 'd', long = "debug", conflicts_with = "quiet")]
    pub debug: bool,

    /// Path to configuration file of named server
    #[clap(
        short = 'c',
        long = "config",
        default_value = "/etc/named.toml",
        value_name = "NAME",
        value_hint=clap::ValueHint::FilePath,
    )]
    config: PathBuf,

    /// Path to the root directory for all zone files,
    /// see also config toml
    #[clap(short = 'z', long = "zonedir", value_name = "DIR", value_hint=clap::ValueHint::DirPath)]
    zonedir: Option<PathBuf>,

    /// Listening port for DNS queries,
    /// overrides any value in config file
    #[clap(short = 'p', long = "port", value_name = "PORT")]
    port: Option<u16>,

    /// Listening port for DNS over TLS queries,
    /// overrides any value in config file
    #[cfg(feature = "__tls")]
    #[clap(long = "tls-port", value_name = "TLS-PORT")]
    tls_port: Option<u16>,

    /// Listening port for DNS over HTTPS queries,
    /// overrides any value in config file
    #[cfg(feature = "__https")]
    #[clap(long = "https-port", value_name = "HTTPS-PORT")]
    https_port: Option<u16>,

    /// Listening port for DNS over QUIC queries,
    /// overrides any value in config file
    #[cfg(feature = "__quic")]
    #[clap(long = "quic-port", value_name = "QUIC-PORT")]
    quic_port: Option<u16>,

    /// Listening socket for Prometheus metrics,
    /// for remote access configure socket as needed (e.g. 0.0.0.0:9000)
    /// overrides any value in config file
    #[cfg(feature = "prometheus-metrics")]
    #[clap(
        long = "prometheus-listen-address",
        value_name = "PROMETHEUS-LISTEN-ADDRESS"
    )]
    prometheus_listen_addr: Option<SocketAddr>,

    /// Disable TCP protocol,
    /// overrides any value in config file
    #[clap(long = "disable-tcp")]
    disable_tcp: bool,

    /// Disable UDP protocol,
    /// overrides any value in config file
    #[clap(long = "disable-udp")]
    disable_udp: bool,

    /// Disable TLS protocol,
    /// overrides any value in config file
    #[cfg(feature = "__tls")]
    #[clap(long = "disable-tls", conflicts_with = "tls_port")]
    disable_tls: bool,

    /// Disable HTTPS protocol,
    /// overrides any value in config file
    #[cfg(feature = "__https")]
    #[clap(long = "disable-https", conflicts_with = "https_port")]
    disable_https: bool,

    /// Disable QUIC protocol,
    /// overrides any value in config file
    #[cfg(feature = "__quic")]
    #[clap(long = "disable-quic", conflicts_with = "quic_port")]
    disable_quic: bool,

    /// Disable Prometheus metrics,
    /// overrides any value in config file
    #[cfg(feature = "prometheus-metrics")]
    #[clap(long = "disable-prometheus", conflicts_with = "prometheus_listen_addr")]
    disable_prometheus: bool,

    /// Name server identifier (NSID) payload for EDNS responses.
    /// Use `0x` prefix for hex-encoded data. Mutually exclusive with --nsid-hostname
    #[clap(long = "nsid", value_name = "NSID", conflicts_with = "nsid_hostname", value_parser = parse_nsid_payload)]
    nsid: Option<NSIDPayload>,

    /// Use the system hostname as the name server identifier (NSID) payload
    /// for EDNS responses.
    /// Mutually exclusive with --nsid
    #[clap(long = "nsid-hostname", conflicts_with = "nsid")]
    nsid_hostname: bool,
}

impl Cli {
    pub async fn run(self) -> Result<(), String> {
        let Self {
            validate,
            workers: _, // Used in `main()`
            quiet: _,   // Used in `main()`
            debug: _,   // Used in `main()`
            config,
            zonedir,
            port,
            #[cfg(feature = "__tls")]
            tls_port,
            #[cfg(feature = "__https")]
            https_port,
            #[cfg(feature = "__quic")]
            quic_port,
            #[cfg(feature = "prometheus-metrics")]
            prometheus_listen_addr,
            disable_tcp,
            disable_udp,
            #[cfg(feature = "__tls")]
            disable_tls,
            #[cfg(feature = "__https")]
            disable_https,
            #[cfg(feature = "__quic")]
            disable_quic,
            #[cfg(feature = "prometheus-metrics")]
            disable_prometheus,
            nsid,
            nsid_hostname,
        } = self;

        let config_path = Path::new(&config);
        info!("loading configuration from: {config_path:?}");
        let config = Config::read_config(config_path)
            .map_err(|err| format!("failed to read config file from {config_path:?}: {err}"))?;

        let directory_config = config.directory().to_path_buf();
        let zonedir = zonedir.clone();
        let zone_dir: PathBuf = zonedir
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or(directory_config);

        #[cfg(feature = "prometheus-metrics")]
        let prometheus_server_opt = if !disable_prometheus && !config.disable_prometheus() {
            let socket_addr =
                prometheus_listen_addr.unwrap_or_else(|| config.prometheus_listen_addr());
            let listener =
                build_tcp_listener(socket_addr.ip(), socket_addr.port()).map_err(|err| {
                    format!(
                        "failed to bind to Prometheus TCP socket address {socket_addr:?}: {err}"
                    )
                })?;
            let local_addr = listener
                .local_addr()
                .map_err(|err| format!("failed to look up local address: {err}"))?;

            // Set up Prometheus HTTP server.
            let server = PrometheusServer::new(listener)?;
            info!("listening for Prometheus metrics on {local_addr:?}");
            Some(server)
        } else {
            info!("Prometheus metrics are disabled");
            None
        };

        #[cfg(feature = "metrics")]
        let (process_metrics_collector, config_metrics) = {
            // setup process metrics (cpu, memory, ...) collection
            let collector = Collector::default();
            collector.describe(); // add metric descriptions

            let process_metrics_collector = tokio::spawn(async move {
                loop {
                    sleep(Duration::from_secs(1)).await;
                    collector.collect();
                }
            });

            // metrics need to be created after the recorder is registered
            // calling increment() after registration is not sufficient
            let config_metrics = ConfigMetrics::new(&config);
            (process_metrics_collector, config_metrics)
        };

        #[cfg(unix)]
        let mut signal = signal(SignalKind::terminate())
            .map_err(|e| format!("failed to register signal handler: {e}"))?;

        let mut catalog = Catalog::new();
        catalog.set_nsid(nsid);

        if nsid_hostname {
            let hostname =
                hostname::get().map_err(|e| format!("failed to get system hostname: {e}"))?;
            let payload = NSIDPayload::new(hostname.into_encoded_bytes())
                .map_err(|e| format!("invalid NSID payload: {e}"))?;
            catalog.set_nsid(Some(payload));
        }

        // configure our server based on the config_path
        for zone in config.zones() {
            let zone_name = zone
                .zone()
                .map_err(|err| format!("failed to read zone name from {config_path:?}: {err}"))?;

            match zone.load(&zone_dir).await {
                Ok(handlers) => catalog.upsert(zone_name.into(), handlers),
                Err(err) => return Err(format!("could not load zone {zone_name}: {err}")),
            }

            #[cfg(feature = "metrics")]
            config_metrics.increment_zone_metrics(zone);
        }

        let v4addr = config
            .listen_addrs_ipv4()
            .map_err(|err| format!("failed to parse IPv4 addresses from {config_path:?}: {err}"))?;
        let v6addr = config
            .listen_addrs_ipv6()
            .map_err(|err| format!("failed to parse IPv6 addresses from {config_path:?}: {err}"))?;
        let mut listen_addrs: Vec<IpAddr> = v4addr
            .into_iter()
            .map(IpAddr::V4)
            .chain(v6addr.into_iter().map(IpAddr::V6))
            .collect();

        let listen_port = port.unwrap_or_else(|| config.listen_port());

        if listen_addrs.is_empty() {
            listen_addrs.push(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            listen_addrs.push(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        }

        if validate {
            info!("configuration files are validated");
            return Ok(());
        }

        let deny_networks = config.deny_networks();
        let allow_networks = config.allow_networks();
        let tcp_request_timeout = config.tcp_request_timeout();

        // now, run the server, based on the config
        #[cfg_attr(not(feature = "__tls"), allow(unused_mut))]
        let mut server = Server::with_access(catalog, deny_networks, allow_networks);

        if !disable_udp && !config.disable_udp() {
            // load all udp listeners
            for addr in &listen_addrs {
                info!("binding UDP to {addr:?}");

                let udp_socket = build_udp_socket(*addr, listen_port).map_err(|err| {
                    format!("failed to bind to UDP socket address {addr:?}: {err}")
                })?;

                info!(
                    "listening for UDP on {:?}",
                    udp_socket
                        .local_addr()
                        .map_err(|err| format!("failed to lookup local address: {err}"))?
                );

                server.register_socket(udp_socket);
            }
        } else {
            info!("UDP protocol is disabled");
        }

        if !disable_tcp && !config.disable_tcp() {
            // load all tcp listeners
            for addr in &listen_addrs {
                info!("binding TCP to {addr:?}");

                let tcp_listener = build_tcp_listener(*addr, listen_port).map_err(|err| {
                    format!("failed to bind to TCP socket address {addr:?}: {err}")
                })?;

                info!(
                    "listening for TCP on {:?}",
                    tcp_listener
                        .local_addr()
                        .map_err(|err| format!("failed to lookup local address: {err}"))?
                );

                server.register_listener(tcp_listener, tcp_request_timeout);
            }
        } else {
            info!("TCP protocol is disabled");
        }

        #[cfg(feature = "__tls")]
        if let Some(tls_cert_config) = config.tls_cert() {
            #[cfg(feature = "__tls")]
            if !disable_tls && !config.disable_tls() {
                // setup TLS listeners
                config_tls(
                    tls_port,
                    &mut server,
                    &config,
                    tls_cert_config,
                    &zone_dir,
                    &listen_addrs,
                )?;
            } else {
                info!("TLS protocol is disabled");
            }

            #[cfg(feature = "__https")]
            if !disable_https && !config.disable_https() {
                // setup HTTPS listeners
                config_https(
                    https_port,
                    &mut server,
                    &config,
                    tls_cert_config,
                    &zone_dir,
                    &listen_addrs,
                )?;
            } else {
                info!("HTTPS protocol is disabled");
            }

            #[cfg(feature = "__quic")]
            if !disable_quic && !config.disable_quic() {
                // setup QUIC listeners
                config_quic(
                    quic_port,
                    &mut server,
                    &config,
                    tls_cert_config,
                    &zone_dir,
                    &listen_addrs,
                )?;
            } else {
                info!("QUIC protocol is disabled");
            }
        } else {
            info!("TLS certificates are not provided");
            info!("TLS related protocols (TLS, HTTPS and QUIC) are disabled")
        }

        // Drop privileges on Unix systems if running as root.
        #[cfg(target_family = "unix")]
        check_drop_privs(
            config.user.as_deref().unwrap_or(DEFAULT_USER),
            config.group.as_deref().unwrap_or(DEFAULT_GROUP),
        )?;
        #[cfg(not(target_family = "unix"))]
        if config.user.is_some() || config.group.is_some() {
            return Err("dropping privileges is only supported on Unix systems".to_string());
        }

        #[cfg(unix)]
        {
            let token = server.shutdown_token().clone();
            tokio::spawn(async move {
                signal.recv().await;
                token.cancel();
            });
        }

        // config complete, starting!
        banner();

        // TODO: how to do threads? should we do a bunch of listener threads and then query threads?
        // Ideally the processing would be n-threads for receiving, which hand off to m-threads for
        //  request handling. It would generally be the case that n <= m.
        info!("server starting up, awaiting connections...");
        match server.block_until_done().await {
            Ok(()) => {
                // we're exiting for some reason...
                info!("Hickory DNS {} stopping", env!("CARGO_PKG_VERSION"));
            }
            Err(e) => {
                let error_msg = format!(
                    "Hickory DNS {} has encountered an error: {}",
                    env!("CARGO_PKG_VERSION"),
                    e
                );

                error!("{}", error_msg);
                panic!("{}", error_msg);
            }
        };

        // Shut down the Prometheus metrics server after the DNS server has gracefully shut down.
        #[cfg(feature = "prometheus-metrics")]
        if let Some(server) = prometheus_server_opt {
            server.stop().await;
        }

        #[cfg(feature = "metrics")]
        process_metrics_collector.abort();

        Ok(())
    }
}

#[cfg(feature = "__tls")]
fn config_tls(
    tls_port: Option<u16>,
    server: &mut Server<Catalog>,
    config: &Config,
    tls_cert_config: &TlsCertConfig,
    zone_dir: &Path,
    listen_addrs: &[IpAddr],
) -> Result<(), String> {
    let tls_listen_port = tls_port.unwrap_or_else(|| config.tls_listen_port());

    if listen_addrs.is_empty() {
        warn!("a tls certificate was specified, but no TLS addresses configured to listen on");
        return Ok(());
    }

    for addr in listen_addrs {
        let tls_cert_path = &tls_cert_config.path;
        info!("loading cert for DNS over TLS: {tls_cert_path:?}");

        let tls_cert = tls_cert_config.load(zone_dir).map_err(|err| {
            format!("failed to load tls certificate files from {tls_cert_path:?}: {err}")
        })?;

        info!("binding TLS to {addr:?}");

        let tls_listener = build_tcp_listener(*addr, tls_listen_port)
            .map_err(|err| format!("failed to bind to TLS socket address {addr:?}: {err}"))?;

        info!(
            "listening for TLS on {:?}",
            tls_listener
                .local_addr()
                .map_err(|err| format!("failed to lookup local address: {err}"))?
        );

        let mut tls_config = default_tls_server_config(b"dot", tls_cert)
            .map_err(|err| format!("failed to build default TLS config: {err}"))?;
        if config.ssl_keylog_enabled() {
            warn!("DoT SSL_KEYLOG_FILE support enabled");
            tls_config.key_log = Arc::new(KeyLogFile::new());
        }

        server
            .register_tls_listener_with_tls_config(
                tls_listener,
                config.tcp_request_timeout(),
                Arc::new(tls_config),
            )
            .map_err(|err| format!("failed to register TLS listener: {err}"))?;
    }
    Ok(())
}

#[cfg(feature = "__https")]
fn config_https(
    https_port: Option<u16>,
    server: &mut Server<Catalog>,
    config: &Config,
    tls_cert_config: &TlsCertConfig,
    zone_dir: &Path,
    listen_addrs: &[IpAddr],
) -> Result<(), String> {
    let https_listen_port = https_port.unwrap_or_else(|| config.https_listen_port());
    let endpoint_path = config.http_endpoint();

    if listen_addrs.is_empty() {
        warn!("a tls certificate was specified, but no HTTPS addresses configured to listen on");
        return Ok(());
    }

    for addr in listen_addrs {
        let tls_cert_path = &tls_cert_config.path;
        if let Some(endpoint_name) = &tls_cert_config.endpoint_name {
            info!("loading cert for DNS over TLS named {endpoint_name} from {tls_cert_path:?}");
        } else {
            info!("loading cert for DNS over TLS from {tls_cert_path:?}");
        }
        let tls_cert = tls_cert_config.load(zone_dir).map_err(|err| {
            format!("failed to load tls certificate files from {tls_cert_path:?}: {err}")
        })?;

        info!("binding HTTPS to {addr:?}");

        let https_listener = build_tcp_listener(*addr, https_listen_port)
            .map_err(|err| format!("failed to bind to HTTPS socket address {addr:?}: {err}"))?;

        info!(
            "listening for HTTPS on {:?}",
            https_listener
                .local_addr()
                .map_err(|err| format!("failed to lookup local address: {err}"))?
        );

        let mut tls_config = default_tls_server_config(b"h2", tls_cert)
            .map_err(|err| format!("failed to build default TLS config: {err}"))?;
        if config.ssl_keylog_enabled() {
            warn!("DoH SSL_KEYLOG_FILE support enabled");
            tls_config.key_log = Arc::new(KeyLogFile::new());
        }

        server
            .register_https_listener_with_tls_config(
                https_listener,
                config.tcp_request_timeout(),
                Arc::new(tls_config),
                tls_cert_config.endpoint_name.clone(),
                endpoint_path.into(),
            )
            .map_err(|err| format!("failed to register HTTPS listener: {err}"))?;
    }

    Ok(())
}

#[cfg(feature = "__quic")]
fn config_quic(
    quic_port: Option<u16>,
    server: &mut Server<Catalog>,
    config: &Config,
    tls_cert_config: &TlsCertConfig,
    zone_dir: &Path,
    listen_addrs: &[IpAddr],
) -> Result<(), String> {
    let quic_listen_port = quic_port.unwrap_or_else(|| config.quic_listen_port());

    if listen_addrs.is_empty() {
        warn!("a tls certificate was specified, but no QUIC addresses configured to listen on");
        return Ok(());
    }

    for addr in listen_addrs {
        let tls_cert_path = &tls_cert_config.path;
        if let Some(endpoint_name) = &tls_cert_config.endpoint_name {
            info!("loading cert for DNS over QUIC named {endpoint_name} from {tls_cert_path:?}");
        } else {
            info!("loading cert for DNS over QUIC from {tls_cert_path:?}",);
        }
        let tls_cert = tls_cert_config.load(zone_dir).map_err(|err| {
            format!("failed to load tls certificate files from {tls_cert_path:?}: {err}")
        })?;

        info!("Binding QUIC to {addr:?}");

        let quic_listener = build_udp_socket(*addr, quic_listen_port)
            .map_err(|err| format!("failed to bind to QUIC socket address {addr:?}: {err}"))?;

        info!(
            "listening for QUIC on {:?}",
            quic_listener
                .local_addr()
                .map_err(|err| format!("failed to lookup local address: {err}"))?
        );

        let mut tls_config = default_tls_server_config(b"doq", tls_cert)
            .map_err(|err| format!("failed to build default TLS config: {err}"))?;
        if config.ssl_keylog_enabled() {
            warn!("DoQ SSL_KEYLOG_FILE support enabled");
            tls_config.key_log = Arc::new(KeyLogFile::new());
        }

        server
            .register_quic_listener_and_tls_config(
                quic_listener,
                config.tcp_request_timeout(),
                Arc::new(tls_config),
                tls_cert_config.endpoint_name.clone(),
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

#[cfg(feature = "metrics")]
struct ConfigMetrics {
    #[cfg(feature = "resolver")]
    zones_forwarder: Counter,

    zones_file_primary: Counter,
    zones_file_secondary: Counter,
    #[cfg(feature = "sqlite")]
    zones_sqlite_primary: Counter,
    #[cfg(feature = "sqlite")]
    zones_sqlite_secondary: Counter,
}

#[cfg(feature = "metrics")]
impl ConfigMetrics {
    fn new(config: &Config) -> Self {
        let hickory_build_info =
            gauge!("hickory_build_info", "version" => env!("CARGO_PKG_VERSION"));
        describe_gauge!(
            "hickory_build_info",
            Unit::Count,
            "A metric with a constant '1' labeled by the version from which Hickory DNS was built."
        );
        hickory_build_info.set(1);

        let hickory_config_info = gauge!("hickory_config_info",
            "directory" => config.directory().to_string_lossy().to_string(),
            "disable_https" => config.disable_https().to_string(),
            "disable_quic" => config.disable_quic().to_string(),
            "disable_tcp" => config.disable_tcp().to_string(),
            "disable_tls" => config.disable_tls().to_string(),
            "disable_udp" => config.disable_udp().to_string(),
            "allow_networks" => config.allow_networks().len().to_string(),
            "deny_networks" => config.deny_networks().len().to_string(),
            "zones" => config.zones().len().to_string()
        );
        describe_gauge!(
            "hickory_config_info",
            Unit::Count,
            "Hickory DNS configuration metadata."
        );
        hickory_config_info.set(1);

        let zones_total_name = "hickory_zones_total";
        let zones_file_primary = counter!(zones_total_name, "store" => "file", "role" => "primary");
        let zones_file_secondary =
            counter!(zones_total_name, "store" => "file", "role" => "secondary");

        describe_counter!(
            zones_total_name,
            Unit::Count,
            "Number of DNS zones in stores."
        );

        #[cfg(feature = "resolver")]
        let zones_forwarder = counter!(zones_total_name, "store" => "forwarder");

        #[cfg(feature = "sqlite")]
        let (zones_sqlite_primary, zones_sqlite_secondary) = {
            let zones_primary_sqlite =
                counter!(zones_total_name, "store" => "sqlite", "role" => "primary");
            let zones_secondary_sqlite =
                counter!(zones_total_name, "store" => "sqlite", "role" => "secondary");
            (zones_primary_sqlite, zones_secondary_sqlite)
        };

        Self {
            #[cfg(feature = "resolver")]
            zones_forwarder,
            #[cfg(feature = "sqlite")]
            zones_sqlite_primary,
            zones_file_primary,
            #[cfg(feature = "sqlite")]
            zones_sqlite_secondary,
            zones_file_secondary,
        }
    }

    fn increment_zone_metrics(&self, zone: &ZoneConfig) {
        match &zone.zone_type_config {
            ZoneTypeConfig::Primary(server_config) => self.increment_stores(server_config, true),
            ZoneTypeConfig::Secondary(server_config) => self.increment_stores(server_config, false),
            #[cfg_attr(not(feature = "resolver"), allow(unused_variables))]
            ZoneTypeConfig::External { stores } =>
            {
                #[cfg(feature = "resolver")]
                for store in stores {
                    if let ExternalStoreConfig::Forward(_) = store {
                        self.zones_forwarder.increment(1)
                    }
                }
            }
        }
    }

    fn increment_stores(&self, server_config: &ServerZoneConfig, primary: bool) {
        for store in &server_config.stores {
            if matches!(store, ServerStoreConfig::File(_)) {
                if primary {
                    self.zones_file_primary.increment(1)
                } else {
                    self.zones_file_secondary.increment(1)
                }
            }
            #[cfg(feature = "sqlite")]
            if matches!(store, ServerStoreConfig::Sqlite(_)) {
                if primary {
                    self.zones_sqlite_primary.increment(1)
                } else {
                    self.zones_sqlite_secondary.increment(1)
                }
            };
        }
    }
}

/// Build a TcpListener for a given IP, port pair; IPv6 listeners will not accept v4 connections
fn build_tcp_listener(ip: IpAddr, port: u16) -> Result<TcpListener, Error> {
    let sock = if ip.is_ipv4() {
        Socket::new(Domain::IPV4, Type::STREAM, None)?
    } else {
        let s = Socket::new(Domain::IPV6, Type::STREAM, None)?;
        s.set_only_v6(true)?;
        s
    };

    sock.set_nonblocking(true)?;

    let s_addr = SocketAddr::new(ip, port);
    sock.bind(&s_addr.into())?;

    // this is a fairly typical backlog value, but we don't have any good data to support it as of yet
    sock.listen(128)?;

    TcpListener::from_std(sock.into())
}

/// Build a UdpSocket for a given IP, port pair; IPv6 sockets will not accept v4 connections
fn build_udp_socket(ip: IpAddr, port: u16) -> Result<UdpSocket, Error> {
    let sock = if ip.is_ipv4() {
        Socket::new(Domain::IPV4, Type::DGRAM, None)?
    } else {
        let s = Socket::new(Domain::IPV6, Type::DGRAM, None)?;
        s.set_only_v6(true)?;
        s
    };

    sock.set_nonblocking(true)?;

    let s_addr = SocketAddr::new(ip, port);
    sock.bind(&s_addr.into())?;

    UdpSocket::from_std(sock.into())
}

/// Drop privileges on Unix systems if running as root. Errors that prevent dropping privileges will
/// halt the server.  This must be called after binding to low numbered sockets is complete.
#[cfg(target_family = "unix")]
fn check_drop_privs(user: &str, group: &str) -> Result<(), String> {
    use libc::{getegid, geteuid, getgid, getgrnam, getpwnam, getuid, setgid, setuid};
    use std::ffi::CString;

    // These calls are guaranteed to succeed in a POSIX-conforming environment. In non-conforming
    // environments, implementations may return -1 to indicate a process running without an
    // associated UID/EUID/GID/EGID. In that case, our main block below will not execute as
    // libc typedefs uid_t and gid_t to u32; -1 will be u32::MAX.
    //
    // POSIX reference: IEEE Std 1003.1-1024 getuid, geteuid, getgid, and getegid specifications
    // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getuid.html
    // https://pubs.opengroup.org/onlinepubs/9799919799/functions/geteuid.html
    // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getgid.html
    // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getegid.html
    let (uid, gid, euid, egid) = unsafe { (getuid(), getgid(), geteuid(), getegid()) };

    if uid == 0 || euid == 0 {
        info!(
            "running as root (uid: {uid} gid: {gid} euid: {euid} egid: {egid})...dropping privileges.",
        );

        let Ok(user_cstring) = CString::new(user) else {
            return Err(format!("unable to create CString for user {user}"));
        };

        let Ok(group_cstring) = CString::new(group) else {
            return Err(format!(
                "unable to create CString for group {group}. Exiting."
            ));
        };

        // These functions must be supplied a NULL-terminated string, which is guaranteed by
        // std::ffi::CString.  Upon success, they will return a pointer to a struct passwd or
        // struct group, or NULL upon failure. Testing for a NULL return value is mandatory.
        //
        // POSIX reference: IEEE Std 1003.1-1024 getpwnam and getgrnam specifications
        // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getpwnam.html
        // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getgrnam.html
        let (user_info, group_info) = unsafe {
            (
                getpwnam(user_cstring.as_ptr()),
                getgrnam(group_cstring.as_ptr()),
            )
        };

        if user_info.is_null() {
            return Err(format!("unable to lookup user '{user}'. Exiting."));
        }

        if group_info.is_null() {
            return Err(format!("unable to lookup group '{group}'. Exiting."));
        }

        // These functions must be supplied a gid_t (setgid) and uid_t (setuid), which are
        // supplied by the passwd and group structs returned by getpwnam and getgrnam.
        // The structs are tested to be valid by the calls to is_null() above.
        //
        // The call to setgid must be completed before the call to setuid is made or the
        // process will almost certainly lack the privileges necessary to switch its real gid.
        //
        // POSIX reference: IEEE Std 1003.1-1024 setgid and setuid specifications
        // https://pubs.opengroup.org/onlinepubs/9799919799/functions/setgid.html
        // https://pubs.opengroup.org/onlinepubs/9799919799/functions/setuid.html
        let (setgid_rc, setuid_rc) =
            unsafe { (setgid((*group_info).gr_gid), setuid((*user_info).pw_uid)) };

        if setgid_rc < 0 {
            return Err("unable to set gid. Exiting.".into());
        }

        if setuid_rc < 0 {
            return Err("unable to set uid. Exiting.".into());
        }
    }

    let (uid, gid, euid, egid) = unsafe { (getuid(), getgid(), geteuid(), getegid()) };

    info!("now running as uid: {uid}, gid: {gid} (euid: {euid}, egid: {egid})",);
    Ok(())
}

fn parse_nsid_payload(raw_payload: &str) -> Result<NSIDPayload, ProtoError> {
    let bytes = if let Some(hex_str) = raw_payload.strip_prefix("0x") {
        hex::decode(hex_str)
            .map_err(|e| ProtoError::from(format!("invalid NSID hex encoding: {e}")))?
    } else {
        raw_payload.as_bytes().to_vec()
    };
    NSIDPayload::new(bytes)
}

#[cfg(target_family = "unix")]
static DEFAULT_USER: &str = "nobody";
#[cfg(target_family = "unix")]
static DEFAULT_GROUP: &str = "nobody";

#[cfg(test)]
mod tests {
    use hickory_proto::rr::rdata::opt::NSIDPayload;

    use super::parse_nsid_payload;

    #[test]
    fn test_hex_nsid_payload() {
        let expected = NSIDPayload::new(vec![0xC0, 0xFF, 0xEE]).unwrap();
        let value = parse_nsid_payload("0xC0FFEE").unwrap();
        assert_eq!(value, expected);
    }

    #[test]
    fn test_string_nsid_payload() {
        let string_value = "HickoryDNS";
        let expected = NSIDPayload::new(string_value.as_bytes()).unwrap();
        let value = parse_nsid_payload(string_value).unwrap();
        assert_eq!(value, expected);
    }

    #[test]
    fn test_nsid_payload_too_long() {
        let too_large = "x".repeat(u16::MAX as usize + 1);
        let err = parse_nsid_payload(&too_large).unwrap_err();
        assert_eq!(err.to_string(), "NSID EDNS payload too large");
    }
}
