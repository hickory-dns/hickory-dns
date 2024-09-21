// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The dns client program

// BINARY WARNINGS
#![warn(
    clippy::default_trait_access,
    clippy::dbg_macro,
    clippy::unimplemented,
    missing_copy_implementations,
    missing_docs,
    non_snake_case,
    non_upper_case_globals,
    rust_2018_idioms,
    unreachable_pub
)]

use std::net::SocketAddr;
#[cfg(feature = "dns-over-rustls")]
use std::sync::Arc;

use clap::{Args, Parser, Subcommand, ValueEnum};
#[cfg(feature = "dns-over-rustls")]
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified},
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, RootCertStore,
};
use tracing::Level;

use hickory_client::client::{AsyncClient, ClientHandle};
#[cfg(feature = "dns-over-rustls")]
use hickory_proto::rustls::tls_client_connect;
use hickory_proto::{
    rr::{DNSClass, Name, RData, RecordSet, RecordType},
    runtime::{RuntimeProvider, TokioRuntimeProvider},
    serialize::txt::RDataParser,
    tcp::TcpClientStream,
    udp::UdpClientStream,
};

/// A CLI interface for the hickory-client.
///
/// This utility directly uses the hickory-client to perform actions with a single
/// DNS server
#[derive(Debug, Parser)]
#[clap(name = "trust dns client", version)]
struct Opts {
    /// Specify a nameserver to use, ip and port e.g. 8.8.8.8:53 or \[2001:4860:4860::8888\]:53 (port required)
    #[clap(short = 'n', long)]
    nameserver: SocketAddr,

    /// Protocol type to use for the communication
    #[clap(short = 'p', long, default_value = "udp", value_enum)]
    protocol: Protocol,

    /// TLS endpoint name, i.e. the name in the certificate presented by the remote server
    #[clap(short = 't', long, required_if_eq_any = [("protocol", "tls"), ("protocol", "https"), ("protocol", "quic")])]
    tls_dns_name: Option<String>,

    /// HTTP endpoint path. Relevant only to DNS-over-HTTPS. Defaults to `/dns-query`.
    #[clap(short = 'e', long, default_value = "/dns-query")]
    http_endpoint: Option<String>,

    /// For TLS, HTTPS, QUIC and H3 a custom ALPN code can be supplied
    ///
    /// Defaults: none for TLS (`dot` has been suggested), `h2` for HTTPS, `doq` for QUIC, and `h3` for H3
    #[clap(short = 'a',
        long,
        default_value_ifs = [("protocol", "tls", None), ("protocol", "https", Some("h2")), ("protocol", "quic", Some("doq")), ("protocol", "h3", Some("h3"))]
    )]
    alpn: Option<String>,

    // TODO: put this behind a feature gate
    /// DANGER: do not verify remote nameserver
    #[clap(long)]
    do_not_verify_nameserver_cert: bool,

    // TODO: zone is required for all update operations...
    /// Zone, required for dynamic DNS updates, e.g. example.com if updating www.example.com
    #[clap(short = 'z', long)]
    zone: Option<Name>,

    /// The Class of the record
    #[clap(long, default_value_t = DNSClass::IN)]
    class: DNSClass,

    /// Enable debug and all logging
    #[clap(long)]
    debug: bool,

    /// Enable info + warning + error logging
    #[clap(long)]
    info: bool,

    /// Enable warning + error logging
    #[clap(long)]
    warn: bool,

    /// Enable error logging
    #[clap(long)]
    error: bool,

    /// Command to execute
    #[clap(subcommand)]
    command: Command,
}

#[derive(Clone, Debug, ValueEnum)]
enum Protocol {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
    H3,
}

#[derive(Debug, Subcommand)]
enum Command {
    Query(QueryOpt),
    Notify(NotifyOpt),
    Create(CreateOpt),
    Append(AppendOpt),
    // CompareAndSwap(),
    DeleteRecord(DeleteRecordOpt),
    // DeleteRecordSet,
    // DeleteAll,
    // ZoneTransfer,
    // Raw?
}

/// Query a name server for the record of the given type
#[derive(Debug, Args)]
struct QueryOpt {
    /// Name of the record to query
    name: Name,

    /// Type of DNS record to notify
    #[clap(name = "TYPE")]
    ty: RecordType,
}

/// Notify a nameserver that a record has been updated
#[derive(Debug, Args)]

struct NotifyOpt {
    /// Name associated to the record that is being notified
    name: Name,

    /// Type of DNS record to notify
    #[clap(name = "TYPE")]
    ty: RecordType,

    /// Optional record data to associate
    rdata: Vec<String>,
}

/// Create a new record in the target zone
#[derive(Debug, Args)]
struct CreateOpt {
    /// Name associated to the record to create
    name: Name,

    /// Type of DNS record to create
    #[clap(name = "TYPE")]
    ty: RecordType,

    /// Time to live value for the record
    ttl: u32,

    /// Record data to associate
    #[clap(required = true)]
    rdata: Vec<String>,
}

/// Append record data to a record set
#[derive(Debug, Args)]
struct AppendOpt {
    /// If true, then the record must exist for the append to succeed
    #[clap(long)]
    must_exist: bool,

    /// Name associated to the record that is being updated
    name: Name,

    /// Type of DNS record to update
    #[clap(name = "TYPE")]
    ty: RecordType,

    /// Time to live value for the record
    ttl: u32,

    /// Record data to associate
    #[clap(required = true)]
    rdata: Vec<String>,
}

/// Delete a single record from a zone, the data must match the record
#[derive(Debug, Args)]
struct DeleteRecordOpt {
    /// Name associated to the record that is being updated
    name: Name,

    /// Type of DNS record to update
    #[clap(name = "TYPE")]
    ty: RecordType,

    /// Record data to associate
    #[clap(required = true)]
    rdata: Vec<String>,
}

/// Run the resolve program
#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts: Opts = Opts::parse();

    // enable logging early
    let log_level = if opts.debug {
        Some(Level::DEBUG)
    } else if opts.info {
        Some(Level::INFO)
    } else if opts.warn {
        Some(Level::WARN)
    } else if opts.error {
        Some(Level::ERROR)
    } else {
        None
    };

    hickory_util::logger(env!("CARGO_BIN_NAME"), log_level);

    // TODO: need to cleanup all of ClientHandle and the Client in general to make it dynamically usable.
    let provider = TokioRuntimeProvider::new();
    match opts.protocol {
        Protocol::Udp => udp(opts, provider).await?,
        Protocol::Tcp => tcp(opts, provider).await?,
        Protocol::Tls => tls(opts, provider).await?,
        Protocol::Https => https(opts, provider).await?,
        Protocol::Quic => quic(opts).await?,
        Protocol::H3 => h3(opts).await?,
    };

    Ok(())
}

async fn udp(opts: Opts, provider: impl RuntimeProvider) -> Result<(), Box<dyn std::error::Error>> {
    let nameserver = opts.nameserver;

    println!("; using udp:{nameserver}");
    let stream = UdpClientStream::new(nameserver, provider);
    let (client, bg) = AsyncClient::connect(stream).await?;
    let handle = tokio::spawn(bg);
    handle_request(opts.class, opts.zone, opts.command, client).await?;
    drop(handle);

    Ok(())
}

async fn tcp(opts: Opts, provider: impl RuntimeProvider) -> Result<(), Box<dyn std::error::Error>> {
    let nameserver = opts.nameserver;

    println!("; using tcp:{nameserver}");
    let (stream, sender) = TcpClientStream::new(nameserver, None, None, provider);
    let client = AsyncClient::new(stream, sender, None);
    let (client, bg) = client.await?;

    let handle = tokio::spawn(bg);
    handle_request(opts.class, opts.zone, opts.command, client).await?;
    drop(handle);

    Ok(())
}

#[cfg(not(feature = "dns-over-rustls"))]
async fn tls(
    _opts: Opts,
    _provider: impl RuntimeProvider,
) -> Result<(), Box<dyn std::error::Error>> {
    panic!("`dns-over-rustls` feature is required during compilation");
}

#[cfg(feature = "dns-over-rustls")]
async fn tls(opts: Opts, provider: impl RuntimeProvider) -> Result<(), Box<dyn std::error::Error>> {
    let nameserver = opts.nameserver;
    let alpn = opts.alpn.map(String::into_bytes);
    let dns_name = opts
        .tls_dns_name
        .expect("tls_dns_name is required tls connections");
    println!("; using tls:{nameserver} dns_name:{dns_name}");

    let mut config = tls_config()?;
    if opts.do_not_verify_nameserver_cert {
        self::do_not_verify_nameserver_cert(&mut config);
    }
    if let Some(alpn) = alpn {
        config.alpn_protocols.push(alpn);
    }

    let config = Arc::new(config);
    let (stream, sender) = tls_client_connect(nameserver, dns_name, config, provider);
    let (client, bg) = AsyncClient::new(stream, sender, None).await?;

    let handle = tokio::spawn(bg);
    handle_request(opts.class, opts.zone, opts.command, client).await?;
    drop(handle);

    Ok(())
}

#[cfg(not(feature = "dns-over-https-rustls"))]
async fn https(
    _opts: Opts,
    _provider: impl RuntimeProvider,
) -> Result<(), Box<dyn std::error::Error>> {
    panic!("`dns-over-https` feature is required during compilation");
}

#[cfg(feature = "dns-over-https-rustls")]
async fn https(
    opts: Opts,
    provider: impl RuntimeProvider,
) -> Result<(), Box<dyn std::error::Error>> {
    use hickory_proto::h2::HttpsClientStreamBuilder;

    let nameserver = opts.nameserver;
    let alpn = opts
        .alpn
        .map(String::into_bytes)
        .expect("ALPN is required for HTTPS");
    let dns_name = opts
        .tls_dns_name
        .expect("tls_dns_name is required for https connections");
    let http_endpoint = opts
        .http_endpoint
        .expect("http_endpoint is required for https connections");
    println!("; using https:{nameserver} dns_name:{dns_name}");

    let mut config = tls_config()?;
    if opts.do_not_verify_nameserver_cert {
        self::do_not_verify_nameserver_cert(&mut config);
    }
    config.alpn_protocols.push(alpn);
    let config = Arc::new(config);

    let https_builder = HttpsClientStreamBuilder::with_client_config(config, provider);
    let (client, bg) =
        AsyncClient::connect(https_builder.build(nameserver, dns_name, http_endpoint)).await?;

    let handle = tokio::spawn(bg);
    handle_request(opts.class, opts.zone, opts.command, client).await?;
    drop(handle);

    Ok(())
}

#[cfg(not(feature = "dns-over-quic"))]
async fn quic(_opts: Opts) -> Result<(), Box<dyn std::error::Error>> {
    panic!("`dns-over-quic` feature is required during compilation");
}

#[cfg(feature = "dns-over-quic")]
async fn quic(opts: Opts) -> Result<(), Box<dyn std::error::Error>> {
    use hickory_proto::quic::{self, QuicClientStream};

    let nameserver = opts.nameserver;
    let alpn = opts
        .alpn
        .map(String::into_bytes)
        .expect("ALPN is required for QUIC");
    let dns_name = opts
        .tls_dns_name
        .expect("tls_dns_name is required quic connections");
    println!("; using quic:{nameserver} dns_name:{dns_name}");

    let mut config = quic::client_config_tls13()?;
    if opts.do_not_verify_nameserver_cert {
        self::do_not_verify_nameserver_cert(&mut config);
    }
    config.alpn_protocols.push(alpn);

    let mut quic_builder = QuicClientStream::builder();
    quic_builder.crypto_config(config);
    let (client, bg) = AsyncClient::connect(quic_builder.build(nameserver, dns_name)).await?;

    let handle = tokio::spawn(bg);
    handle_request(opts.class, opts.zone, opts.command, client).await?;
    drop(handle);

    Ok(())
}

#[cfg(not(feature = "dns-over-h3"))]
async fn h3(_opts: Opts) -> Result<(), Box<dyn std::error::Error>> {
    panic!("`dns-over-h3` feature is required during compilation");
}

#[cfg(feature = "dns-over-h3")]
async fn h3(opts: Opts) -> Result<(), Box<dyn std::error::Error>> {
    use hickory_proto::h3::{self, H3ClientStream};

    let nameserver = opts.nameserver;
    let alpn = opts
        .alpn
        .map(String::into_bytes)
        .expect("ALPN is required for H3");
    let dns_name = opts
        .tls_dns_name
        .expect("tls_dns_name is required for H3 connections");
    let http_endpoint = opts
        .http_endpoint
        .expect("http_endpoint is required for H3 connections");
    println!("; using h3:{nameserver} dns_name:{dns_name}");

    let mut config = h3::client_config_tls13()?;
    if opts.do_not_verify_nameserver_cert {
        self::do_not_verify_nameserver_cert(&mut config);
    }
    config.alpn_protocols.push(alpn);

    let mut h3_builder = H3ClientStream::builder();
    h3_builder.crypto_config(config);
    let (client, bg) =
        AsyncClient::connect(h3_builder.build(nameserver, dns_name, http_endpoint)).await?;

    let handle = tokio::spawn(bg);
    handle_request(opts.class, opts.zone, opts.command, client).await?;
    drop(handle);

    Ok(())
}

async fn handle_request(
    class: DNSClass,
    zone: Option<Name>,
    command: Command,
    mut client: impl ClientHandle,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = match command {
        Command::Query(query) => {
            let name = query.name;
            let ty = query.ty;
            println!("; sending query: {name} {class} {ty}");
            client.query(name, class, ty).await?
        }
        Command::Notify(opt) => {
            let name = opt.name;
            let ty = opt.ty;
            let ttl = 0;
            let rdata = opt.rdata;

            let rdata = if rdata.is_empty() {
                None
            } else {
                Some(record_set_from(name.clone(), class, ty, ttl, rdata))
            };

            println!("; sending notify: {name} {class} {ty}");
            client.notify(name, class, ty, rdata).await?
        }
        Command::Create(opt) => {
            let zone = zone.expect("zone is required for dynamic update operations");
            let name = opt.name;
            let ty = opt.ty;
            let ttl = opt.ttl;
            let rdata = opt.rdata;

            let rdata = record_set_from(name.clone(), class, ty, ttl, rdata);

            println!("; sending create: {name} {class} {ty} in {zone}");
            client.create(rdata, zone).await?
        }
        Command::Append(opt) => {
            let zone = zone.expect("zone is required for dynamic update operations");
            let name = opt.name;
            let ty = opt.ty;
            let ttl = opt.ttl;
            let rdata = opt.rdata;
            let must_exist = opt.must_exist;

            let rdata = record_set_from(name.clone(), class, ty, ttl, rdata);

            println!(
                "; sending append: {name} {class} {ty} in {zone} and must_exist({must_exist})"
            );
            client.append(rdata, zone, must_exist).await?
        }
        Command::DeleteRecord(opt) => {
            let zone = zone.expect("zone is required for dynamic update operations");
            let name = opt.name;
            let ty = opt.ty;
            let ttl = 0;
            let rdata = opt.rdata;

            let rdata = record_set_from(name.clone(), class, ty, ttl, rdata);

            println!("; sending delete-record: {name} {class} {ty} from {zone}");
            client.delete_by_rdata(rdata, zone).await?
        }
    };

    let response = response.into_message();
    println!("; received response");
    println!("{response}");
    Ok(())
}

fn record_set_from(
    name: Name,
    class: DNSClass,
    record_type: RecordType,
    ttl: u32,
    rdata: Vec<String>,
) -> RecordSet {
    let rdata = rdata
        .iter()
        .map(|r| RData::try_from_str(record_type, r).expect("failed to parse rdata"));

    let mut record_set = RecordSet::with_ttl(name, record_type, ttl);
    record_set.set_dns_class(class);

    for data in rdata {
        record_set.add_rdata(data);
    }

    record_set
}

#[cfg(feature = "dns-over-rustls")]
fn tls_config() -> Result<ClientConfig, Box<dyn std::error::Error>> {
    #[cfg_attr(
        not(any(feature = "native-certs", feature = "webpki-roots")),
        allow(unused_mut)
    )]
    let mut root_store = RootCertStore::empty();
    #[cfg(all(feature = "native-certs", not(feature = "webpki-roots")))]
    {
        use hickory_proto::error::ProtoErrorKind;

        let (added, ignored) =
            root_store.add_parsable_certificates(&rustls_native_certs::load_native_certs()?);

        if ignored > 0 {
            tracing::warn!(
                "failed to parse {} certificate(s) from the native root store",
                ignored,
            );
        }

        if added == 0 {
            return Err(ProtoErrorKind::NativeCerts.into());
        }
    }
    #[cfg(feature = "webpki-roots")]
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    Ok(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

#[cfg(feature = "dns-over-rustls")]
fn do_not_verify_nameserver_cert(tls_config: &mut ClientConfig) {
    let provider = tls_config.crypto_provider().clone();
    tls_config
        .dangerous()
        .set_certificate_verifier(Arc::new(DangerousVerifier { provider }));
}

#[cfg(feature = "dns-over-rustls")]
#[derive(Debug)]
struct DangerousVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

#[cfg(feature = "dns-over-rustls")]
impl rustls::client::danger::ServerCertVerifier for DangerousVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        println!(";!!!NOT VERIFYING THE SERVER TLS CERTIFICATE!!!");
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        println!(";!!!NOT VERIFYING THE SERVER TLS CERTIFICATE!!!");
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        println!(";!!!NOT VERIFYING THE SERVER TLS CERTIFICATE!!!");
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
