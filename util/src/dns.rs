// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
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

use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use clap::{ArgEnum, Args, Parser, Subcommand};
use console::style;
use rustls::{Certificate, ClientConfig, OwnedTrustAnchor, RootCertStore};
use tokio::net::{TcpStream as TokioTcpStream, UdpSocket};

use trust_dns_client::{
    client::{AsyncClient, ClientHandle},
    rr::{DNSClass, RData, RecordSet, RecordType},
    serialize::txt::RDataParser,
    tcp::TcpClientStream,
    udp::UdpClientStream,
};
use trust_dns_proto::{
    https::HttpsClientStreamBuilder, iocompat::AsyncIoTokioAsStd, rr::Name,
    rustls::tls_client_connect, xfer::DnsRequestOptions,
};

/// A CLI interface for the trust-dns-client.
///
/// This utility directly uses the trust-dns-client to perform actions with a single
/// DNS server
#[derive(Debug, Parser)]
#[clap(name = "trust dns client", version)]
struct Opts {
    /// Specify a nameserver to use, ip and port e.g. 8.8.8.8:53 or \[2001:4860:4860::8888\]:53 (port required)
    #[clap(short = 'n', long)]
    nameserver: SocketAddr,

    /// Protocol type to use for the communication
    #[clap(short = 'p', long, default_value = "udp", arg_enum)]
    protocol: Protocol,

    /// TLS endpoint name, i.e. the name in the certificate presented by the remote server
    #[clap(short = 't', long, required_if_eq_any = &[("protocol", "tls"), ("protocol", "https"), ("protocol", "quic")])]
    tls_dns_name: Option<String>,

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

#[derive(Clone, Debug, ArgEnum)]
enum Protocol {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
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
        log::LevelFilter::Debug
    } else if opts.info {
        log::LevelFilter::Info
    } else if opts.warn {
        log::LevelFilter::Warn
    } else if opts.error {
        log::LevelFilter::Error
    } else {
        log::LevelFilter::Off
    };

    // Get query term
    env_logger::builder()
        .filter_module("trust_dns_resolver", log_level)
        .filter_module("trust_dns_proto", log_level)
        .filter_module("trust_dns_client", log_level)
        .write_style(env_logger::WriteStyle::Auto)
        .format_indent(Some(4))
        .init();

    // params
    let nameserver = opts.nameserver;
    let class = opts.class;
    let zone = opts.zone;
    let protocol = opts.protocol;
    let dns_name = opts.tls_dns_name;
    let command = opts.command;

    // TODO: need to cleanup all of ClientHandle and the Client in general to make it dynamically usable.
    match protocol {
        Protocol::Udp => {
            println!("; using udp:{nameserver}");
            let stream = UdpClientStream::<UdpSocket>::new(nameserver);
            let (client, bg) = AsyncClient::connect(stream).await?;
            let handle = tokio::spawn(bg);
            handle_request(class, zone, command, client).await?;
            drop(handle);
        }
        Protocol::Tcp => {
            println!("; using tcp:{nameserver}");
            let (stream, sender) =
                TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(nameserver);
            let client = AsyncClient::new(stream, sender, None);
            let (client, bg) = client.await?;

            let handle = tokio::spawn(bg);
            handle_request(class, zone, command, client).await?;
            drop(handle);
        }
        Protocol::Tls => {
            let dns_name = dns_name.expect("tls_dns_name is required tls connections");
            println!("; using tls:{nameserver} dns_name:{dns_name}");

            let config = Arc::new(tls_config());
            let (stream, sender) = tls_client_connect::<AsyncIoTokioAsStd<TokioTcpStream>>(
                nameserver, dns_name, config,
            );
            let (client, bg) = AsyncClient::new(stream, sender, None).await?;

            let handle = tokio::spawn(bg);
            handle_request(class, zone, command, client).await?;
            drop(handle);
        }
        Protocol::Https => {
            const ALPN_H2: &[u8] = b"h2";

            let dns_name = dns_name.expect("tls_dns_name is required https connections");
            println!("; using https:{nameserver} dns_name:{dns_name}");

            let mut config = tls_config();
            config.alpn_protocols.push(ALPN_H2.to_vec());
            let config = Arc::new(config);

            let https_builder = HttpsClientStreamBuilder::with_client_config(config);
            let (client, bg) = AsyncClient::connect(
                https_builder.build::<AsyncIoTokioAsStd<TokioTcpStream>>(nameserver, dns_name),
            )
            .await?;

            let handle = tokio::spawn(bg);
            handle_request(class, zone, command, client).await?;
            drop(handle);
        }
        Protocol::Quic => {
            let dns_name = dns_name.expect("tls_dns_name is required quic connections");
            println!("; using quic:{nameserver} dns_name:{dns_name}");
            todo!()
        }
    };

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

    let response = response.into_inner();
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

fn tls_config() -> ClientConfig {
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}
