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
};

use clap::{ArgEnum, Args, Parser, Subcommand};
use console::style;

use trust_dns_client::rr::{DNSClass, RData, RecordType};
use trust_dns_proto::{rr::Name, xfer::DnsRequestOptions};

/// A CLI interface for the trust-dns-client.
///
/// This utility directly uses the trust-dns-client to perform actions with a single
/// DNS server
#[derive(Debug, Parser)]
#[clap(name = "dns client")]
struct Opts {
    /// Specify a nameserver to use, ip and port e.g. 8.8.8.8:53 or \[2001:4860:4860::8888\]:53 (port required)
    #[clap(short = 'n', long)]
    nameserver: SocketAddr,

    /// Specify the IP address to connect from.
    #[clap(long)]
    bind: Option<IpAddr>,

    /// Protocol type to use for the communication
    #[clap(short = 'p', long, default_value = "udp", arg_enum)]
    protocol: Protocol,

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

    // query parameters
    let name = opts.zone.as_ref();

    // execute query
    println!("Sending DNS request");

    // report response, TODO: better display of errors
    println!("Got response");

    Ok(())
}
