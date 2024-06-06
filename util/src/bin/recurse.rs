// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The resolve program

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
    path::PathBuf,
    time::Instant,
};

use clap::Parser;
use console::style;

use hickory_client::op::Query;
use hickory_recursor::Recursor;
use hickory_resolver::{
    config::{NameServerConfig, NameServerConfigGroup, Protocol},
    proto::rr::RecordType,
    Name,
};

/// A CLI interface for the hickory-dns-recursor.
///
/// This utility directly uses the hickory-dns-recursor to perform a recursive lookup
///   starting with a set of root dns servers, aka hints.
#[derive(Debug, Parser)]
#[clap(name = "recurse")]
struct Opts {
    /// Name to attempt to resolve, this is assumed to be fully-qualified
    domainname: Name,

    /// Type of query to issue, e.g. A, AAAA, NS, etc.
    #[clap(short = 't', long = "type", default_value = "A")]
    ty: RecordType,

    /// Specify a nameserver to use, ip and port e.g. 8.8.8.8:53 or \[2001:4860:4860::8888\]:53 (port required)
    /// ip:port are delimited by a comma like 8.8.8.8:53,1.1.1.1:53
    #[clap(short = 'n', long, use_value_delimiter = true, value_delimiter(','))]
    nameserver: Vec<SocketAddr>,

    /// Specify the IP address to connect from.
    #[clap(long)]
    bind: Option<IpAddr>,

    /// Use ipv4 addresses only, default is both ipv4 and ipv6
    #[clap(long)]
    ipv4: bool,

    /// Use ipv6 addresses only, default is both ipv4 and ipv6
    #[clap(long)]
    ipv6: bool,

    /// Use only UDP, default to UDP and TCP
    #[clap(long)]
    udp: bool,

    /// Use only TCP, default to UDP and TCP
    #[clap(long)]
    tcp: bool,

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

    /// Path to a roots file
    #[clap(short = 'r', long)]
    roots: Option<PathBuf>,
}

/// Run the resolve programf
#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts: Opts = Opts::parse();

    // enable logging early
    let log_level = if opts.debug {
        Some(tracing::Level::DEBUG)
    } else if opts.info {
        Some(tracing::Level::INFO)
    } else if opts.warn {
        Some(tracing::Level::WARN)
    } else if opts.error {
        Some(tracing::Level::ERROR)
    } else {
        None
    };

    hickory_util::logger(env!("CARGO_BIN_NAME"), log_level);

    // Configure all the name servers
    let mut roots = NameServerConfigGroup::new();

    for socket_addr in &opts.nameserver {
        roots.push(NameServerConfig {
            socket_addr: *socket_addr,
            protocol: Protocol::Tcp,
            tls_dns_name: None,
            trust_negative_responses: false,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
            bind_addr: opts.bind.map(|ip| SocketAddr::new(ip, 0)),
        });

        roots.push(NameServerConfig {
            socket_addr: *socket_addr,
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
            bind_addr: opts.bind.map(|ip| SocketAddr::new(ip, 0)),
        });
    }

    let ipv4 = opts.ipv4 || !opts.ipv6;
    let ipv6 = opts.ipv6 || !opts.ipv4;

    let udp = opts.udp || !opts.tcp;
    let tcp = opts.tcp || !opts.udp;

    roots.retain(|ns| (ipv4 && ns.socket_addr.is_ipv4()) || (ipv6 && ns.socket_addr.is_ipv6()));
    roots.retain(|ns| {
        (udp && ns.protocol == Protocol::Udp) || (tcp && ns.protocol == Protocol::Tcp)
    });

    // query parameters
    let name = opts.domainname;
    let ty = opts.ty;

    let recursor = Recursor::builder().build(roots)?;

    // execute query
    println!(
        "Recursing for {name} {ty} from roots",
        name = style(&name).yellow(),
        ty = style(ty).yellow(),
    );

    let now = Instant::now();
    let query = Query::query(name, ty);
    let lookup = recursor.resolve(query, now, false).await?;

    // report response, TODO: better display of errors
    println!(
        "{} for query {:?}",
        style("Success").green(),
        style(&lookup).blue()
    );

    for r in lookup.record_iter().filter(|r| r.record_type() == ty) {
        print!(
            "\t{name} {ttl} {class} {ty} {rdata}",
            name = style(r.name()).blue(),
            ttl = style(r.ttl()).blue(),
            class = style(r.dns_class()).blue(),
            ty = style(r.record_type()).blue(),
            rdata = r.data()
        );
    }

    Ok(())
}
