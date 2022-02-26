// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
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

use std::net::{IpAddr, SocketAddr};

use clap::Parser;
use console::style;

use trust_dns_recursor::Recursor;
use trust_dns_resolver::config::{
    NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts,
};
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::TokioAsyncResolver;

/// A CLI interface for the trust-dns-recursor.
///
/// This utility directly uses the trust-dns-recursor to perform a recursive lookup
///   starting with a sent of hints or root dns servers.
#[derive(Debug, Parser)]
#[clap(name = "recurse")]
struct Opts {
    /// Name to attempt to resolve, this is assumed to be fully-qualified
    domainname: String,

    /// Type of query to issue, e.g. A, AAAA, NS, etc.
    #[clap(short = 't', long = "type", default_value = "A")]
    ty: RecordType,

    /// Specify a nameserver to use, ip and port e.g. 8.8.8.8:53 or \[2001:4860:4860::8888\]:53 (port required)
    #[clap(short = 'n', long, require_value_delimiter = true)]
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
}

/// Run the resolve programf
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
        .filter_module("trust_dns_recursor", log_level)
        .filter_module("trust_dns_resolver", log_level)
        .filter_module("trust_dns_proto", log_level)
        .write_style(env_logger::WriteStyle::Auto)
        .format_indent(Some(4))
        .init();

    // Configure all the name servers
    let mut hints = NameServerConfigGroup::new();

    for socket_addr in &opts.nameserver {
        hints.push(NameServerConfig {
            socket_addr: *socket_addr,
            protocol: Protocol::Tcp,
            tls_dns_name: None,
            trust_nx_responses: false,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
            bind_addr: opts.bind.map(|ip| SocketAddr::new(ip, 0)),
        });

        hints.push(NameServerConfig {
            socket_addr: *socket_addr,
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_nx_responses: false,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
            bind_addr: opts.bind.map(|ip| SocketAddr::new(ip, 0)),
        });
    }

    let ipv4 = opts.ipv4 || !opts.ipv6;
    let ipv6 = opts.ipv6 || !opts.ipv4;

    let udp = opts.udp || !opts.tcp;
    let tcp = opts.tcp || !opts.udp;

    hints.retain(|ns| (ipv4 && ns.socket_addr.is_ipv4()) || (ipv6 && ns.socket_addr.is_ipv6()));
    hints.retain(|ns| {
        (udp && ns.protocol == Protocol::Udp) || (tcp && ns.protocol == Protocol::Tcp)
    });

    let name_servers =
        hints
            .iter()
            .map(|n| format!("{}", n))
            .fold(String::new(), |mut names, n| {
                if !names.is_empty() {
                    names.push_str(", ")
                }

                names.push_str(&n);
                names
            });

    // query parameters
    let name = &opts.domainname;
    let ty = opts.ty;

    let recursor = Recursor::new(hints)?;

    // execute query
    println!(
        "Recursing for {name} {ty} from hints",
        name = style(name).yellow(),
        ty = style(ty).yellow(),
    );

    let lookup = recursor.resolve(name.to_string(), ty).await?;

    // report response, TODO: better display of errors
    println!(
        "{} for query {}",
        style("Success").green(),
        style(lookup.query()).blue()
    );

    for r in lookup.record_iter() {
        print!(
            "\t{name} {ttl} {class} {ty}",
            name = style(r.name()).blue(),
            ttl = style(r.ttl()).blue(),
            class = style(r.dns_class()).blue(),
            ty = style(r.record_type()).blue(),
        );

        if let Some(rdata) = r.data() {
            println!(" {rdata}", rdata = rdata);
        } else {
            println!("NULL")
        }
    }

    Ok(())
}
