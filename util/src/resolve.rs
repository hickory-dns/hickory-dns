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

use trust_dns_resolver::config::{
    NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts,
};
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::TokioAsyncResolver;

/// A CLI interface for the trust-dns-resolver.
///
/// This utility directly uses the trust-dns-resolver to perform a lookup to a
/// set of nameservers. Many of the features can be directly tested via the
/// FLAGS and OPTIONS. By default (like trust-dns-resolver) the configured
/// nameservers are the Google provided ones. The system configured ones can be
/// used with the `--system` FLAG. Other nameservers, as many as desired, can
/// be configured directly with the `--nameserver` OPTION.
#[derive(Debug, Parser)]
#[clap(name = "resolve")]
struct Opts {
    /// Name to attempt to resolve, if followed by a '.' then it's a fully-qualified-domain-name.
    domainname: String,

    /// Type of query to issue, e.g. A, AAAA, NS, etc.
    #[clap(short = 't', long = "type", default_value = "A")]
    ty: RecordType,

    /// Happy eye balls lookup, ipv4 and ipv6
    #[clap(short = 'e', long = "happy", conflicts_with("ty"))]
    happy: bool,

    /// Use system configuration, e.g. /etc/resolv.conf, instead of defaults
    #[clap(short = 's', long = "system")]
    system: bool,

    /// Use google resolvers, default
    #[clap(long)]
    google: bool,

    /// Use cloudflare resolvers
    #[clap(long)]
    cloudflare: bool,

    /// Use quad9 resolvers
    #[clap(long)]
    quad9: bool,

    /// Specify a nameserver to use, ip and port e.g. 8.8.8.8:53 or \[2001:4860:4860::8888\]:53 (port required)
    #[clap(
        short = 'n',
        long,
        use_value_delimiter = true,
        require_value_delimiter = true
    )]
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

/// Run the resolve program
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

    trust_dns_util::logger(env!("CARGO_BIN_NAME"), log_level);

    // read system configuration
    let (sys_config, sys_options): (Option<ResolverConfig>, Option<ResolverOpts>) = if opts.system {
        let (config, options) = trust_dns_resolver::system_conf::read_system_conf()?;

        (Some(config), Some(options))
    } else {
        (None, None)
    };

    // Configure all the name servers
    let mut name_servers = NameServerConfigGroup::new();

    for socket_addr in &opts.nameserver {
        name_servers.push(NameServerConfig {
            socket_addr: *socket_addr,
            protocol: Protocol::Tcp,
            tls_dns_name: None,
            trust_nx_responses: false,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
            bind_addr: opts.bind.map(|ip| SocketAddr::new(ip, 0)),
        });

        name_servers.push(NameServerConfig {
            socket_addr: *socket_addr,
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_nx_responses: false,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
            bind_addr: opts.bind.map(|ip| SocketAddr::new(ip, 0)),
        });
    }

    if opts.google {
        name_servers.merge(NameServerConfigGroup::google());
    }
    if opts.cloudflare {
        name_servers.merge(NameServerConfigGroup::cloudflare());
    }
    if opts.quad9 {
        name_servers.merge(NameServerConfigGroup::quad9());
    }
    if name_servers.is_empty() && sys_config.is_none() {
        name_servers.merge(NameServerConfigGroup::google());
    }

    let ipv4 = opts.ipv4 || !opts.ipv6;
    let ipv6 = opts.ipv6 || !opts.ipv4;

    let udp = opts.udp || !opts.tcp;
    let tcp = opts.tcp || !opts.udp;

    name_servers
        .retain(|ns| (ipv4 && ns.socket_addr.is_ipv4()) || (ipv6 && ns.socket_addr.is_ipv6()));
    name_servers.retain(|ns| {
        (udp && ns.protocol == Protocol::Udp) || (tcp && ns.protocol == Protocol::Tcp)
    });

    let mut config = sys_config.unwrap_or_else(ResolverConfig::new);

    for ns in name_servers.iter() {
        config.add_name_server(ns.clone());
    }

    let name_servers = config.name_servers().iter().map(|n| format!("{}", n)).fold(
        String::new(),
        |mut names, n| {
            if !names.is_empty() {
                names.push_str(", ")
            }

            names.push_str(&n);
            names
        },
    );

    // query parameters
    let name = &opts.domainname;
    let ty = opts.ty;

    // configure the resolver options
    let mut options = sys_options.unwrap_or_default();
    if opts.happy {
        options.ip_strategy = trust_dns_resolver::config::LookupIpStrategy::Ipv4AndIpv6;
    }

    let resolver = TokioAsyncResolver::tokio(config, options)?;

    // execute query
    println!(
        "Querying for {name} {ty} from {ns}",
        name = style(name).yellow(),
        ty = style(ty).yellow(),
        ns = style(name_servers).blue()
    );

    let lookup = if opts.happy {
        let lookup = resolver.lookup_ip(name.to_string()).await?;

        lookup.into()
    } else {
        resolver.lookup(name.to_string(), ty).await?
    };

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
