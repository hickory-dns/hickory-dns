// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::SocketAddr;

use console::Term;
use structopt::StructOpt;

use trust_dns_resolver::config::{
    NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts,
};
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::TokioAsyncResolver;

/// A CLI interface for the trust-dns-resolver.
#[derive(Debug, StructOpt)]
struct Opts {
    /// Name to attempt to resolve, if followed by a '.' then it's a fully-qualified-domain-name.
    domainname: String,

    /// Type of query to issue, e.g. A, AAAA, NS, etc.
    #[structopt(short = "t", long = "type", default_value = "A")]
    ty: RecordType,

    /// Use google resolvers, default
    #[structopt(long)]
    google: bool,

    /// Use cloudflare resolvers
    #[structopt(long)]
    cloudflare: bool,

    /// Use quad9 resolvers
    #[structopt(long)]
    quad9: bool,

    /// Specify a nameserver to use, ip and port e.g. 8.8.8.8:53 or [2001:4860:4860::8888]:53 (port required)
    #[structopt(short = "n", long, require_delimiter = true)]
    nameserver: Vec<SocketAddr>,

    /// Use ipv4 addresses only, default is both ipv4 and ipv6
    #[structopt(long)]
    ipv4: bool,

    /// Use ipv6 addresses only, default is both ipv4 and ipv6
    #[structopt(long)]
    ipv6: bool,

    /// Use only UDP, default to UDP and TCP
    #[structopt(long)]
    udp: bool,

    /// Use only TCP, default to UDP and TCP
    #[structopt(long)]
    tcp: bool,

    /// Enable debug and all logging
    #[structopt(long)]
    debug: bool,

    /// Enable info + warning + error logging
    #[structopt(long)]
    info: bool,

    /// Enable warning + error logging
    #[structopt(long)]
    warn: bool,

    /// Enable error logging
    #[structopt(long)]
    error: bool,
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts: Opts = Opts::from_args();
    let term = Term::stdout();

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
        .filter_module("trust_dns_proto", log_level)
        .write_style(env_logger::WriteStyle::Auto)
        .format_indent(Some(4))
        .init();

    let name = &opts.domainname;
    let ty = opts.ty;

    // Configure all the name servers
    let mut name_servers = NameServerConfigGroup::new();

    for socket_addr in &opts.nameserver {
        name_servers.push(NameServerConfig {
            socket_addr: *socket_addr,
            protocol: Protocol::Tcp,
            tls_dns_name: None,
        });

        name_servers.push(NameServerConfig {
            socket_addr: *socket_addr,
            protocol: Protocol::Udp,
            tls_dns_name: None,
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
    if name_servers.is_empty() {
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

    let config = ResolverConfig::from_parts(None, vec![], name_servers);

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

    term.write_line(&format!(
        "Querying for {} {} from {}",
        name, ty, name_servers
    ))?;

    let resolver = TokioAsyncResolver::tokio(config, ResolverOpts::default())?;

    let lookup = resolver
        .lookup(name.to_string(), ty, Default::default())
        .await?;

    term.write_line(&format!("{:?} success, records:", lookup.query()))?;

    for record in lookup.record_iter() {
        term.write_line(&format!("{:?}", record))?;
    }

    Ok(())
}
