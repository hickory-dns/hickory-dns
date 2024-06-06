// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
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
    fs::File,
    io::{BufRead, BufReader},
    net::{IpAddr, SocketAddr},
    ops::Deref,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use clap::{ArgGroup, Parser};
use console::style;
use hickory_proto::error::{ProtoError, ProtoErrorKind};
use tokio::task::JoinSet;

use hickory_client::rr::{Record, RecordData};
use hickory_resolver::{
    config::{NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts},
    error::ResolveError,
    lookup::Lookup,
    proto::rr::RecordType,
    TokioAsyncResolver,
};
use tokio::time::MissedTickBehavior;

/// A CLI interface for the hickory-resolver.
///
/// This utility directly uses the hickory-resolver to perform a lookup to a
/// set of nameservers. Many of the features can be directly tested via the
/// FLAGS and OPTIONS. By default (like hickory-resolver) the configured
/// nameservers are the Google provided ones. The system configured ones can be
/// used with the `--system` FLAG. Other nameservers, as many as desired, can
/// be configured directly with the `--nameserver` OPTION.
#[derive(Debug, Parser)]
#[clap(name = "resolve",
    group(ArgGroup::new("qtype").args(&["happy", "reverse", "ty"])),
    group(ArgGroup::new("input").required(true).args(&["domainname", "inputfile"]))
)]
struct Opts {
    /// Name to attempt to resolve, if followed by a '.' then it's a fully-qualified-domain-name.
    domainname: Option<String>,

    /// File containing one domainname to resolve per line
    #[clap(
        short = 'f',
        long = "file",
        value_parser,
        value_name = "FILE",
        conflicts_with("domainname")
    )]
    inputfile: Option<PathBuf>,

    /// Type of query to issue, e.g. A, AAAA, NS, etc.
    #[clap(short = 't', long = "type", default_value = "A")]
    ty: RecordType,

    /// Happy eye balls lookup, ipv4 and ipv6
    #[clap(short = 'e', long = "happy", conflicts_with_all(&["reverse", "ty"]))]
    happy: bool,

    /// Reverse DNS lookup
    #[clap(short = 'r', long = "reverse", conflicts_with_all(&["happy", "ty"]))]
    reverse: bool,

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

    /// Set the time interval between requests (in seconds, useful with --file)
    #[clap(long, default_value = "1.0")]
    interval: f32,
}

fn print_record<D: RecordData, R: Deref<Target = Record<D>>>(r: &R) {
    print!(
        "\t{name} {ttl} {class} {ty} {rdata}",
        name = style(r.name()).blue(),
        ttl = style(r.ttl()).blue(),
        class = style(r.dns_class()).blue(),
        ty = style(r.record_type()).blue(),
        rdata = r.data(),
    );
}

fn print_ok(lookup: Lookup) {
    println!(
        "{} for query {}",
        style("Success").green(),
        style(lookup.query()).blue()
    );

    for r in lookup.record_iter() {
        print_record(&r);
    }
}

fn print_error(error: ResolveError) {
    match error.proto().map(ProtoError::kind) {
        Some(ProtoErrorKind::NoRecordsFound { query, soa, .. }) => {
            println!(
                "{} for query {}",
                style("NoRecordsFound").red(),
                style(query).blue()
            );
            if let Some(ref r) = soa {
                print_record(r);
            }
        }
        _ => {
            println!("{error:?}");
        }
    }
}

fn print_result(result: Result<Lookup, ResolveError>) {
    match result {
        Ok(lookup) => print_ok(lookup),
        Err(re) => print_error(re),
    }
}

fn log_query(name: &str, ty: RecordType, name_servers: &str, opts: &Opts) {
    if opts.happy {
        println!(
            "Querying for {name} {ty} from {ns}",
            name = style(name).yellow(),
            ty = style("A+AAAA").yellow(),
            ns = style(name_servers).blue()
        );
    } else if opts.reverse {
        println!(
            "Querying {reverse} for {name} from {ns}",
            reverse = style("reverse").yellow(),
            name = style(name).yellow(),
            ns = style(name_servers).blue()
        );
    } else {
        println!(
            "Querying for {name} {ty} from {ns}",
            name = style(name).yellow(),
            ty = style(ty).yellow(),
            ns = style(name_servers).blue()
        );
    }
}

async fn execute_query(
    resolver: Arc<TokioAsyncResolver>,
    name: String,
    happy: bool,
    reverse: bool,
    ty: RecordType,
) -> Result<Lookup, ResolveError> {
    if happy {
        Ok(resolver.lookup_ip(name.to_string()).await?.into())
    } else if reverse {
        let v4addr = name
            .parse::<IpAddr>()
            .unwrap_or_else(|_| panic!("Could not parse {} into an IP address", name));
        Ok(resolver.reverse_lookup(v4addr).await?.into())
    } else {
        Ok(resolver.lookup(name.to_string(), ty).await?)
    }
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

    hickory_util::logger(env!("CARGO_BIN_NAME"), log_level);

    // read system configuration
    let (sys_config, sys_options): (Option<ResolverConfig>, Option<ResolverOpts>) = if opts.system {
        let (config, options) = hickory_resolver::system_conf::read_system_conf()?;

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
            trust_negative_responses: false,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
            bind_addr: opts.bind.map(|ip| SocketAddr::new(ip, 0)),
        });

        name_servers.push(NameServerConfig {
            socket_addr: *socket_addr,
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,
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

    let name_servers = config
        .name_servers()
        .iter()
        .map(|ns| format!("{ns}"))
        .collect::<Vec<String>>()
        .join(", ");

    // configure the resolver options
    let mut options = sys_options.unwrap_or_default();
    if opts.happy {
        options.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4AndIpv6;
    }

    let resolver_arc = Arc::new(TokioAsyncResolver::tokio(config, options));

    if let Some(domainname) = &opts.domainname {
        log_query(domainname, opts.ty, &name_servers, &opts);
        let lookup = execute_query(
            resolver_arc,
            domainname.to_owned(),
            opts.happy,
            opts.reverse,
            opts.ty,
        )
        .await;
        print_result(lookup);
    } else {
        let duration = Duration::from_secs_f32(opts.interval);
        let fd = File::open(opts.inputfile.as_ref().unwrap())?;
        let reader = BufReader::new(fd);
        let mut taskset = JoinSet::new();
        let mut timer = tokio::time::interval(duration);
        timer.set_missed_tick_behavior(MissedTickBehavior::Burst);
        for name in reader.lines().map_while(Result::ok) {
            let (happy, reverse, ty) = (opts.happy, opts.reverse, opts.ty);
            log_query(&name, ty, &name_servers, &opts);
            let resolver = resolver_arc.clone();
            taskset.spawn(async move { execute_query(resolver, name, happy, reverse, ty).await });
            loop {
                tokio::select! {
                    _ = timer.tick() => break,
                    lookup_opt = taskset.join_next() => match lookup_opt {
                        Some(lookup_rr) => {
                            print_result(lookup_rr?);
                        },
                        None => { timer.tick().await; break; }
                    }
                };
            }
        }
    }
    Ok(())
}
