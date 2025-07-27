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
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;

use hickory_proto::{
    DnsError, ProtoError, ProtoErrorKind,
    rr::{Record, RecordData, RecordType},
    runtime::TokioRuntimeProvider,
};
use hickory_resolver::{
    TokioResolver,
    config::{
        CLOUDFLARE, GOOGLE, NameServerConfig, ProtocolConfig, QUAD9, ResolverConfig, ResolverOpts,
    },
    lookup::Lookup,
};

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

    /// Configure log verbosity.
    #[clap(flatten)]
    log_config: hickory_util::LogConfig,

    /// Set the time interval between requests (in seconds, useful with --file)
    #[clap(long, default_value = "1.0")]
    interval: f32,
}

fn print_record<D: RecordData, R: Deref<Target = Record<D>>>(r: &R) {
    println!(
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

fn print_error(error: ProtoError) {
    let no_records = match error.kind() {
        ProtoErrorKind::Dns(DnsError::NoRecordsFound(no_records)) => no_records,
        _ => {
            println!("{error:?}");
            return;
        }
    };

    println!(
        "{} for query {}",
        style("NoRecordsFound").red(),
        style(&no_records.query).blue()
    );

    if let Some(r) = &no_records.soa {
        print_record(r);
    }
}

fn print_result(result: Result<Lookup, ProtoError>) {
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
    resolver: Arc<TokioResolver>,
    name: String,
    happy: bool,
    reverse: bool,
    ty: RecordType,
) -> Result<Lookup, ProtoError> {
    if happy {
        Ok(resolver.lookup_ip(name.to_string()).await?.into())
    } else if reverse {
        let v4addr = name
            .parse::<IpAddr>()
            .unwrap_or_else(|_| panic!("Could not parse {name} into an IP address"));
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
    hickory_util::logger(env!("CARGO_BIN_NAME"), opts.log_config.level());

    // read system configuration
    let (sys_config, sys_options): (Option<ResolverConfig>, Option<ResolverOpts>) = if opts.system {
        let (config, options) = hickory_resolver::system_conf::read_system_conf()?;

        (Some(config), Some(options))
    } else {
        (None, None)
    };

    // Configure all the name servers
    let mut name_servers = Vec::new();
    for socket_addr in &opts.nameserver {
        let mut config = NameServerConfig::udp_and_tcp(socket_addr.ip());
        config.trust_negative_responses = false;
        for conn in config.connections.iter_mut() {
            conn.port = socket_addr.port();
            conn.bind_addr = opts.bind.map(|ip| SocketAddr::new(ip, 0));
        }

        name_servers.push(config);
    }

    if opts.google {
        name_servers.extend(GOOGLE.udp_and_tcp());
    }
    if opts.cloudflare {
        name_servers.extend(CLOUDFLARE.udp_and_tcp());
    }
    if opts.quad9 {
        name_servers.extend(QUAD9.udp_and_tcp());
    }
    if name_servers.is_empty() && sys_config.is_none() {
        name_servers.extend(GOOGLE.udp_and_tcp());
    }

    let ipv4 = opts.ipv4 || !opts.ipv6;
    let ipv6 = opts.ipv6 || !opts.ipv4;

    let udp = opts.udp || !opts.tcp;
    let tcp = opts.tcp || !opts.udp;

    name_servers.retain(|ns| (ipv4 && ns.ip.is_ipv4()) || (ipv6 && ns.ip.is_ipv6()));
    for ns in name_servers.iter_mut() {
        ns.connections.retain(|conn| {
            (udp && conn.protocol == ProtocolConfig::Udp)
                || (tcp && conn.protocol == ProtocolConfig::Tcp)
        });
    }

    let mut config = sys_config.unwrap_or_default();

    for ns in name_servers.iter() {
        config.add_name_server(ns.clone());
    }

    let name_servers = config
        .name_servers()
        .iter()
        .map(|ns| format!("{ns:#?}"))
        .collect::<Vec<String>>()
        .join(", ");

    // configure the resolver options
    let mut options = sys_options.unwrap_or_default();
    if opts.happy {
        options.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4AndIpv6;
    }

    let mut resolver_builder =
        TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
    *resolver_builder.options_mut() = options;
    let resolver_arc = Arc::new(resolver_builder.build()?);

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
